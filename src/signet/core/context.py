"""Context objects passed to :class:`signet.core.check.Check` hooks.

Each hook receives one context object that carries the inputs that hook
needs and a free-form ``scratch`` dict that checks can use to thread state
across calls within a single request.

The context split mirrors the four hook timings:

* :class:`RequestContext` -- :meth:`Check.pre_request`
* :class:`ResponseContext` -- :meth:`Check.inspect_response_chunk` and
  :meth:`Check.post_complete`
* :class:`ToolCallContext` -- :meth:`Check.inspect_tool_call`

These are deliberately simple: dataclasses, mutable, single-request-scoped.
A check that needs richer state should attach it to ``scratch`` or use
:class:`signet.server.session.Session` for cross-request continuity.

Also exposes :func:`get_header_ci`, the single canonical helper for
case-insensitive HTTP header lookup. HTTP header names are case-insensitive
on the wire but Python dicts are not; ASGI servers and reverse proxies
normalize differently (uvicorn lowercases, nginx may preserve case). Every
header lookup performed by built-in checks goes through this helper so
``X-Classification``, ``x-classification``, and ``X-CLASSIFICATION`` all
resolve identically.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from signet.core.owner import Owner


# Module-level optional callback. Set by :class:`signet.server.metrics.Metrics`
# at construction to wire truncation events into the metrics registry without
# forcing :mod:`signet.core.context` to import :mod:`signet.server.metrics`
# (that would create a circular dependency, since ``server`` already depends
# on ``core``). The signature receives the cap size in bytes so dashboards can
# correlate cap-policy changes with truncation rates.
_truncation_observer: Callable[[int], None] | None = None


def set_truncation_observer(callback: Callable[[int], None] | None) -> None:
    """Install (or clear) the response-text truncation observer.

    :class:`signet.server.metrics.Metrics` calls this with a counter-
    incrementing function at construction; tests that don't want metrics
    emission pass ``None``. The observer fires once per
    :class:`ResponseContext` the *first* time its cap is hit -- repeated
    extensions on a saturated context don't double-count.
    """
    global _truncation_observer
    _truncation_observer = callback


def get_header_ci(headers: dict[str, str], name: str) -> str:
    """Case-insensitive single-header lookup; returns ``""`` when absent.

    HTTP headers are case-insensitive but Python dicts are not. Some
    ASGI servers normalize to lowercase, others preserve the case the
    client sent. We try the canonical case first (cheapest), then walk
    the dict with a case-fold compare.
    """
    v = headers.get(name)
    if v:
        return v.strip()
    target = name.lower()
    for k, val in headers.items():
        if k.lower() == target and val:
            return val.strip()
    return ""


@dataclass
class RequestContext:
    """Inputs visible to ADMISSION-stage checks (``pre_request`` hook).

    Attributes:
        owner: The accountable :class:`Owner`. May be unresolved when the
            owner-resolution check itself is running.
        headers: Case-insensitive header dict from the inbound request.
        body: Parsed request body. Typically an OpenAI-shaped chat
            completion request, but the pipeline is agnostic.
        path: The request path (e.g. ``/v1/chat/completions``).
        method: HTTP method of the inbound request. Defaults to
            ``"POST"`` (every gated endpoint in v0.1 is POST). Surfaced
            so checks that gate by verb (e.g. an embeddings/completions-
            specific rule) don't need to inspect raw headers.
        client_ip: Source IP, used by the loopback-trust check and other
            network-aware policies.
        session_id: Stable session identifier for cross-request state.
            ``None`` when the caller did not assert a session.
        scratch: Free-form dict that checks within this request can use to
            thread state across the four hook timings. Cleared between
            requests.
    """

    owner: Owner
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    path: str = ""
    method: str = "POST"
    client_ip: str | None = None
    session_id: str | None = None
    scratch: dict[str, Any] = field(default_factory=dict)


_DEFAULT_ACCUMULATED_TEXT_CAP = 1_048_576  # 1 MiB


@dataclass
class ResponseContext:
    """Inputs visible to INSPECTION and RECORD stage checks.

    A single ``ResponseContext`` instance is reused across the streaming
    lifecycle: each call to :meth:`Check.inspect_response_chunk` sees the
    *same* context with ``accumulated_text`` growing as chunks arrive.
    :meth:`Check.post_complete` sees the same instance with the full text.

    Attributes:
        request: The originating :class:`RequestContext`.
        accumulated_text: All text content seen so far in the stream,
            capped at ``accumulated_text_cap`` bytes (UTF-8). Beyond
            the cap, new content is dropped and ``accumulated_text_truncated``
            is set True. Use :meth:`extend_text` rather than ``+=``
            directly so the cap is enforced without callers having to
            think about it.
        accumulated_text_cap: Maximum size of ``accumulated_text``.
            Default is 1 MiB -- enough for INSPECTION-stage checks on
            long completions, while bounded against O(N²) string growth
            on multi-megabyte streams. Adjust if your INSPECTION checks
            need more context, but understand the cost.
        accumulated_text_truncated: True once at least one chunk was
            dropped because the cap was hit. INSPECTION checks should
            treat this as a signal that they're seeing only a prefix.
        output_char_count: Characters of MODEL OUTPUT seen so far --
            delta/message content and nothing else.

            Distinct from ``len(accumulated_text)``, and the distinction
            matters. ``accumulated_text`` is the INSPECTION surface: it
            deliberately includes event-level metadata (``id``,
            ``model``, and other non-structural strings) because a
            hostile upstream can smuggle markers through those fields,
            so they must be scanned. But that metadata repeats on every
            single chunk, so the inspection surface grows with CHUNK
            COUNT, not with how much the model actually said.

            Measured against a real vLLM stream: a chunk carrying ONE
            character of content contributes 58 characters to
            ``accumulated_text`` (a 41-character ``chatcmpl-`` id, a
            16-character model name, and the one character). Any budget
            expressed in "characters the model produced" and evaluated
            against ``accumulated_text`` is therefore off by whatever
            the chunk count happens to be -- roughly 45x on a
            token-per-chunk stream.

            Use this field for output budgets. Use ``accumulated_text``
            for marker scanning.
        chunk_count: Number of chunks delivered so far.
        finish_reason: Set by the proxy when the stream completes
            (``"stop"``, ``"length"``, ``"tool_calls"``, ``"abort"``).
            ``None`` while the stream is in flight.
        usage: OpenAI-shape ``{"prompt_tokens", "completion_tokens",
            "total_tokens"}``. Populated when the upstream returns it,
            either inline or in the final chunk.
        scratch: Free-form dict for cross-hook state within this response.
    """

    request: RequestContext
    accumulated_text: str = ""
    accumulated_text_cap: int = _DEFAULT_ACCUMULATED_TEXT_CAP
    accumulated_text_truncated: bool = False
    output_char_count: int = 0
    chunk_count: int = 0
    finish_reason: str | None = None
    usage: dict[str, int] = field(default_factory=dict)
    scratch: dict[str, Any] = field(default_factory=dict)

    def record_output(self, more: str) -> None:
        """Record model output for budget purposes.

        Call with the delta/message content ONLY -- not with event
        metadata. Uncapped by design: it is a counter, not a buffer, so
        it stays accurate on streams long enough to saturate
        ``accumulated_text_cap``. A budget that silently stops counting
        once an unrelated memory cap is hit is worse than no budget.
        """
        if not more:
            return
        self.output_char_count += len(more)

    def extend_text(self, more: str) -> None:
        """Append to ``accumulated_text``, enforcing the byte cap.

        Strings, not bytes -- the cap is a soft byte budget computed
        against the current length. Once exceeded, additional content
        is dropped and the truncated flag is set; subsequent calls
        become no-ops on the text but still flip the flag for any new
        content received.

        The first time the cap is hit on this context, the module-level
        :data:`_truncation_observer` is fired (if installed) so metrics
        backends can count truncation events. Subsequent extensions on
        the same saturated context do *not* re-fire the observer -- one
        emission per response, regardless of how many overflow chunks
        arrive.
        """
        if not more:
            return
        budget = self.accumulated_text_cap - len(self.accumulated_text)
        if budget <= 0:
            self._mark_truncated()
            return
        if len(more) > budget:
            self.accumulated_text += more[:budget]
            self._mark_truncated()
        else:
            self.accumulated_text += more

    def _mark_truncated(self) -> None:
        """Flip the truncated flag and fire the observer once per response."""
        if not self.accumulated_text_truncated:
            self.accumulated_text_truncated = True
            if _truncation_observer is not None:
                _truncation_observer(self.accumulated_text_cap)


@dataclass
class ToolCallContext:
    """Inputs visible to COMMITMENT-stage checks (``inspect_tool_call`` hook).

    The COMMITMENT stage decides per-tool-call whether the proposed action
    is allowed to run. The check sees the tool name, its arguments, and
    metadata that callers can attach to the tool registry (risk tier,
    irreversibility flag, dry-run support).

    Attributes:
        request: The originating :class:`RequestContext`.
        response: The :class:`ResponseContext` accumulated to this point.
        tool_name: The tool the model is asking to invoke.
        arguments: Parsed tool arguments. Shape is tool-specific.
        tool_metadata: Caller-supplied metadata about this tool. Common
            keys: ``"risk_tier"`` (low|medium|high|critical),
            ``"irreversible"`` (bool), ``"dryrun_supported"`` (bool).
            **Canonical source**: when you also use
            :class:`signet.checks.tool_call_inspector.ToolCallInspectorCheck`,
            its ``ToolSpec`` registry is the source of truth. Either
            populate this dict from the matching
            :meth:`ToolSpec.as_metadata`, or hand the same registry
            object to
            :class:`signet.plugins.sandbox.SandboxPreviewCheck` and let
            it read the flag directly. Don't keep two copies in sync by
            hand.
        scratch: Free-form dict for state.
    """

    request: RequestContext
    response: ResponseContext
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    tool_metadata: dict[str, Any] = field(default_factory=dict)
    scratch: dict[str, Any] = field(default_factory=dict)
