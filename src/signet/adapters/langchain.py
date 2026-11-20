"""LangChain adapter -- surface signet decisions in LangChain tracing.

Usage::

    from langchain_openai import ChatOpenAI
    from signet.adapters.langchain import SignetCallbackHandler

    llm = ChatOpenAI(
        model="gpt-4o",
        base_url="http://localhost:8443/v1",
        default_headers={"X-Commit-Owner": "human:alice@example.com"},
    )
    handler = SignetCallbackHandler()

    chain = some_chain.with_config(callbacks=[handler])
    result = chain.invoke({"input": "..."})

    # Receipt of the most recent gated call:
    print(handler.last_receipt)
    # → "signet=v1; entry=...; key=k1; sig=..."

The callback intercepts ``on_llm_end`` events, extracts the
``X-Signet-Receipt`` header from the response (if present), and
records it on ``last_receipt``. It also surfaces signet refusals as
LangChain ``on_llm_error`` events so chains see them as first-class
errors rather than silent passthroughs.

Pure observability -- does not modify requests or responses. Wire owner
headers via the LLM client's ``default_headers`` (as in the example
above) or via :func:`signet.adapters.openai.wrap_openai` against the
underlying OpenAI client.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID


class SignetCallbackHandler:
    """LangChain ``BaseCallbackHandler``-shaped observer for signet.

    Subclassing :class:`langchain_core.callbacks.BaseCallbackHandler` is
    intentionally *not* done at import time so signet can be imported
    without LangChain installed. The class is duck-typed: LangChain
    will accept any object that exposes the appropriate ``on_*``
    methods.
    """

    def __init__(self) -> None:
        self.last_receipt: str | None = None
        """Most recent ``X-Signet-Receipt`` header value seen."""

        self.last_refusal: dict[str, Any] | None = None
        """Most recent refusal payload from signet, or ``None``."""

        self.receipts: list[str] = []
        """All receipts seen, in arrival order."""

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Extract ``X-Signet-Receipt`` from the LLM result if present."""
        receipt = self._extract_receipt(response, kwargs)
        if receipt:
            self.last_receipt = receipt
            self.receipts.append(receipt)

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Capture signet refusal payloads when present in the error.

        Recognizes both the strict-redaction body shape
        (``{"error": "refused", "correlation_id": ...}``, the v0.1.5
        default) and the verbose body shape
        (``{"error": "signet refused this request", "reason": ...}``,
        the historical / ``--no-strict-error-redaction`` shape).
        """
        # Try to pull JSON body off common HTTP-error shapes:
        #   - OpenAI / Anthropic APIStatusError expose ``error.body`` as a
        #     parsed ``dict`` or raw JSON ``str``/``bytes``, plus an
        #     ``httpx.Response`` on ``error.response``.
        #   - ``httpx.HTTPStatusError`` exposes ``error.response.json()``.
        payload: Any = None
        for candidate in (getattr(error, "body", None), getattr(error, "response", None)):
            if candidate is None:
                continue
            if isinstance(candidate, dict):
                payload = candidate
                break
            if isinstance(candidate, (str, bytes)):
                try:
                    parsed = json.loads(candidate)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, dict):
                    payload = parsed
                    break
            elif hasattr(candidate, "json"):
                try:
                    parsed = candidate.json()
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    payload = parsed
                    break
        if isinstance(payload, dict):
            err = payload.get("error", "")
            # "refused" is the strict-mode marker; "signet refused..."
            # is the legacy verbose marker.
            if isinstance(err, str) and (err == "refused" or err.startswith("signet refused")):
                self.last_refusal = payload

    @staticmethod
    def _extract_receipt(response: Any, extras: dict[str, Any]) -> str | None:
        """Best-effort extraction of the receipt header from a LangChain
        LLMResult or the kwargs LangChain passes to callbacks."""
        # LangChain stores raw HTTP headers in different places depending
        # on the chat model. Try a few common locations.
        for source in (
            getattr(response, "llm_output", None) or {},
            getattr(response, "response_metadata", None) or {},
            extras,
        ):
            if not isinstance(source, dict):
                continue
            headers = source.get("response_headers") or source.get("headers")
            if isinstance(headers, dict):
                for key in ("X-Signet-Receipt", "x-signet-receipt"):
                    if key in headers:
                        return str(headers[key])
        return None


__all__ = ["SignetCallbackHandler"]
