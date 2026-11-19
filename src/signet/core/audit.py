"""AuditEntry -- the immutable record of one decision.

Every decision the pipeline makes -- *allow*, *block*, *redact*, *escalate* --
becomes one :class:`AuditEntry`. Entries are append-only; once written to the
audit chain they are never modified. Tampering is detected by the HMAC chain
in :mod:`signet.audit`.

This module is data-only. The chain that signs and stores entries lives
separately so this module has zero crypto dependencies and can be safely
imported anywhere.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from signet.core.owner import Owner


class Decision(enum.StrEnum):
    """The outcome of evaluating a request through one or more checks."""

    ALLOW = "allow"
    """Request passed all checks; forward to upstream."""

    BLOCK = "block"
    """Request refused; do not forward. Caller receives an error response."""

    REDACT = "redact"
    """Request forwarded but with content modifications (e.g. PII removed)."""

    ESCALATE = "escalate"
    """Request requires out-of-band human approval before any further action."""


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One immutable decision record.

    ``entry_id`` and ``ts_ns`` are populated automatically when the entry is
    constructed. ``prev_hmac`` and ``hmac`` are populated by the chain writer
    in :mod:`signet.audit.chain` and remain empty strings on free-standing
    entries.

    Attributes:
        entry_id: Unique UUIDv4 identifier for this entry.
        ts_ns: Wall-clock nanoseconds since the Unix epoch when the decision
            was made.
        owner: The accountable :class:`Owner` for the request.
        check_name: Name of the :class:`Check` that produced the decision, or
            ``"pipeline"`` when the decision is the pipeline's aggregated
            result.
        decision: The :class:`Decision` produced.
        reason: Human-readable rationale, ideally short and policy-tagged
            (e.g. ``"owner-resolution: no header present"``).
        request_fingerprint: Stable hash of the request body or its salient
            fields. Used for cross-referencing without leaking full payloads.
        metadata: Free-form structured detail. Use sparingly; prefer dedicated
            fields where possible.
        prev_hmac: HMAC of the immediately-previous chain entry. Populated by
            the chain writer.
        hmac: HMAC of this entry's payload (excluding ``hmac`` itself, but
            including ``prev_hmac``). Populated by the chain writer.
    """

    owner: Owner
    check_name: str
    decision: Decision
    reason: str
    request_fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts_ns: int = field(default_factory=time.time_ns)
    prev_hmac: str = ""
    hmac: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-ready dict.

        ``owner`` is flattened to discrete columns for log-query ergonomics
        (``owner_type``, ``owner_id``, ``approval_chain``) rather than a
        nested object. The :class:`Decision` enum is unwrapped to its string
        value for the same reason.
        """
        d = asdict(self)
        # Flatten owner for log readability and cheap grep'ability.
        owner = d.pop("owner")
        d["owner_type"] = owner["owner_type"]
        d["owner_id"] = owner["owner_id"]
        d["approval_chain"] = list(owner["approval_chain"])
        # Unwrap enum to wire-format string.
        d["decision"] = self.decision.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Inverse of :meth:`to_dict`. Used by the chain verifier when reading
        previously-written entries from disk.

        Type validation (Round 7 HIGH-1 / MED-2): the cryptographic fields
        (``hmac``, ``prev_hmac``) and the temporal field (``ts_ns``) are
        type-checked here. A tampered JSONL line that flips ``"hmac": "..."``
        to ``"hmac": null`` / ``"hmac": 42`` / etc. would otherwise produce a
        frozen :class:`AuditEntry` whose ``hmac`` is not a string -- and
        downstream ``hmac.compare_digest`` and ``str[:16]`` slicing would
        raise raw :class:`TypeError`, leaking a Python traceback out of the
        verifier instead of the structured ``MALFORMED_LINE`` break the
        chain pipeline guarantees. ``JsonlBackend.iter_entries`` already
        catches ``TypeError`` / ``KeyError`` / ``ValueError`` from this
        method and routes them through :class:`MalformedAuditEntry`.

        Round 23 MED (F-R23-5): the same routing applies to every
        attacker-controlled string slot. A tampered JSONL line that flips
        ``"entry_id": "..."`` to ``"entry_id": [...]`` would otherwise
        survive ``from_dict`` and crash ``signet replay`` / ``signet audit
        show`` with a raw ``AttributeError`` traceback at
        ``entry.entry_id.lower()``; and ``signet audit verify --json`` would
        emit the non-string ``entry_id`` straight back into its breaks
        array, violating the documented schema contract. Every string field
        (``entry_id``, ``check_name``, ``reason``, ``request_fingerprint``,
        ``owner_id``) is therefore type-checked here, plus ``metadata``
        gets a ``dict`` type-check (a list value would otherwise survive
        ``dict([...])`` only for the narrow case of a list of 2-tuples,
        and we want a clean ``TypeError`` for any non-dict ``metadata``).
        All five rejections raise ``TypeError`` which the backend already
        routes through :class:`MalformedAuditEntry` /
        ``BreakKind.MALFORMED_LINE``.

        ``ts_ns`` additionally has a sanity bound: nanoseconds-since-epoch
        values larger than ``10**19`` would put us past year 2286, which is
        almost certainly tampering and also crashes platform
        :func:`datetime.fromtimestamp` with raw ``OSError`` on some libcs.
        Reject up front so the compactor / report formatters never see a
        value they can't render.
        """
        from signet.core.owner import OwnerType

        # bool is a subclass of int in Python, so we have to explicitly
        # exclude it from the int check -- a tampered ``"ts_ns": true``
        # would otherwise sneak through as the integer 1.
        ts_ns_val = data["ts_ns"]
        if isinstance(ts_ns_val, bool) or not isinstance(ts_ns_val, int):
            raise TypeError(f"ts_ns must be int, got {type(ts_ns_val).__name__}")
        # Sanity bound: ns since epoch > 10**19 is past year 2286 and
        # crashes datetime.fromtimestamp on some libcs. The check is
        # closed-on-the-right (``> 10**19`` rejects, so ``10**19``
        # itself is accepted -- it renders as 2286-11-20T17:46:40Z,
        # which is comfortably inside Python's ``fromtimestamp``
        # range). Round 9 LOW aligned the error message with the
        # check.
        if ts_ns_val < 0 or ts_ns_val > 10**19:
            raise ValueError(f"ts_ns={ts_ns_val} is outside the supported range [0, 10**19]")

        hmac_val = data.get("hmac", "")
        if not isinstance(hmac_val, str):
            raise TypeError(f"hmac must be str, got {type(hmac_val).__name__}")
        prev_hmac_val = data.get("prev_hmac", "")
        if not isinstance(prev_hmac_val, str):
            raise TypeError(f"prev_hmac must be str, got {type(prev_hmac_val).__name__}")

        # Round 23 F-R23-5: the remaining attacker-controlled string slots.
        # A non-string entry_id reaches ``entry.entry_id.lower()`` in
        # ``signet replay`` / ``signet audit show`` and crashes with a raw
        # AttributeError; check_name / reason / request_fingerprint reach
        # ``_sanitize_for_terminal`` and format strings; owner_id reaches
        # ``Owner.__str__`` and ``str(entry.owner)``. Raise TypeError on
        # every non-str so the backend routes it through MALFORMED_LINE.
        entry_id_val = data["entry_id"]
        if not isinstance(entry_id_val, str):
            raise TypeError(f"entry_id must be str, got {type(entry_id_val).__name__}")
        check_name_val = data["check_name"]
        if not isinstance(check_name_val, str):
            raise TypeError(f"check_name must be str, got {type(check_name_val).__name__}")
        reason_val = data["reason"]
        if not isinstance(reason_val, str):
            raise TypeError(f"reason must be str, got {type(reason_val).__name__}")
        request_fingerprint_val = data.get("request_fingerprint", "")
        if not isinstance(request_fingerprint_val, str):
            raise TypeError(
                f"request_fingerprint must be str, got {type(request_fingerprint_val).__name__}"
            )
        owner_id_val = data["owner_id"]
        if not isinstance(owner_id_val, str):
            raise TypeError(f"owner_id must be str, got {type(owner_id_val).__name__}")
        # ``metadata`` is consumed via ``.get(...)`` / ``dict(...)`` in
        # multiple downstream sites that assume a Mapping. A non-dict
        # (e.g. a JSON list) only survives ``dict(...)`` for the narrow
        # case of a list of 2-tuples; reject anything that's not a dict
        # outright so the failure mode is uniform.
        metadata_val = data.get("metadata", {})
        if not isinstance(metadata_val, dict):
            raise TypeError(f"metadata must be dict, got {type(metadata_val).__name__}")

        # Round 25 LOW (F-R25-3): ``approval_chain`` is one of the few
        # attacker-controlled slots that R23-5 did not extend coverage
        # to. ``tuple(data.get("approval_chain", ()))`` accepted a bare
        # JSON string (``"alice"`` -> tuple of single chars) and a list
        # of mixed types (``[1, 2, {"k":"v"}]`` -> tuple of those types
        # verbatim). ``Owner.approval_chain`` is typed
        # ``tuple[str, ...]``; consumers (``tool_call_inspector``
        # ESCALATE routing, ``signet audit show`` JSON dump) iterate
        # it assuming every link is a string. Validate the outer type
        # is list/tuple and every element is a string here so the
        # invariant matches the type annotation, and so any breach
        # routes through ``MalformedAuditEntry`` /
        # ``BreakKind.MALFORMED_LINE`` like the other R23-5 slots.
        approval_chain_val = data.get("approval_chain", ())
        if not isinstance(approval_chain_val, (list, tuple)):
            raise TypeError(f"approval_chain must be list, got {type(approval_chain_val).__name__}")
        for i, link in enumerate(approval_chain_val):
            if not isinstance(link, str):
                raise TypeError(f"approval_chain[{i}] must be str, got {type(link).__name__}")

        # Round 25 LOW (F-R25-4): ``hmac`` / ``prev_hmac`` are
        # type-checked above but not length-validated. The real chain
        # writer always emits 64-char lowercase hex (32-byte SHA-256
        # digests via ``hashlib.sha256().hexdigest()``); a tampered row
        # carrying a 0-char or 1000-char string is operationally a
        # malformed line. ``hmac.compare_digest`` would already reject
        # length-mismatched candidates cleanly (no security boundary
        # crossed), but tightening the schema here keeps the on-disk
        # invariant uniform with the writer and surfaces tampering as
        # a ``MalformedAuditEntry`` instead of a downstream
        # ``SELF_MISMATCH``. The empty-string sentinel is preserved
        # because a freshly-constructed (un-chained) entry legitimately
        # has empty ``hmac`` / ``prev_hmac`` before the chain writer
        # fills them in.
        _HEX_DIGITS = "0123456789abcdef"
        _VALID_SIG_HEX_LENS = (64, 128)  # 32-byte HMAC-SHA256 (64) or 64-byte Ed25519 (128)
        for name, val in (("hmac", hmac_val), ("prev_hmac", prev_hmac_val)):
            if val == "":
                continue
            if len(val) not in _VALID_SIG_HEX_LENS:
                raise ValueError(
                    f"{name} must be 64 hex chars (HMAC-SHA256) or 128 hex chars (Ed25519), "
                    f"got length {len(val)}"
                )
            if not all(c in _HEX_DIGITS for c in val):
                raise ValueError(f"{name} must be lowercase hex, got non-hex chars")

        return cls(
            owner=Owner(
                owner_type=OwnerType(data["owner_type"]),
                owner_id=owner_id_val,
                approval_chain=tuple(approval_chain_val),
            ),
            check_name=check_name_val,
            decision=Decision(data["decision"]),
            reason=reason_val,
            request_fingerprint=request_fingerprint_val,
            metadata=dict(metadata_val),
            entry_id=entry_id_val,
            ts_ns=ts_ns_val,
            prev_hmac=prev_hmac_val,
            hmac=hmac_val,
        )

    def with_chain_links(self, prev_hmac: str, hmac: str) -> AuditEntry:
        """Return a new entry with chain HMACs populated.

        Frozen dataclasses can't be mutated; this is the canonical way for the
        chain writer to add the cryptographic links to a fresh entry before
        appending it to disk.
        """
        from dataclasses import replace

        return replace(self, prev_hmac=prev_hmac, hmac=hmac)
