"""HMAC-chained audit log -- tamper-evident decision history.

Every decision the :class:`signet.core.pipeline.Pipeline` makes is appended
to an audit chain. Each entry is HMAC-SHA256-signed using a secret key, and
its signature includes the *previous* entry's signature. This means any
tampering -- modifying, deleting, reordering, or inserting entries -- breaks
the chain at the tamper point, and every entry after it fails verification.

This module is the storage and crypto layer:

* :class:`HmacChain` -- the writer. Append entries; manage the secret key.
* :class:`ChainVerifier` -- the reader. Walk a chain and report breaks.
* :class:`KeyRing` -- multi-key support for key rotation across eras.
* :class:`JsonlBackend` -- default append-only storage backend.

The data shape (:class:`signet.core.audit.AuditEntry`) lives in
:mod:`signet.core.audit` and is intentionally crypto-free so it can be
imported anywhere.

Compatible with NIST 800-53 AU-3 (audit content) and AU-9 (audit
information protection): the chain is append-only, integrity-protected,
and every entry carries non-repudiable attribution to an :class:`Owner`.
"""

from __future__ import annotations

from signet.audit.backend import MalformedAuditEntry
from signet.audit.chain import (
    CANON_JCS_V1,
    CANON_LEGACY,
    SEQ_FIELD,
    HmacChain,
)
from signet.audit.compactor import (
    ARCHIVE_FORMAT_VERSION,
    COMPACTION_CHECK_NAME,
    COMPACTION_MARKER_FIELD,
    ArchiveHeader,
    CompactionResult,
    MerkleTree,
    compact_audit_log,
    is_compaction_marker,
    read_archive,
    trim_before_index,
)
from signet.audit.verifier import (
    BreakKind,
    ChainBreak,
    ChainVerifier,
    ContiguityGap,
    ContiguityReport,
    VerificationReport,
    verify_contiguity,
    verify_with_archives,
)

__all__: list[str] = [
    "ARCHIVE_FORMAT_VERSION",
    "CANON_JCS_V1",
    "CANON_LEGACY",
    "COMPACTION_CHECK_NAME",
    "COMPACTION_MARKER_FIELD",
    "SEQ_FIELD",
    "ArchiveHeader",
    "BreakKind",
    "ChainBreak",
    "ChainVerifier",
    "CompactionResult",
    "ContiguityGap",
    "ContiguityReport",
    "HmacChain",
    "MalformedAuditEntry",
    "MerkleTree",
    "VerificationReport",
    "compact_audit_log",
    "is_compaction_marker",
    "read_archive",
    "trim_before_index",
    "verify_contiguity",
    "verify_with_archives",
]
