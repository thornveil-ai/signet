"""Audit log compaction with Merkle archival.

Audit chains grow unboundedly. Operators eventually need to archive old
ranges while preserving end-to-end verifiability. This module implements
the protocol:

1. Read all live entries with ``ts`` strictly before a cutoff.
2. Build a Merkle tree over those entries (SHA-256 over ``entry.hmac``).
3. Write a deterministic archive file: header + serialized tree + gzipped
   JSONL of the original entries.
4. Append a single *compaction marker* to the live chain via the existing
   :class:`HmacChain.append`. The marker carries the Merkle root, the
   archive path, the entry count, and the covered range. Because it is
   appended through the chain it is HMAC-linked to the LAST compacted
   entry, preserving tail integrity across the gap.
5. Atomically rewrite the live log: marker first, then every post-cutoff
   entry retained as-is.

After compaction the live log is short again, but the chain plus archive
together still verify as one logical sequence -- :func:`verify_with_archives`
in :mod:`signet.audit.verifier` walks the live log and on each marker
re-opens the matching archive, recomputes the Merkle root, and compares.

Threat-model boundaries (documented in detail in ``docs/audit-archive-format.md``):

* **In scope:** chain integrity preserved across compaction; archives are
  byte-stable so two compactors over the same input produce identical
  archive bytes.
* **Out of scope (deferred to 0.1.7):** concurrent-write safety
  (operators MUST quiesce the chain before compaction), encryption-at-rest,
  partial-compaction recovery, sub-range incremental verification.

The 0.1.6 archive format is version 1. See
``docs/audit-archive-format.md`` for the byte-level spec.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import tempfile
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from signet.audit.backend import JsonlBackend, exclusive_log_lock
from signet.audit.chain import HmacChain
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner

logger = logging.getLogger("signet.audit.compactor")

#: The current archive format version this module emits.
ARCHIVE_FORMAT_VERSION = 1

#: ``check_name`` of synthetic entries that mark a compaction boundary in
#: the live chain. Verifiers recognize this string to switch into
#: archive-walk mode.
COMPACTION_CHECK_NAME = "_compaction"

#: Metadata key on a compaction-marker entry under which the marker
#: payload (merkle root, archive path, count, range, format version)
#: lives. Stable across versions.
COMPACTION_MARKER_FIELD = "_compaction_marker"

#: Sub-key inside a compaction-marker payload that carries a
#: keyring-MAC over the marker's identifying fields. Round 7 LOW-1:
#: without this, ``is_compaction_marker`` was a pure shape check on
#: user-controllable fields, so any caller able to append a tampered
#: entry with ``check_name == "_compaction"`` could permanently block
#: future compactions via the A2 guard in :func:`compact_audit_log`.
#: The MAC is computed with the active key's secret over the marker's
#: ``(merkle_root, archive_path, compacted_count, range_start,
#: range_end, archive_format_version)`` tuple, so a user-crafted entry
#: cannot produce a valid signature without the HMAC key.
COMPACTION_MARKER_SIG_FIELD = "_marker_signature"

#: Stable domain-separation prefix mixed into the marker MAC so the
#: same key cannot be confused with chain HMACs or other future MAC
#: surfaces. Treat as part of the format version contract.
_MARKER_SIG_DOMAIN = b"signet-compaction-marker-v1\x00"


@dataclass(frozen=True, slots=True)
class ArchiveHeader:
    """The header block at the start of every archive file.

    Attributes:
        archive_format_version: Integer version of the archive byte
            format. 0.1.6 emits version 1.
        signet_version: ``signet.__version__`` of the writer. Recorded
            for forensic traceability -- diagnosing format drift across
            releases is much easier when the file says who made it.
        range_start: ISO 8601 UTC timestamp of the OLDEST archived
            entry.
        range_end: ISO 8601 UTC timestamp of the NEWEST archived entry.
        entry_count: Number of entries archived.
        merkle_root: Hex-encoded SHA-256 Merkle root of the archived
            entries' HMAC fields.
    """

    archive_format_version: int
    signet_version: str
    range_start: str
    range_end: str
    entry_count: int
    merkle_root: str

    def to_json_line(self) -> str:
        """Serialize to a single canonical JSON line for the archive header."""
        return json.dumps(
            {
                "archive_format_version": self.archive_format_version,
                "signet_version": self.signet_version,
                "range_start": self.range_start,
                "range_end": self.range_end,
                "entry_count": self.entry_count,
                "merkle_root": self.merkle_root,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=False,
        )

    @classmethod
    def from_json_line(cls, line: str) -> ArchiveHeader:
        """Inverse of :meth:`to_json_line`."""
        d = json.loads(line)
        return cls(
            archive_format_version=int(d["archive_format_version"]),
            signet_version=str(d["signet_version"]),
            range_start=str(d["range_start"]),
            range_end=str(d["range_end"]),
            entry_count=int(d["entry_count"]),
            merkle_root=str(d["merkle_root"]),
        )


@dataclass(frozen=True, slots=True)
class CompactionResult:
    """The outcome of one successful :func:`compact_audit_log` call.

    Attributes:
        archive_path: Path to the written archive file.
        merkle_root: Hex Merkle root over the archived entries' HMACs.
        compacted_count: Number of entries archived.
        range: ``(range_start, range_end)`` ISO 8601 UTC pair covering
            the archived entries' timestamps.
        marker_entry_id: ``entry_id`` of the compaction marker that was
            appended to the live chain in place of the compacted
            entries.
    """

    archive_path: Path
    merkle_root: str
    compacted_count: int
    range: tuple[str, str]
    marker_entry_id: str


@dataclass(frozen=True, slots=True)
class MerkleTree:
    """Balanced binary Merkle tree over entry HMAC strings.

    Leaf hash function: ``SHA-256(entry.hmac.encode("utf-8"))``. Internal
    nodes are ``SHA-256(left || right)`` over the raw 32-byte digests
    (we keep hex for the public surface but concatenate raw bytes for
    the parent computation, matching standard practice).

    For an odd number of nodes at any level the last hash is duplicated
    (the "fill" approach used in Certificate Transparency RFC 6962 §2.1
    -- strictly speaking CT uses a different odd-handling rule, but the
    duplicate-last-hash variant is widely deployed in practice and
    produces a deterministic, single-rooted tree without extra
    encoding).

    The serialized form is canonical: same input entries → same byte
    output, every time.
    """

    leaves: tuple[str, ...]
    root: str

    @classmethod
    def from_entries(cls, entries: Iterable[AuditEntry]) -> MerkleTree:
        """Build a tree over an iterable of entries.

        Empty input is rejected -- there's no meaningful Merkle root over
        zero leaves, and callers should be filtering before they reach
        the compactor.
        """
        leaf_hashes = tuple(_leaf_hash(e.hmac) for e in entries)
        if not leaf_hashes:
            raise ValueError("MerkleTree.from_entries: cannot build a tree over zero entries")
        root = _compute_root(leaf_hashes)
        return cls(leaves=leaf_hashes, root=root)

    def serialize(self) -> bytes:
        """Serialize the tree to a canonical byte format.

        Layout (all bytes, big-endian unsigned 32-bit lengths):

        ::

            "MERKLE-V1\\n"
            <u32 leaf_count>
            <u32 leaf_byte_len>
            <leaf_count * leaf_byte_len bytes of leaf hashes (hex strings)>
            <u32 root_byte_len>
            <root bytes (hex string)>

        The intermediate levels are NOT serialized -- they are
        deterministically recomputable from the leaves, and storing them
        would be both redundant and a footgun for any drift between
        writer and reader. Verifiers rebuild the tree on load.
        """
        leaf_count = len(self.leaves)
        if leaf_count == 0:
            raise ValueError("cannot serialize an empty MerkleTree")
        leaf_byte_len = len(self.leaves[0].encode("ascii"))
        for h in self.leaves:
            if len(h.encode("ascii")) != leaf_byte_len:
                raise ValueError("MerkleTree leaves must all be the same hex length")

        out = bytearray()
        out += b"MERKLE-V1\n"
        out += leaf_count.to_bytes(4, "big")
        out += leaf_byte_len.to_bytes(4, "big")
        for h in self.leaves:
            out += h.encode("ascii")
        root_bytes = self.root.encode("ascii")
        out += len(root_bytes).to_bytes(4, "big")
        out += root_bytes
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> MerkleTree:
        """Inverse of :meth:`serialize`. Recomputes the root from the
        leaves and asserts it matches the stored root -- any mismatch
        means the archive is corrupt or written by a buggy peer.
        """
        prefix = b"MERKLE-V1\n"
        if not data.startswith(prefix):
            raise ValueError("MerkleTree.deserialize: missing MERKLE-V1 magic")
        cursor = len(prefix)

        def _u32() -> int:
            nonlocal cursor
            if cursor + 4 > len(data):
                raise ValueError("MerkleTree.deserialize: truncated u32")
            v = int.from_bytes(data[cursor : cursor + 4], "big")
            cursor += 4
            return v

        leaf_count = _u32()
        leaf_byte_len = _u32()
        leaves: list[str] = []
        for _ in range(leaf_count):
            if cursor + leaf_byte_len > len(data):
                raise ValueError("MerkleTree.deserialize: truncated leaf")
            leaves.append(data[cursor : cursor + leaf_byte_len].decode("ascii"))
            cursor += leaf_byte_len
        root_byte_len = _u32()
        if cursor + root_byte_len > len(data):
            raise ValueError("MerkleTree.deserialize: truncated root")
        stored_root = data[cursor : cursor + root_byte_len].decode("ascii")

        leaves_t = tuple(leaves)
        recomputed = _compute_root(leaves_t)
        if recomputed != stored_root:
            raise ValueError(
                "MerkleTree.deserialize: stored root does not match recomputed root "
                f"(stored={stored_root[:16]}..., recomputed={recomputed[:16]}...)"
            )
        return cls(leaves=leaves_t, root=stored_root)


def _leaf_hash(hmac_hex: str) -> str:
    """Hash an entry's HMAC string with SHA-256, return hex digest."""
    return hashlib.sha256(hmac_hex.encode("utf-8")).hexdigest()


def _compute_root(leaves: tuple[str, ...]) -> str:
    """Reduce a tuple of hex leaf hashes to a single hex root.

    Even-count layers pair off normally. Odd-count layers duplicate the
    last hash before pairing (RFC 6962-style fill).
    """
    if not leaves:
        raise ValueError("_compute_root: empty leaves")
    level: list[bytes] = [bytes.fromhex(h) for h in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = next_level
    return level[0].hex()


# Archive format byte sentinels. These match the spec in
# ``docs/audit-archive-format.md`` exactly.
_MAGIC_PREFIX = b"SIGNET-ARCHIVE-V"
_MERKLE_START = b"MERKLE-START\n"
_MERKLE_END = b"\nMERKLE-END\n"
_ENTRIES_START = b"ENTRIES-START\n"
_ENTRIES_END = b"\nENTRIES-END\n"


def _ts_ns_to_iso(ts_ns: int) -> str:
    """Convert nanoseconds-since-epoch to an ISO 8601 UTC string with
    ``Z`` suffix, microsecond precision (Python's datetime ceiling).

    Round 7 MED-2: absurd integer ``ts_ns`` values (well past year
    2286, e.g. 10**20) crash :func:`datetime.fromtimestamp` with a
    raw ``OSError [Errno 22]`` on some libcs. Catch that family and
    re-raise as :class:`ValueError` so the caller surface (compactor's
    range-formatting path) can refuse fail-closed with a clean error
    instead of leaking the platform error out. The HIGH-1 ``ts_ns``
    bound in :meth:`AuditEntry.from_dict` (>= 0, <= 10**19) is the
    primary line of defense; this is belt-and-braces.
    """
    seconds = ts_ns / 1_000_000_000
    try:
        dt = datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"ts_ns={ts_ns} is outside the platform's representable range") from exc
    # Python's isoformat appends +00:00; we normalize to Z for compactness.
    return dt.isoformat().replace("+00:00", "Z")


def _iso_to_dt(iso: str) -> datetime:
    """Parse the ISO strings we emit (``...Z`` suffix) back to a
    timezone-aware UTC datetime."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _serialize_entry_for_archive(entry: AuditEntry) -> str:
    """Canonical single-line JSON for an archived entry.

    Same canonicalization rules as the chain signer: ``sort_keys=True``,
    no whitespace, no NaN. This guarantees byte-stable archives when the
    same logical entry is compacted twice.
    """
    return json.dumps(
        entry.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=False,
    )


def _write_archive(
    *,
    output: Path,
    header: ArchiveHeader,
    tree: MerkleTree,
    entries: list[AuditEntry],
) -> None:
    """Write the archive file at ``output`` atomically.

    Format (matches ``docs/audit-archive-format.md``)::

        SIGNET-ARCHIVE-V<format_version>\n
        <header JSON, single line>\n
        MERKLE-START\n
        <merkle tree binary>\n
        MERKLE-END\n
        ENTRIES-START\n
        <gzip-compressed JSONL of entries>
        ENTRIES-END\n

    Determinism: all sources of nondeterminism are pinned. The JSONL is
    gzipped with ``mtime=0`` and a fixed compresslevel so two writers
    over the same input produce byte-identical archives.
    """
    output.parent.mkdir(parents=True, exist_ok=True)

    # Compose the archive payload in memory. Archive sizes are O(entries
    # being compacted) -- for a 100k-entry archive that's a few tens of
    # megabytes, well under the threshold where streaming would matter.
    body = bytearray()
    body += _MAGIC_PREFIX + str(header.archive_format_version).encode("ascii") + b"\n"
    body += header.to_json_line().encode("utf-8") + b"\n"
    body += _MERKLE_START
    body += tree.serialize()
    body += _MERKLE_END
    body += _ENTRIES_START

    # Gzip the JSONL with mtime=0 so the gzip header is byte-stable
    # across runs. compresslevel=6 is the gzip default and is also
    # documented as deterministic for given input.
    jsonl = "\n".join(_serialize_entry_for_archive(e) for e in entries) + "\n"
    gz = _gzip_bytes_deterministic(jsonl.encode("utf-8"))
    body += gz
    body += _ENTRIES_END

    # Atomic write: temp file in same directory + os.replace. Works on
    # both POSIX and Windows.
    fd, tmp_name = tempfile.mkstemp(
        prefix=output.name + ".tmp-",
        dir=str(output.parent),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(body))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, output)
    except Exception:
        # Best-effort cleanup of the orphaned temp file.
        import contextlib

        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def _gzip_bytes_deterministic(data: bytes) -> bytes:
    """Produce a byte-stable gzip stream over ``data``.

    Standard ``gzip.compress(...)`` injects the current mtime into the
    gzip header, which would break archive byte-stability. We use
    :class:`gzip.GzipFile` with ``mtime=0`` to pin it.
    """
    import io

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=6) as gz:
        gz.write(data)
    return buf.getvalue()


def _read_archive(path: Path) -> tuple[ArchiveHeader, MerkleTree, list[AuditEntry]]:
    """Read and parse an archive file produced by :func:`_write_archive`.

    Returns the header, the deserialized Merkle tree (with verified
    root), and the decompressed list of entries. Raises
    :class:`ValueError` on any structural violation -- verifiers
    translate that into ``ARCHIVE_FORMAT_INVALID`` breaks.
    """
    raw = path.read_bytes()
    cursor = 0

    # Magic + format version line.
    nl = raw.find(b"\n", cursor)
    if nl == -1 or not raw[cursor:nl].startswith(_MAGIC_PREFIX):
        raise ValueError(f"archive {path} missing SIGNET-ARCHIVE-V magic prefix")
    version_str = raw[cursor + len(_MAGIC_PREFIX) : nl].decode("ascii")
    try:
        version = int(version_str)
    except ValueError as exc:
        raise ValueError(f"archive {path} has non-integer format version {version_str!r}") from exc
    if version != ARCHIVE_FORMAT_VERSION:
        raise ValueError(
            f"archive {path} declares format version {version}; this build of "
            f"signet only reads version {ARCHIVE_FORMAT_VERSION}"
        )
    cursor = nl + 1

    # Header line.
    nl = raw.find(b"\n", cursor)
    if nl == -1:
        raise ValueError(f"archive {path}: header line not terminated")
    header = ArchiveHeader.from_json_line(raw[cursor:nl].decode("utf-8"))
    cursor = nl + 1

    # MERKLE-START
    if not raw[cursor:].startswith(_MERKLE_START):
        raise ValueError(f"archive {path}: expected MERKLE-START at byte {cursor}")
    cursor += len(_MERKLE_START)

    merkle_end = raw.find(_MERKLE_END, cursor)
    if merkle_end == -1:
        raise ValueError(f"archive {path}: MERKLE-END not found")
    merkle_blob = raw[cursor:merkle_end]
    tree = MerkleTree.deserialize(merkle_blob)
    cursor = merkle_end + len(_MERKLE_END)

    # ENTRIES-START
    if not raw[cursor:].startswith(_ENTRIES_START):
        raise ValueError(f"archive {path}: expected ENTRIES-START at byte {cursor}")
    cursor += len(_ENTRIES_START)

    entries_end = raw.find(_ENTRIES_END, cursor)
    if entries_end == -1:
        raise ValueError(f"archive {path}: ENTRIES-END not found")
    gz_blob = raw[cursor:entries_end]
    # A1: a corrupted gzip body raises ``zlib.error`` (or
    # ``gzip.BadGzipFile`` on some malformations); a corrupt gzip
    # can also yield bytes that aren't valid UTF-8. Translate all of
    # those into a ``ValueError`` the verifier already knows how to
    # map to ``ARCHIVE_FORMAT_INVALID``.
    try:
        jsonl = gzip.decompress(gz_blob).decode("utf-8")
    except (zlib.error, gzip.BadGzipFile, UnicodeDecodeError, OSError) as exc:
        raise ValueError(
            f"archive {path}: entries section is corrupt: {type(exc).__name__}: {exc}"
        ) from exc
    entries: list[AuditEntry] = []
    for line in jsonl.splitlines():
        if not line.strip():
            continue
        try:
            entries.append(AuditEntry.from_dict(json.loads(line)))
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            # Round 7 HIGH-2: broaden the except to cover the schema-
            # validation failures ``AuditEntry.from_dict`` raises -- a
            # tampered archive with valid JSON but missing-required-key
            # or wrong-typed entries would otherwise crash the verifier
            # with raw ``KeyError`` / ``TypeError`` instead of routing
            # through ``ARCHIVE_FORMAT_INVALID``.
            raise ValueError(
                f"archive {path}: archived entry is invalid: {type(exc).__name__}: {exc}"
            ) from exc

    if len(entries) != header.entry_count:
        raise ValueError(
            f"archive {path}: header claims {header.entry_count} entries, "
            f"file contains {len(entries)}"
        )

    return header, tree, entries


def read_archive(path: Path) -> tuple[ArchiveHeader, MerkleTree, list[AuditEntry]]:
    """Public entry point for reading an archive file.

    Used by the verifier and by external tools. Returns the same triple
    as :func:`_read_archive`.
    """
    return _read_archive(path)


def compact_audit_log(
    *,
    chain: HmacChain,
    backend: JsonlBackend,
    before: datetime,
    output: Path,
    archive_format_version: int = ARCHIVE_FORMAT_VERSION,
    quiesce_required: bool = True,
    force: bool = False,
) -> CompactionResult | None:
    """Compact entries with timestamps strictly before ``before`` into
    ``output``, replace them in the live chain with a single compaction
    marker, and return a :class:`CompactionResult`.

    When the cutoff is so old that no entries qualify, this is a no-op:
    no archive is written, no marker is appended, and ``None`` is
    returned. The caller can branch on the return value to log a "no
    eligible entries" message.

    The 0.1.6 archive format version is :data:`ARCHIVE_FORMAT_VERSION`
    (``1``); the parameter is plumbed for future compatibility but only
    that version is currently emitted.

    Args:
        chain: The live :class:`HmacChain` writer. The marker is
            appended through this so chain integrity is preserved.
        backend: The :class:`JsonlBackend` underlying ``chain``. Needed
            because compaction has to atomically rewrite the file --
            a chain-only API would be too narrow.
        before: Cutoff datetime. Entries whose ``ts_ns`` represents a
            wall-clock instant strictly less than this are archived.
            Should be timezone-aware UTC; naive datetimes are assumed
            UTC for compatibility.
        output: Path to write the archive to. Parent directory is
            created if it doesn't exist.
        archive_format_version: Version stamp recorded in the archive
            header. Must equal :data:`ARCHIVE_FORMAT_VERSION`.
        quiesce_required: Marker for the contract -- the chain must be
            quiesced (no concurrent writers) before this is called.
            Reserved for a future runtime check; currently always True.
        force: When True, overwrite an existing archive at ``output``.
            Default False refuses with :class:`FileExistsError`,
            because clobbering the only non-tampered copy of compacted
            entries is an unsafe default.

    Returns:
        A :class:`CompactionResult` on success, or ``None`` if no
        entries qualified for compaction.

    Raises:
        ValueError: ``archive_format_version`` is not the supported
            version, the chain is empty, or the eligible range
            includes a previous compaction marker (re-compacting over
            an existing marker would break ``verify_with_archives``;
            v0.1.7 refuses cleanly. Multi-archive bridging is a
            Phase-2 item).
        FileExistsError: ``output`` already exists and ``force`` is
            False. Pass ``force=True`` to overwrite.
        OSError: An I/O error occurred during archive write or live
            log rewrite.

    Concurrency contract: the live chain MUST be quiesced before this
    call. The compactor takes a cross-process exclusive lock on the
    live log's sidecar (``<path>.lock``) so
    :class:`FileLockingJsonlBackend` writers block on the same lock
    for the duration of the rewrite -- but other backends (or external
    processes writing the file directly) are not constrained. See
    ``docs/audit-archive-format.md`` for the operator playbook.
    """
    if archive_format_version != ARCHIVE_FORMAT_VERSION:
        raise ValueError(
            f"compactor only emits archive format version "
            f"{ARCHIVE_FORMAT_VERSION}; got {archive_format_version}"
        )

    # Resolve the archive output path. We accept relative paths but the
    # marker payload records an absolute resolved path so verifier
    # lookups don't depend on cwd.
    output = Path(output).resolve()

    # A4: refuse to silently overwrite an existing archive. Operators
    # who really mean it pass ``force=True`` (the CLI surfaces this as
    # ``--force``). Default is refusal because an archive on disk may
    # be the only non-tampered copy of those entries.
    if output.exists() and not force:
        raise FileExistsError(
            f"refusing to overwrite existing archive {output}; pass force=True to override"
        )

    # Normalize cutoff to UTC. Naive datetimes are assumed UTC for
    # convenience; timezone-aware ones are converted.
    before_utc = before.replace(tzinfo=UTC) if before.tzinfo is None else before.astimezone(UTC)
    # Convert to ns since epoch via integer microseconds rather than
    # the float seconds path. ``datetime.timestamp()`` returns a float
    # that loses sub-microsecond precision and can drift the boundary
    # by a handful of nanoseconds -- enough to pull a neighboring
    # entry over the cutoff in tests with closely-spaced ``ts_ns``.
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = before_utc - epoch
    cutoff_ns = (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000

    # A7: hold an exclusive lock on the live log's sidecar so any
    # ``FileLockingJsonlBackend`` writers block on the same lock for
    # the duration of the read + archive-write + rewrite. This closes
    # the silent-data-loss footgun where a concurrent appender's open
    # handle on the live log would race with the compactor's
    # ``os.replace`` on Windows. Plain ``JsonlBackend`` (single-writer)
    # is unconstrained -- but it isn't multi-writer safe to begin
    # with.
    with exclusive_log_lock(backend.path):
        # Read the entire chain. We need every entry both to identify
        # eligible ones and to rewrite the live log atomically afterwards.
        all_entries = list(backend.iter_entries())
        if not all_entries:
            return None

        eligible: list[AuditEntry] = []
        retained: list[AuditEntry] = []
        for entry in all_entries:
            if entry.ts_ns < cutoff_ns:
                eligible.append(entry)
            else:
                retained.append(entry)

        if not eligible:
            # Nothing to compact. No archive, no marker. Operators relying on
            # idempotent invocation get the right behavior.
            logger.info(
                "compact_audit_log: no entries before cutoff %s; no-op",
                before_utc.isoformat(),
            )
            return None

        # A2: refuse to re-compact across an existing compaction marker.
        # Walking the verifier across a marker that itself sits inside
        # an archive (because a second compaction archived it) requires
        # multi-archive bridge logic the v0.1.7 verifier does not yet
        # implement. Surface a clean error here pointing at the marker
        # so the operator can either widen ``--before`` past it or skip
        # it. Phase 2: implement marker-bridge logic in
        # ``verify_with_archives`` and lift this guard.
        #
        # Round 7 LOW-1 / Round 9 HIGH-2: use the shape check for the
        # guard dispatch so a marker-shaped entry whose MAC fails to
        # verify (e.g. key revoked from the ring) still refuses
        # re-compaction -- the alternative is to silently archive the
        # marker into a corrupting second archive. After dispatch, use
        # the keyring-aware ``is_compaction_marker`` to distinguish
        # "valid marker, can't re-compact" from "marker-shaped entry
        # but MAC failed, possible key revocation; refusing fail-
        # closed" so the operator can act on either signal.
        for entry in eligible:
            if not _has_marker_shape(entry):
                continue
            marker_ts_iso = _ts_ns_to_iso(entry.ts_ns)
            if is_compaction_marker(entry, keyring=chain._keyring):
                raise ValueError(
                    f"compaction range includes a previous compaction marker "
                    f"(entry_id={entry.entry_id}, ts={marker_ts_iso}); "
                    f"v0.1.7 refuses to re-compact over markers because the "
                    f"resulting multi-archive chain cannot yet be verified. "
                    f"Widen --before to either skip the marker or include it "
                    f"AND its referenced archive in the new archive (the "
                    f"latter is a Phase-2 feature). Idempotent re-compaction "
                    f"with the same cutoff also trips this guard, by design."
                )
            raise ValueError(
                f"compaction range includes a marker-shaped entry whose MAC "
                f"does not verify under any key in the ring "
                f"(entry_id={entry.entry_id}, ts={marker_ts_iso}). If you "
                f"rotated or revoked keys, re-add the marker's signing key "
                f"as a legacy entry in the keyring before compacting. "
                f"Refusing fail-closed to avoid corrupting the archive "
                f"bridge by sweeping a marker into a second archive."
            )

        # Build the Merkle tree over the eligible entries' HMAC fields.
        tree = MerkleTree.from_entries(eligible)
        range_start = _ts_ns_to_iso(eligible[0].ts_ns)
        range_end = _ts_ns_to_iso(eligible[-1].ts_ns)

        # Write the archive first. If anything goes wrong we have made no
        # changes to the live chain.
        header = ArchiveHeader(
            archive_format_version=ARCHIVE_FORMAT_VERSION,
            signet_version=_signet_version(),
            range_start=range_start,
            range_end=range_end,
            entry_count=len(eligible),
            merkle_root=tree.root,
        )
        _write_archive(output=output, header=header, tree=tree, entries=eligible)

        # Build the compaction-marker entry. We need to sign it manually
        # here rather than calling :meth:`HmacChain.append` because the
        # marker MUST link to the LAST eligible entry's hmac -- and at the
        # moment we're calling, the backend file still contains every
        # entry, so the chain's normal "what's the latest entry" lookup
        # would return the wrong predecessor whenever there are retained
        # entries after the cutoff.
        #
        # We use the same machinery that :meth:`HmacChain.append` uses
        # (active key, anchor, ``_serialize_for_signing``) so the marker
        # is byte-identical to what a normal append produces, then we hand
        # it to the rewrite step below to land it in the right slot.
        last_eligible_hmac = eligible[-1].hmac
        appended_marker = _sign_compaction_marker(
            chain=chain,
            prev_hmac=last_eligible_hmac,
            archive_path=output,
            merkle_root=tree.root,
            compacted_count=len(eligible),
            range_start=range_start,
            range_end=range_end,
        )

        # Rewrite the live log so it consists of:
        #   [marker, retained_entries...]
        # The marker's prev_hmac points at the last eligible entry's hmac
        # (recoverable from the archive); the first retained entry's
        # prev_hmac ALSO points at that same hmac because that's how it
        # was appended originally. The :func:`verify_with_archives`
        # verifier knows about this fork: on a marker it switches to the
        # archive to validate the bridge, then continues with the next
        # retained entry as a fresh segment whose prev_hmac matches the
        # archive's last hmac.
        _atomic_rewrite_live_log(
            backend=backend,
            new_entries=[appended_marker, *retained],
        )

        # The chain's prev cache (if active) is now stale -- the next
        # append should link to whatever the *new* last entry is in the
        # rewritten file, not whatever the chain happened to cache from a
        # previous append. Invalidate it.
        #
        # Round 9 HIGH-1 (full-sweep bridge fix): when ``retained`` is
        # empty, the new live log contains ONLY the marker. The
        # verifier's archive-bridge rule (see ``verify_with_archives``
        # docstring near "Bridge from archive back to live log") says
        # the next live entry's ``prev_hmac`` MUST equal the LAST
        # ARCHIVED entry's hmac, NOT the marker's. If we cleared the
        # cache to ``None`` here, the next ``chain.append`` would call
        # ``backend.last_entry()`` and link to the marker, producing
        # a permanent ``LINK_MISMATCH`` from ``verify_with_archives``
        # for the rest of the chain. Seed the cache with the bridge
        # value (``eligible[-1].hmac``) so the next append links
        # correctly. The half-compaction path (``retained`` non-empty)
        # is unaffected: ``backend.last_entry()`` returns the last
        # retained entry, whose hmac is the correct predecessor.
        if retained:
            chain._cached_prev = None
        else:
            chain._cached_prev = eligible[-1].hmac

        return CompactionResult(
            archive_path=output,
            merkle_root=tree.root,
            compacted_count=len(eligible),
            range=(range_start, range_end),
            marker_entry_id=appended_marker.entry_id,
        )


def _marker_signature_payload(
    *,
    archive_format_version: int,
    archive_path: str,
    compacted_count: int,
    merkle_root: str,
    range_start: str,
    range_end: str,
) -> bytes:
    canonical = json.dumps(
        {
            "archive_format_version": archive_format_version,
            "archive_path": archive_path,
            "compacted_count": compacted_count,
            "merkle_root": merkle_root,
            "range_end": range_end,
            "range_start": range_start,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=False,
    ).encode("utf-8")
    return _MARKER_SIG_DOMAIN + canonical


def _compute_marker_signature(
    *,
    secret: bytes,
    archive_format_version: int,
    archive_path: str,
    compacted_count: int,
    merkle_root: str,
    range_start: str,
    range_end: str,
) -> str:
    """Compute the keyring-MAC stamped into a compaction marker (LOW-1)."""
    import hashlib
    import hmac as _hmac

    payload = _marker_signature_payload(
        archive_format_version=archive_format_version,
        archive_path=archive_path,
        compacted_count=compacted_count,
        merkle_root=merkle_root,
        range_start=range_start,
        range_end=range_end,
    )
    return _hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _sign_compaction_marker(
    *,
    chain: HmacChain,
    prev_hmac: str,
    archive_path: Path,
    merkle_root: str,
    compacted_count: int,
    range_start: str,
    range_end: str,
) -> AuditEntry:
    """Build and HMAC-sign a compaction marker entry.

    Mirrors :meth:`HmacChain.append`'s signing logic but with an
    explicit ``prev_hmac`` (to the last archived entry's hmac, not the
    last live-log entry). The chain's anchor backend is invoked just
    like a normal append, so the marker carries a real anchor receipt
    when one is configured.

    Round 7 LOW-1: stamp a keyring-MAC into the marker payload under
    :data:`COMPACTION_MARKER_SIG_FIELD` so external callers can't
    forge markers (a forged marker would otherwise DoS future
    compactions via the A2 guard).
    """
    from dataclasses import replace

    from signet.audit.anchor import ANCHOR_FIELD, AnchorReceipt
    from signet.audit.chain import ALG_FIELD, KEY_ID_FIELD, _serialize_for_signing
    from signet.audit.keyring import ALG_HMAC_SHA256

    active = chain._keyring.active
    if not active.can_sign:
        raise ValueError(
            f"Active key {active.key_id!r} ({active.algorithm}) is verify-only and cannot sign compaction markers"
        )

    marker_sig_payload = _marker_signature_payload(
        archive_format_version=ARCHIVE_FORMAT_VERSION,
        archive_path=str(archive_path),
        compacted_count=compacted_count,
        merkle_root=merkle_root,
        range_start=range_start,
        range_end=range_end,
    )
    marker_signature = active.sign(marker_sig_payload)

    marker_payload = {
        "archive_format_version": ARCHIVE_FORMAT_VERSION,
        "archive_path": str(archive_path),
        "compacted_count": compacted_count,
        "merkle_root": merkle_root,
        "range_end": range_end,
        "range_start": range_start,
        COMPACTION_MARKER_SIG_FIELD: marker_signature,
    }
    marker_entry = AuditEntry(
        owner=Owner.policy("audit-compactor"),
        check_name=COMPACTION_CHECK_NAME,
        decision=Decision.ALLOW,
        reason=f"compacted {compacted_count} entries into {archive_path.name}",
        metadata={COMPACTION_MARKER_FIELD: marker_payload},
    )

    stamped: dict[str, str] = {KEY_ID_FIELD: active.key_id}
    if active.algorithm != ALG_HMAC_SHA256:
        stamped[ALG_FIELD] = active.algorithm

    # First pass: tentative signature for anchor submission.
    tentative = replace(
        marker_entry,
        metadata={**marker_entry.metadata, **stamped},
        prev_hmac=prev_hmac,
    )
    tentative_payload = _serialize_for_signing(tentative)
    tentative_hmac = active.sign(tentative_payload)

    try:
        anchor_receipt = chain._anchor.anchor_hmac(tentative_hmac)
    except Exception as exc:
        if chain._require_anchor_success:
            raise
        anchor_receipt = AnchorReceipt(
            backend=chain._anchor.name,
            success=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    if not anchor_receipt.success and chain._require_anchor_success:
        raise RuntimeError(
            f"anchor backend {chain._anchor.name!r} failed during compaction "
            f"(require_anchor_success=True): {anchor_receipt.error}"
        )

    anchored_metadata = {
        **marker_entry.metadata,
        **stamped,
        ANCHOR_FIELD: anchor_receipt.to_dict(),
    }
    anchored = replace(
        marker_entry,
        metadata=anchored_metadata,
        prev_hmac=prev_hmac,
    )
    payload = _serialize_for_signing(anchored)
    final_hmac = active.sign(payload)
    return anchored.with_chain_links(prev_hmac=prev_hmac, hmac=final_hmac)


def _atomic_rewrite_live_log(*, backend: JsonlBackend, new_entries: list[AuditEntry]) -> None:
    """Replace the contents of ``backend.path`` with ``new_entries``.

    Writes to a temp file in the same directory, fsyncs, and
    :func:`os.replace`-s into place. Atomic on POSIX; on Windows
    ``os.replace`` is the documented atomic-replace primitive (it maps
    to ``MoveFileExW`` with ``MOVEFILE_REPLACE_EXISTING``).
    """
    target = backend.path
    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".compact-",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            for entry in new_entries:
                line = json.dumps(
                    entry.to_dict(),
                    separators=(",", ":"),
                    sort_keys=True,
                    allow_nan=False,
                    ensure_ascii=False,
                )
                f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
    except Exception:
        import contextlib

        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def trim_before_index(
    backend: JsonlBackend,
    index: int,
    *,
    chain: HmacChain | None = None,
) -> int:
    """Remove the first ``index`` entries from the backend's live log.

    Returns the new entry count. This is provided as a free function
    rather than a :class:`JsonlBackend` method because trimming is a
    compaction-only concern -- the rest of the chain treats the backend
    as strictly append-only, and adding a delete method to the public
    backend protocol would invite misuse.

    Atomicity: same temp-file + ``os.replace`` pattern used elsewhere
    in this module.

    Round 7 MED-1: when ``chain`` is supplied, its ``_cached_prev`` is
    invalidated AFTER the rewrite so a subsequent
    :meth:`HmacChain.append` re-reads the chain head from disk-truth
    rather than linking the next entry to a hmac that no longer exists
    in the trimmed log. Operators reusing a chain across a trim MUST
    pass ``chain=`` here -- omitting it silently forks the chain on the
    next append (the cached prev points to an entry that was just
    removed).
    """
    if index < 0:
        raise ValueError(f"trim_before_index: index must be >= 0, got {index}")
    with exclusive_log_lock(backend.path):
        entries = list(backend.iter_entries())
        if index >= len(entries):
            # Trim everything: empty file. Operators usually won't want this,
            # but the result is well-defined.
            retained: list[AuditEntry] = []
        else:
            retained = entries[index:]
        _atomic_rewrite_live_log(backend=backend, new_entries=retained)
        # Clear both prev-HMAC and sequence caches so the next ``append``
        # re-reads the (now-truncated) tail from disk. Mirrors
        # ``compact_audit_log``'s post-rewrite invalidation.
        if chain is not None:
            with chain._lock:
                chain._cached_prev = None
                chain._cached_seq = None
    return len(retained)


def _has_marker_shape(entry: AuditEntry) -> bool:
    """Cheap structural check: True if ``entry`` has compaction-marker
    shape, regardless of MAC validity.

    Round 9 HIGH-2: marker recognition is split into two layers so
    callers can choose between *recognition* and *trust*.

    * **Shape** (this function): same fields the pre-Round-8 shape-only
      :func:`is_compaction_marker` required -- ``check_name`` is the
      marker sentinel, ``_compaction_marker`` metadata is a dict, and
      a ``_marker_signature`` string is present. Used by:

      - :func:`verify_with_archives` to dispatch into archive-walking
        mode even if the marker's MAC can no longer be verified (e.g.
        the signing key was revoked from the ring). Without the
        dispatch the verifier would mis-report a phantom
        ``LINK_MISMATCH`` cascade on legitimate post-revocation
        chains.
      - :func:`compact_audit_log`'s A2 guard to refuse re-compaction
        across a marker-shaped entry even when MAC verification fails
        (otherwise A2 silently fails open and the marker is archived
        into a corrupting second archive).

    * **MAC trust** (:func:`is_compaction_marker` with ``keyring=``):
      verifies the marker's MAC against the ring's keys. Used when a
      caller needs to *trust* the marker's claimed ``merkle_root`` /
      ``archive_path`` / ``compacted_count``.

    A shape-only check is safe for dispatch/guard purposes because an
    attacker-crafted marker-shaped entry that fails MAC verification
    is treated identically to a legitimately-signed marker whose key
    was revoked: the chain refuses further compaction and the
    verifier surfaces an actionable ``UNKNOWN_KEY``-style break on
    that entry instead of silently miscarrying.
    """
    if entry.check_name != COMPACTION_CHECK_NAME:
        return False
    marker = entry.metadata.get(COMPACTION_MARKER_FIELD)
    if not isinstance(marker, dict):
        return False
    # Round 23 F-R23-8: an empty string passes ``isinstance(..., str)`` but
    # is never a legitimate marker signature (real markers carry a
    # 64-character hex HMAC). Accepting ``""`` here would let an attacker
    # spoof a marker shape with a signature the MAC verifier trivially
    # rejects but the A2 guard / verifier dispatch still honors -- a
    # cheap DoS primitive against future compactions. Require non-empty.
    sig = marker.get(COMPACTION_MARKER_SIG_FIELD)
    return isinstance(sig, str) and len(sig) > 0


def is_compaction_marker(
    entry: AuditEntry,
    *,
    keyring: KeyRing | None = None,
) -> bool:
    """True if ``entry`` is a compaction-marker entry.

    Round 7 LOW-1: when ``keyring`` is supplied, the marker's
    :data:`COMPACTION_MARKER_SIG_FIELD` is recomputed against the
    keyring's keys (active + legacy) and the function returns ``True``
    only when one of them produces a matching MAC. This closes the
    user-crafted-fake-compaction-marker DoS where any caller able to
    append an entry with ``check_name == "_compaction"`` and the
    matching shape could permanently block future compactions via
    the A2 guard.

    Without ``keyring`` the legacy shape-only check is performed --
    callers walking entries without crypto context (e.g. external
    tools listing markers) still need a way to recognize the form,
    and the security-critical caller (the A2 guard in
    :func:`compact_audit_log`) explicitly passes the keyring.

    Round 9 HIGH-2: this function answers "should I TRUST this marker"
    (used for downstream merkle/archive decisions). For "is this
    marker-shaped" (dispatch + DoS-guard), use :func:`_has_marker_shape`,
    which does not depend on the ring containing the marker's signing
    key. The split keeps key revocation from collapsing the verifier's
    bridge dispatch and the compactor's A2 guard at the same time.
    """
    if entry.check_name != COMPACTION_CHECK_NAME:
        return False
    marker = entry.metadata.get(COMPACTION_MARKER_FIELD)
    if not isinstance(marker, dict):
        return False
    if keyring is None:
        return True
    # Keyring-aware path: verify the marker signature with the active key
    # and any legacy keys (a marker written under a previous era's key
    # must still be recognized).
    expected = marker.get(COMPACTION_MARKER_SIG_FIELD)
    if not isinstance(expected, str):
        return False
    try:
        archive_format_version = int(marker["archive_format_version"])
        archive_path = str(marker["archive_path"])
        compacted_count = int(marker["compacted_count"])
        merkle_root = str(marker["merkle_root"])
        range_start = str(marker["range_start"])
        range_end = str(marker["range_end"])
    except (KeyError, TypeError, ValueError):
        return False
    marker_sig_payload = _marker_signature_payload(
        archive_format_version=archive_format_version,
        archive_path=archive_path,
        compacted_count=compacted_count,
        merkle_root=merkle_root,
        range_start=range_start,
        range_end=range_end,
    )
    for key_id in keyring.all_known_ids():
        key = keyring.get(key_id)
        if key is None:
            continue
        if key.verify(marker_sig_payload, expected):
            return True
    return False


def _signet_version() -> str:
    """Look up ``signet.__version__`` lazily to avoid an import cycle.

    ``signet/__init__.py`` is intentionally crypto-free, but at module
    import time of this file the parent package's ``__version__`` may
    or may not yet be set depending on import order. Resolving it at
    write time keeps things safe.
    """
    try:
        from signet import __version__

        return str(__version__)
    except ImportError:
        return "unknown"


__all__ = [
    "ARCHIVE_FORMAT_VERSION",
    "COMPACTION_CHECK_NAME",
    "COMPACTION_MARKER_FIELD",
    "COMPACTION_MARKER_SIG_FIELD",
    "ArchiveHeader",
    "CompactionResult",
    "MerkleTree",
    "compact_audit_log",
    "is_compaction_marker",
    "read_archive",
    "trim_before_index",
]
