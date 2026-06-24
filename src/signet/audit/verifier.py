"""ChainVerifier -- walks an audit chain and reports tampering.

Verification is read-only and offline: given a backend and a key ring,
walk every entry in order, recompute its HMAC, check the recomputed value
against the stored ``hmac``, and check the stored ``prev_hmac`` against
the previous entry's ``hmac``. Any mismatch is a *break*.

Returns a :class:`VerificationReport` with structured per-break detail.
The report distinguishes:

* **Self-mismatch** -- the entry's own payload was modified (its HMAC
  doesn't match its content).
* **Link-mismatch** -- the entry's ``prev_hmac`` doesn't match the
  previous entry's ``hmac``. Indicates insertion, deletion, or
  reordering.
* **Unknown-key** -- the entry's signing key ID is not in the ring; we
  can't verify it. Distinct from a tamper finding: usually means the
  ring is missing a legacy key.
* **Missing-key-id** -- the entry has no signing-key-id metadata field.
  Either pre-dates the chain feature or was tampered to drop the marker.
* **Merkle-mismatch** -- a compaction marker's claimed Merkle root does
  not match the recomputed root over the linked archive's contents.
  Surfaced by :func:`verify_with_archives` only.
* **Archive-missing** -- a compaction marker references an archive file
  that is not present in the supplied ``archive_dir``. Surfaced by
  :func:`verify_with_archives` only.
* **Archive-format-invalid** -- an archive file exists but cannot be
  parsed (truncated, wrong magic, version mismatch, internal-root
  mismatch). Surfaced by :func:`verify_with_archives` only.

The CLI surfaces this through ``signet audit verify`` and (with
archive walking) ``signet audit verify --including-archives``.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from signet import __version__ as _SIGNET_VERSION
from signet.audit.backend import AuditBackend, MalformedAuditEntry
from signet.audit.chain import KEY_ID_FIELD, _serialize_for_signing
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry


class BreakKind(StrEnum):
    """Discriminator for the kind of integrity failure encountered."""

    SELF_MISMATCH = "self_mismatch"
    """The entry's stored HMAC does not match a recomputation from its
    payload + prev_hmac. The entry was modified after writing."""

    LINK_MISMATCH = "link_mismatch"
    """The entry's prev_hmac does not match the previous entry's hmac.
    Indicates insertion, deletion, or reordering somewhere in the chain."""

    UNKNOWN_KEY = "unknown_key"
    """The entry references a signing key ID not present in the
    :class:`KeyRing`. Verification cannot proceed for this entry."""

    MISSING_KEY_ID = "missing_key_id"
    """The entry has no signing-key-id metadata field. Either pre-dates
    the chain feature or was tampered to drop the marker."""

    MERKLE_MISMATCH = "merkle_mismatch"
    """A compaction marker's claimed Merkle root does not match the
    root recomputed from the archive's contents. The archive or marker
    was tampered with after compaction."""

    ARCHIVE_MISSING = "archive_missing"
    """A compaction marker references an archive file not present in
    the supplied archive directory. Either the archive was deleted, or
    the operator pointed the verifier at the wrong directory."""

    ARCHIVE_FORMAT_INVALID = "archive_format_invalid"
    """An archive file is present but malformed -- bad magic prefix,
    unknown format version, or truncated payload. Treat as a tamper
    finding; archives are written deterministically so a corrupt one
    means human or hardware interference."""

    MALFORMED_LINE = "malformed_line"
    """A line in the live log is not parseable JSON -- mid-write
    truncation (process killed during ``fsync``), accidental editor
    save, or hostile injection of a non-JSON line. Reported with the
    1-based line number and the underlying parse error so the operator
    can locate it. Iteration stops at the offending line; subsequent
    entries are not visible until the line is repaired."""

    CASCADE_SUPPRESSED = "cascade_suppressed"
    """A summary break standing in for ``N`` downstream
    ``LINK_MISMATCH`` entries that all cascade from a single upstream
    forgery / tamper / link break. Emitted only when the verifier is
    asked to compact reports (``compact_breaks=True``) so a 1k-entry
    forgery doesn't drown the report in 1k+ identical-shaped breaks."""


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """One integrity failure in the chain."""

    index: int
    """Zero-based position of the entry within the chain."""

    entry_id: str
    """The audit entry's UUID. Useful for cross-referencing with
    application logs."""

    kind: BreakKind
    """What kind of break this is."""

    detail: str
    """Human-readable rationale, including expected/actual fragments
    where relevant."""


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The output of :meth:`ChainVerifier.verify`.

    Attributes:
        total_entries: Number of entries walked.
        breaks: Per-entry integrity failures, in chain order.
        last_known_good_index: Index of the last entry that verified
            cleanly. ``-1`` is a **sentinel** meaning "no entry
            verified cleanly" -- most commonly seen when the chain was
            verified under the wrong HMAC secret (every entry then
            self-mismatches and there is no last-good index to point
            at). Do NOT interpret as an offset into the chain (A14).
        last_known_good_hmac: HMAC of the last entry that verified
            cleanly. Empty string is the matching sentinel for
            ``last_known_good_index = -1`` (A14).
        signet_version: signet version that produced this report
            (A13). Useful for long-term forensics where a stored
            verify report needs to be tied to the binary that
            produced it.
        verified_at: Wall-clock timestamp (UTC, ISO 8601) when
            verification ran (A13).
    """

    total_entries: int
    breaks: tuple[ChainBreak, ...] = field(default_factory=tuple)
    last_known_good_index: int = -1
    last_known_good_hmac: str = ""
    signet_version: str = _SIGNET_VERSION
    verified_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def ok(self) -> bool:
        """``True`` if no breaks were detected."""
        return len(self.breaks) == 0


class ChainVerifier:
    """Walk a backend's chain end-to-end and report any tampering."""

    def __init__(
        self,
        backend: AuditBackend,
        keyring: KeyRing,
        *,
        compact_breaks: bool = False,
    ) -> None:
        """Walk ``backend`` under ``keyring`` and report integrity failures.

        Args:
            backend: The audit backend to read from.
            keyring: The signing keys covering the chain.
            compact_breaks: When True, collapse cascading
                :attr:`BreakKind.LINK_MISMATCH` runs that follow a
                single upstream tamper into one
                :attr:`BreakKind.CASCADE_SUPPRESSED` summary break.
                Useful for keeping large-chain reports readable when a
                single forgery would otherwise surface as N+ link
                breaks. Default False preserves v0.1.6 behavior.
        """
        self._backend = backend
        self._keyring = keyring
        self._compact_breaks = compact_breaks

    def verify(self) -> VerificationReport:
        """Walk every entry in order and return a structured report.

        The returned :class:`VerificationReport` carries
        ``signet_version`` and ``verified_at`` (A13) for long-term
        forensics. ``last_known_good_index = -1`` is a SENTINEL
        meaning "no entry verified cleanly" -- typically the wrong
        HMAC secret was supplied -- and is not a valid chain offset
        (A14).
        """
        breaks: list[ChainBreak] = []
        prev_hmac = ""
        last_good_idx = -1
        last_good_hmac = ""
        total_entries = 0
        # A11: when compact_breaks is on, runs of consecutive
        # LINK_MISMATCH entries downstream of a tamper get collapsed
        # into a single CASCADE_SUPPRESSED summary break.
        cascade_active = False
        cascade_count = 0
        cascade_first_idx = -1

        def _flush_cascade() -> None:
            nonlocal cascade_active, cascade_count, cascade_first_idx
            if cascade_active and cascade_count > 0:
                breaks.append(
                    ChainBreak(
                        index=cascade_first_idx,
                        entry_id="",
                        kind=BreakKind.CASCADE_SUPPRESSED,
                        detail=(
                            f"{cascade_count} downstream entries reported "
                            f"link_mismatch cascading from upstream tamper; "
                            f"individual breaks suppressed (compact_breaks=True)"
                        ),
                    )
                )
            cascade_active = False
            cascade_count = 0
            cascade_first_idx = -1

        try:
            for index, entry in enumerate(self._backend.iter_entries()):
                total_entries = index + 1
                # A6: track whether THIS entry already produced a
                # link_mismatch -- when it has, the self_mismatch on
                # the same index is suppressed because both checks
                # share an input (``prev_hmac`` is part of the signed
                # payload), so a single-byte tamper naturally trips
                # both. The report reader expects one canonical break.
                link_break_at_this_index = False
                # Link check: this entry's prev_hmac must match the prior entry's hmac
                if entry.prev_hmac != prev_hmac:
                    if self._compact_breaks and cascade_active:
                        cascade_count += 1
                    else:
                        breaks.append(
                            ChainBreak(
                                index=index,
                                entry_id=entry.entry_id,
                                kind=BreakKind.LINK_MISMATCH,
                                detail=(
                                    f"prev_hmac={entry.prev_hmac[:16]}... does not match "
                                    f"previous entry's hmac={prev_hmac[:16] or '(empty)'}..."
                                ),
                            )
                        )
                        if self._compact_breaks:
                            cascade_active = True
                            cascade_count = 0
                            cascade_first_idx = index + 1
                    link_break_at_this_index = True
                else:
                    # A clean link ends any active cascade.
                    _flush_cascade()

                # Identify which key signed this entry. The legitimate
                # absence path is ``metadata`` carries no
                # ``_signing_key_id`` at all (None) or the empty string
                # sentinel: surface as ``MISSING_KEY_ID``. Any present-
                # but-not-a-string value (list, dict, int, etc.) is a
                # tampered row -- see F-R25-1 closure below.
                key_id = entry.metadata.get(KEY_ID_FIELD)
                if key_id is None or key_id == "":
                    breaks.append(
                        ChainBreak(
                            index=index,
                            entry_id=entry.entry_id,
                            kind=BreakKind.MISSING_KEY_ID,
                            detail=f"entry has no {KEY_ID_FIELD!r} field in metadata",
                        )
                    )
                    prev_hmac = entry.hmac
                    continue

                # Round 25 MED (F-R25-1): a tampered ``_signing_key_id``
                # of unhashable type (list, dict, set) would crash
                # ``KeyRing.get`` with a raw ``TypeError: unhashable
                # type`` traceback, bypassing the structured-break
                # channel that R23-5 closed for top-level fields. Reject
                # any non-string ``key_id`` here and surface as a
                # ``MALFORMED_LINE`` break -- the same routing
                # tampered-on-disk lines already get via
                # ``MalformedAuditEntry``. This also catches empty
                # containers (``[]``, ``{}``) that the falsy check
                # above intentionally narrows past, since they're
                # tamper shapes that don't match the
                # ``MISSING_KEY_ID`` semantics. Hashable-but-wrong-type
                # cases (int=42) used to route through ``UNKNOWN_KEY``
                # via ``legacy.get(<int>) -> None`` -- they now route
                # through ``MALFORMED_LINE`` so the schema invariant
                # is uniform: ``_signing_key_id`` is always either
                # absent or a non-empty ``str``.
                if not isinstance(key_id, str):
                    breaks.append(
                        ChainBreak(
                            index=index,
                            entry_id=entry.entry_id,
                            kind=BreakKind.MALFORMED_LINE,
                            detail=(
                                f"{KEY_ID_FIELD!r} must be a string, got {type(key_id).__name__}"
                            ),
                        )
                    )
                    prev_hmac = entry.hmac
                    continue

                key = self._keyring.get(key_id)
                if key is None:
                    breaks.append(
                        ChainBreak(
                            index=index,
                            entry_id=entry.entry_id,
                            kind=BreakKind.UNKNOWN_KEY,
                            detail=(
                                f"entry signed with key_id={key_id!r} but that key is "
                                f"not in the ring (known: {', '.join(self._keyring.all_known_ids())})"
                            ),
                        )
                    )
                    prev_hmac = entry.hmac
                    continue

                # Self check: recompute the HMAC and compare
                try:
                    expected_payload = _serialize_for_signing(entry)
                except (ValueError, RuntimeError) as exc:
                    # A non-canonicalizable payload (NaN/Inf in metadata,
                    # an unknown/tampered _canon marker, or a missing JCS
                    # backend) must not crash the walk. Surface it as a
                    # structured MALFORMED_LINE break and move on.
                    breaks.append(
                        ChainBreak(
                            index=index,
                            entry_id=entry.entry_id,
                            kind=BreakKind.MALFORMED_LINE,
                            detail=f"entry payload is not canonicalizable: {exc}",
                        )
                    )
                    prev_hmac = entry.hmac
                    continue
                expected_hmac = hmac.new(key.secret, expected_payload, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected_hmac, entry.hmac):
                    if not link_break_at_this_index:
                        breaks.append(
                            ChainBreak(
                                index=index,
                                entry_id=entry.entry_id,
                                kind=BreakKind.SELF_MISMATCH,
                                detail=(
                                    f"recomputed hmac={expected_hmac[:16]}... does not match "
                                    f"stored hmac={entry.hmac[:16]}..."
                                ),
                            )
                        )
                else:
                    last_good_idx = index
                    last_good_hmac = entry.hmac

                prev_hmac = entry.hmac
        except MalformedAuditEntry as exc:
            # A3: turn a malformed JSONL line into a structured break
            # rather than letting JSONDecodeError propagate. Iteration
            # stops at the bad line -- the rest of the file is opaque
            # until the operator repairs the line. Subsequent entries
            # are not reported.
            breaks.append(
                ChainBreak(
                    index=total_entries,
                    entry_id="",
                    kind=BreakKind.MALFORMED_LINE,
                    detail=(f"line {exc.line_number}: cannot parse as JSON: {exc.parse_error}"),
                )
            )
        finally:
            _flush_cascade()

        return VerificationReport(
            total_entries=total_entries,
            breaks=tuple(breaks),
            last_known_good_index=last_good_idx,
            last_known_good_hmac=last_good_hmac,
        )


def _verify_entry_self(
    *,
    index: int,
    entry: AuditEntry,
    keyring: KeyRing,
    breaks: list[ChainBreak],
    suppress_self_mismatch: bool = False,
) -> bool:
    """Verify one entry's self-HMAC. Append a break on failure.

    Returns True if the entry's signing key was found and the HMAC
    matched, False otherwise. The link check is the caller's
    responsibility -- link semantics differ between the simple
    walker and the archive-aware walker.

    ``suppress_self_mismatch`` (A6): when True, an HMAC mismatch is
    NOT reported as a separate ``SELF_MISMATCH`` break -- the caller
    has already reported a ``LINK_MISMATCH`` for this entry and the
    two checks share an input (``prev_hmac`` is part of the signed
    payload), so a single byte of tampering naturally trips both.
    The function still returns False so cascade tracking and
    last-known-good bookkeeping behave correctly.
    """
    key_id = entry.metadata.get(KEY_ID_FIELD)
    if key_id is None or key_id == "":
        breaks.append(
            ChainBreak(
                index=index,
                entry_id=entry.entry_id,
                kind=BreakKind.MISSING_KEY_ID,
                detail=f"entry has no {KEY_ID_FIELD!r} field in metadata",
            )
        )
        return False
    # Round 25 MED (F-R25-1): same defense as the live-only walker --
    # a non-string ``_signing_key_id`` (unhashable list/dict/set, or
    # an empty container the falsy check intentionally narrows past)
    # would crash ``KeyRing.get`` with a raw traceback. Surface as a
    # structured ``MALFORMED_LINE`` break instead. See the live walker
    # for full rationale.
    if not isinstance(key_id, str):
        breaks.append(
            ChainBreak(
                index=index,
                entry_id=entry.entry_id,
                kind=BreakKind.MALFORMED_LINE,
                detail=(f"{KEY_ID_FIELD!r} must be a string, got {type(key_id).__name__}"),
            )
        )
        return False
    key = keyring.get(key_id)
    if key is None:
        breaks.append(
            ChainBreak(
                index=index,
                entry_id=entry.entry_id,
                kind=BreakKind.UNKNOWN_KEY,
                detail=(
                    f"entry signed with key_id={key_id!r} but that key is "
                    f"not in the ring (known: {', '.join(keyring.all_known_ids())})"
                ),
            )
        )
        return False

    try:
        expected_payload = _serialize_for_signing(entry)
    except (ValueError, RuntimeError) as exc:
        breaks.append(
            ChainBreak(
                index=index,
                entry_id=entry.entry_id,
                kind=BreakKind.MALFORMED_LINE,
                detail=f"entry payload is not canonicalizable: {exc}",
            )
        )
        return False
    expected_hmac = hmac.new(key.secret, expected_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, entry.hmac):
        if not suppress_self_mismatch:
            breaks.append(
                ChainBreak(
                    index=index,
                    entry_id=entry.entry_id,
                    kind=BreakKind.SELF_MISMATCH,
                    detail=(
                        f"recomputed hmac={expected_hmac[:16]}... does not match "
                        f"stored hmac={entry.hmac[:16]}..."
                    ),
                )
            )
        return False
    return True


def verify_with_archives(
    backend: AuditBackend,
    keyring: KeyRing,
    archive_dir: Path,
    *,
    compact_breaks: bool = False,
) -> VerificationReport:
    """Walk the live log + every referenced archive as one logical chain.

    On each compaction marker encountered in the live log, this
    verifier:

    1. Looks up the marker's referenced archive in ``archive_dir``.
    2. Reads the archive and recomputes the Merkle root from its
       contents.
    3. Compares the recomputed root against the marker's claimed root.
       Mismatch → :attr:`BreakKind.MERKLE_MISMATCH`.
    4. Verifies each archived entry's self-HMAC and internal link
       chain. Any failure is reported with the entry's archive index
       (offset from the start of the archive's entries) and an
       ``in archive <name>`` annotation in the detail string.
    5. Validates that the marker's ``prev_hmac`` matches the LAST
       archived entry's ``hmac`` (the bridge from live log into
       archive).
    6. After the marker, the next live-log entry is treated as the
       continuation of the archive: its ``prev_hmac`` MUST match the
       last archived entry's ``hmac``. This is the bridge from archive
       back into the live log.

    The "live-only" :class:`ChainVerifier` is unchanged. Use it when
    you only need to walk the trimmed live log (cheap) and don't have
    the archives accessible. Use this function for the full-chain
    verification path that ``signet audit verify --including-archives``
    exposes.

    Missing archive (marker references ``archive-X.bin`` but the file
    isn't on disk) → :attr:`BreakKind.ARCHIVE_MISSING`. Malformed
    archive → :attr:`BreakKind.ARCHIVE_FORMAT_INVALID`.

    Args:
        backend: The (post-compaction) live log backend.
        keyring: The signing keys covering the entire logical chain,
            including any keys in use during the archived ranges.
        archive_dir: Directory containing the archive files referenced
            by every compaction marker in the live log. The marker's
            ``archive_path`` may be absolute or relative; the verifier
            tries the absolute path first, then ``archive_dir / Path(
            absolute).name``.
        compact_breaks: When True (A11), runs of consecutive
            :attr:`BreakKind.LINK_MISMATCH` entries downstream of a
            single tamper are collapsed into one
            :attr:`BreakKind.CASCADE_SUPPRESSED` summary break.

    Returns:
        A :class:`VerificationReport`. ``total_entries`` is the count
        across all segments (live log + every archive), so a chain
        with one archive of 47k entries plus 3k live entries reports
        50k.
    """
    # Local imports keep this module's import surface narrow for callers
    # that only use the live-only verifier.
    from signet.audit.compactor import (
        COMPACTION_MARKER_FIELD,
        MerkleTree,
        _has_marker_shape,
        read_archive,
    )

    archive_dir = Path(archive_dir)
    breaks: list[ChainBreak] = []
    total_entries = 0
    last_known_good_index = -1
    last_known_good_hmac = ""
    # The expected prev_hmac for the next entry we encounter. Updated
    # as we walk, including across the archive bridge.
    expected_prev = ""
    # Logical index across the whole chain (live + archives).
    logical_index = 0
    # A11 cascade tracking -- same shape as the live-only verifier.
    cascade_active = False
    cascade_count = 0
    cascade_first_idx = -1
    # A10 (v0.1.7): when an archive is unreadable
    # (ARCHIVE_FORMAT_INVALID), the verifier loses the bridge hmac
    # and the *next* live entry would otherwise emit a synthetic
    # LINK_MISMATCH against the marker's hmac. That's noisy
    # (forensically: two breaks for one corruption) and unhelpful
    # (the link genuinely cannot be checked). When this flag is set,
    # we suppress exactly one downstream link_mismatch and re-anchor
    # ``expected_prev`` to that entry's hmac so subsequent entries
    # link normally against it.
    suppress_one_link_mismatch_after_archive = False

    def _flush_cascade() -> None:
        nonlocal cascade_active, cascade_count, cascade_first_idx
        if cascade_active and cascade_count > 0:
            breaks.append(
                ChainBreak(
                    index=cascade_first_idx,
                    entry_id="",
                    kind=BreakKind.CASCADE_SUPPRESSED,
                    detail=(
                        f"{cascade_count} downstream entries reported "
                        f"link_mismatch cascading from upstream tamper; "
                        f"individual breaks suppressed (compact_breaks=True)"
                    ),
                )
            )
        cascade_active = False
        cascade_count = 0
        cascade_first_idx = -1

    try:
        for entry in backend.iter_entries():
            # Round 7 LOW-1 / Round 9 HIGH-2: dispatch on marker SHAPE
            # so a marker whose MAC can no longer be verified (e.g.
            # the marker's signing key was revoked from the ring)
            # still switches into archive-walking mode. Otherwise the
            # marker would be treated as a plain live entry, its
            # ``prev_hmac`` (which points at the last archived entry's
            # hmac, not the empty-chain sentinel) would mis-fire as a
            # phantom ``LINK_MISMATCH``, and every subsequent live
            # entry would cascade off the wrong ``expected_prev``.
            # The MAC check then runs *inside* the marker branch and
            # surfaces as an actionable ``UNKNOWN_KEY`` break on the
            # marker so the operator can re-add the marker's signing
            # key (or accept the marker as a known-orphan).
            if not _has_marker_shape(entry):
                # Plain live entry: standard self + link checks.
                link_break_at_this_index = False
                if entry.prev_hmac != expected_prev:
                    if suppress_one_link_mismatch_after_archive:
                        # A10: archive was unreadable; suppress this
                        # synthetic break and re-anchor on this entry.
                        # Subsequent entries chain off this one
                        # normally.
                        suppress_one_link_mismatch_after_archive = False
                        link_break_at_this_index = True
                    elif compact_breaks and cascade_active:
                        cascade_count += 1
                        link_break_at_this_index = True
                    else:
                        breaks.append(
                            ChainBreak(
                                index=logical_index,
                                entry_id=entry.entry_id,
                                kind=BreakKind.LINK_MISMATCH,
                                detail=(
                                    f"prev_hmac={entry.prev_hmac[:16]}... does not match "
                                    f"expected previous hmac={expected_prev[:16] or '(empty)'}..."
                                ),
                            )
                        )
                        if compact_breaks:
                            cascade_active = True
                            cascade_count = 0
                            cascade_first_idx = logical_index + 1
                        link_break_at_this_index = True
                else:
                    _flush_cascade()
                    # Any clean link clears a pending archive-suppress
                    # flag -- we recovered without needing it.
                    suppress_one_link_mismatch_after_archive = False
                ok = _verify_entry_self(
                    index=logical_index,
                    entry=entry,
                    keyring=keyring,
                    breaks=breaks,
                    suppress_self_mismatch=link_break_at_this_index,
                )
                if ok:
                    last_known_good_index = logical_index
                    last_known_good_hmac = entry.hmac
                total_entries += 1
                logical_index += 1
                expected_prev = entry.hmac
                continue

            # Compaction marker. Walk the archive first so we have its
            # last hmac to use both for the marker's own link check and
            # for the bridge to the next live entry.
            marker_meta = entry.metadata[COMPACTION_MARKER_FIELD]
            archive_path_str = str(marker_meta.get("archive_path", ""))
            claimed_root = str(marker_meta.get("merkle_root", ""))
            claimed_count = int(marker_meta.get("compacted_count", 0))

            # Resolve the archive: try the absolute path embedded in the
            # marker first, then fall back to archive_dir/<basename>. This
            # keeps deployments working when the audit log is moved
            # between machines (the absolute path is no longer valid but
            # the basename is stable).
            archive_path = Path(archive_path_str)
            if not archive_path.exists():
                fallback = archive_dir / archive_path.name
                if fallback.exists():
                    archive_path = fallback
                else:
                    breaks.append(
                        ChainBreak(
                            index=logical_index,
                            entry_id=entry.entry_id,
                            kind=BreakKind.ARCHIVE_MISSING,
                            detail=(
                                f"compaction marker references archive {archive_path_str!r} "
                                f"but neither it nor {fallback} exists"
                            ),
                        )
                    )
                    # Without the archive we can't bridge. Verify the
                    # marker's self-HMAC (still meaningful) and continue
                    # with expected_prev = marker.hmac so subsequent live
                    # entries don't all cascade as link breaks. This is
                    # operationally inaccurate (the next live entry
                    # actually links to last_archived.hmac, not
                    # marker.hmac) but it produces one ARCHIVE_MISSING
                    # break per missing archive instead of N+1 cascading
                    # breaks per live entry.
                    _verify_entry_self(
                        index=logical_index,
                        entry=entry,
                        keyring=keyring,
                        breaks=breaks,
                    )
                    total_entries += 1
                    logical_index += 1
                    expected_prev = entry.hmac
                    continue

            try:
                header, tree, archived_entries = read_archive(archive_path)
            except (ValueError, KeyError, TypeError) as exc:
                # Round 7 HIGH-2: ``_read_archive`` now routes
                # ``KeyError`` / ``TypeError`` through ``ValueError``, but
                # widen the catch here as defense-in-depth so any future
                # surface that escapes the inner wrapper still surfaces as
                # a structured ``ARCHIVE_FORMAT_INVALID`` break rather
                # than a raw Python traceback.
                breaks.append(
                    ChainBreak(
                        index=logical_index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.ARCHIVE_FORMAT_INVALID,
                        detail=f"archive {archive_path.name}: {exc}",
                    )
                )
                _verify_entry_self(
                    index=logical_index,
                    entry=entry,
                    keyring=keyring,
                    breaks=breaks,
                )
                total_entries += 1
                logical_index += 1
                expected_prev = entry.hmac
                # A10: archive was unreadable; the bridge hmac is lost.
                # Suppress the synthetic LINK_MISMATCH on the next live
                # entry -- one corruption, one break.
                suppress_one_link_mismatch_after_archive = True
                continue

            # Walk the archived entries first, in their own logical-index
            # range that comes BEFORE the marker. This is what the format
            # spec calls "logical chain order": archived entries come
            # before the marker that summarizes them, even though the
            # marker is the entry physically at the top of the post-
            # compaction live log.
            archive_base_index = logical_index
            archive_expected_prev = expected_prev
            for archive_idx, archived in enumerate(archived_entries):
                archive_link_break = False
                if archived.prev_hmac != archive_expected_prev:
                    if compact_breaks and cascade_active:
                        cascade_count += 1
                    else:
                        breaks.append(
                            ChainBreak(
                                index=archive_base_index + archive_idx,
                                entry_id=archived.entry_id,
                                kind=BreakKind.LINK_MISMATCH,
                                detail=(
                                    f"archive {archive_path.name} entry {archive_idx}: "
                                    f"prev_hmac={archived.prev_hmac[:16]}... does not match "
                                    f"expected={archive_expected_prev[:16] or '(empty)'}..."
                                ),
                            )
                        )
                        if compact_breaks:
                            cascade_active = True
                            cascade_count = 0
                            cascade_first_idx = archive_base_index + archive_idx + 1
                    archive_link_break = True
                else:
                    _flush_cascade()
                archive_ok = _verify_entry_self(
                    index=archive_base_index + archive_idx,
                    entry=archived,
                    keyring=keyring,
                    breaks=breaks,
                    suppress_self_mismatch=archive_link_break,
                )
                if archive_ok:
                    last_known_good_index = archive_base_index + archive_idx
                    last_known_good_hmac = archived.hmac
                archive_expected_prev = archived.hmac

            last_archived_hmac = archived_entries[-1].hmac if archived_entries else ""

            # Recompute the Merkle root from the archive's contents and
            # compare against the marker's claim. A mismatch can come from
            # (a) the marker being modified, (b) the archive being modified,
            # or (c) the archive's serialized tree being modified -- the
            # deserialize step asserts the stored root matches the
            # recomputation, so (c) is already an ARCHIVE_FORMAT_INVALID.
            recomputed_tree = MerkleTree.from_entries(archived_entries)
            if (
                recomputed_tree.root != claimed_root
                or header.merkle_root != claimed_root
                or tree.root != claimed_root
            ):
                breaks.append(
                    ChainBreak(
                        index=archive_base_index + len(archived_entries),
                        entry_id=entry.entry_id,
                        kind=BreakKind.MERKLE_MISMATCH,
                        detail=(
                            f"archive {archive_path.name} merkle root "
                            f"recomputed={recomputed_tree.root[:16]}... does not match "
                            f"marker's claim={claimed_root[:16]}..."
                        ),
                    )
                )

            if len(archived_entries) != claimed_count:
                breaks.append(
                    ChainBreak(
                        index=archive_base_index + len(archived_entries),
                        entry_id=entry.entry_id,
                        kind=BreakKind.ARCHIVE_FORMAT_INVALID,
                        detail=(
                            f"archive {archive_path.name} contains "
                            f"{len(archived_entries)} entries but marker claims "
                            f"{claimed_count}"
                        ),
                    )
                )

            # Marker's link check: prev_hmac MUST equal the last archived
            # entry's hmac. This is the live-log → archive bridge.
            marker_logical_index = archive_base_index + len(archived_entries)
            marker_link_break = False
            if entry.prev_hmac != last_archived_hmac:
                breaks.append(
                    ChainBreak(
                        index=marker_logical_index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.LINK_MISMATCH,
                        detail=(
                            f"compaction marker's prev_hmac={entry.prev_hmac[:16]}... "
                            f"does not bridge to last archived entry's "
                            f"hmac={last_archived_hmac[:16]}... in {archive_path.name}"
                        ),
                    )
                )
                marker_link_break = True

            marker_ok = _verify_entry_self(
                index=marker_logical_index,
                entry=entry,
                keyring=keyring,
                breaks=breaks,
                suppress_self_mismatch=marker_link_break,
            )
            if marker_ok:
                last_known_good_index = marker_logical_index
                last_known_good_hmac = entry.hmac

            # Bridge from archive back to live log: the next live entry's
            # prev_hmac must equal the LAST ARCHIVED entry's hmac, NOT the
            # marker's hmac. (Both the marker and the next live entry
            # share the same predecessor -- that's the documented fork.)
            expected_prev = last_archived_hmac
            total_entries += len(archived_entries) + 1  # +1 for the marker
            logical_index = marker_logical_index + 1
    except MalformedAuditEntry as exc:
        # A3 (archive walker): a malformed JSONL line in the live log
        # surfaces as a structured break, just like the live-only
        # walker. Iteration stops there.
        breaks.append(
            ChainBreak(
                index=logical_index,
                entry_id="",
                kind=BreakKind.MALFORMED_LINE,
                detail=(f"line {exc.line_number}: cannot parse as JSON: {exc.parse_error}"),
            )
        )
    finally:
        _flush_cascade()

    return VerificationReport(
        total_entries=total_entries,
        breaks=tuple(breaks),
        last_known_good_index=last_known_good_index,
        last_known_good_hmac=last_known_good_hmac,
    )


@dataclass(frozen=True, slots=True)
class ContiguityGap:
    """A run of missing sequence numbers between two present entries."""

    after_index: int
    """Chain index of the entry immediately BEFORE the gap."""

    missing_from: int
    """First missing sequence number (inclusive)."""

    missing_to: int
    """Last missing sequence number (inclusive)."""

    @property
    def count(self) -> int:
        """How many sequence numbers are missing in this gap."""
        return self.missing_to - self.missing_from + 1


@dataclass(frozen=True, slots=True)
class ContiguityReport:
    """Completeness report from :func:`verify_contiguity`.

    The HMAC chain proves no entry you HOLD was altered, inserted, or
    reordered. It cannot prove an entry was never written, or that the
    tail was truncated -- a shorter intact chain still verifies. The
    per-chain monotonic sequence number (:data:`signet.audit.chain.
    SEQ_FIELD`, written when the chain is constructed with
    ``sequence=True``) closes that gap: a hole in the numbering is an
    entry that is provably missing from an otherwise-intact run.

    Trust note: the sequence numbers are only as trustworthy as the
    chain itself. A sequence value lives inside the signed payload, so
    forging one breaks the entry's HMAC -- but that protection only
    holds if you ALSO run :class:`ChainVerifier`. Always pair a
    contiguity check with an HMAC verify (the ``signet audit
    verify-contiguity`` CLI does both).

    Attributes:
        total_entries: Every entry walked.
        numbered_entries: Entries carrying a valid integer sequence.
        first_seq / last_seq: Lowest/highest sequence observed, or
            ``None`` when the chain carries no sequence numbers.
        gaps: Missing-number runs, in chain order.
        duplicates: Sequence values that appeared more than once.
        out_of_order_indices: Chain indices where the sequence did not
            strictly increase relative to the previous numbered entry.
        unnumbered_indices: Indices of entries lacking a valid sequence.
            Empty on a fully-sequenced chain; a non-empty list on a
            chain that ALSO has numbered entries indicates a dropped
            marker (tamper). A chain with NO numbered entries was simply
            written without ``sequence=True`` -- see :attr:`sequenced`.
        expected_start / expected_end: Operator-declared boundary, if
            supplied. Lets a caller who knows the true endpoints
            out-of-band (e.g. from an externally anchored receipt)
            detect head/tail truncation the chain alone cannot.
        boundary_breaks: Human-readable mismatches against the declared
            boundary.
    """

    total_entries: int
    numbered_entries: int
    first_seq: int | None = None
    last_seq: int | None = None
    gaps: tuple[ContiguityGap, ...] = field(default_factory=tuple)
    duplicates: tuple[int, ...] = field(default_factory=tuple)
    out_of_order_indices: tuple[int, ...] = field(default_factory=tuple)
    unnumbered_indices: tuple[int, ...] = field(default_factory=tuple)
    expected_start: int | None = None
    expected_end: int | None = None
    boundary_breaks: tuple[str, ...] = field(default_factory=tuple)
    signet_version: str = _SIGNET_VERSION
    verified_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def sequenced(self) -> bool:
        """``True`` if the chain carries any sequence numbers at all.

        ``False`` means the chain was written without ``sequence=True``;
        a contiguity check is not applicable and :attr:`ok` is ``False``
        so callers don't mistake "not sequenced" for "verified
        complete".
        """
        return self.numbered_entries > 0

    @property
    def ok(self) -> bool:
        """``True`` only when the chain is sequenced and provably
        gap-free: no missing runs, no duplicates, no out-of-order
        entries, no entries missing a number, and no declared-boundary
        mismatch."""
        return (
            self.sequenced
            and not self.gaps
            and not self.duplicates
            and not self.out_of_order_indices
            and not self.unnumbered_indices
            and not self.boundary_breaks
        )


def verify_contiguity(
    backend: AuditBackend,
    *,
    expected_start: int | None = None,
    expected_end: int | None = None,
) -> ContiguityReport:
    """Check the monotonic-sequence completeness of a chain.

    Reads each entry's sequence number (see :class:`ContiguityReport`)
    and reports gaps, duplicates, out-of-order numbering, and entries
    that are unexpectedly unnumbered. Optionally asserts the chain spans
    a known ``[expected_start, expected_end]`` range so a caller who
    knows the true endpoints out-of-band can catch head/tail truncation.

    This function does NOT verify HMACs -- run :class:`ChainVerifier`
    alongside it, because an unverified sequence number is just an
    attacker-supplied integer. The ``signet audit verify-contiguity``
    CLI command pairs the two.
    """
    from signet.audit.chain import _entry_seq

    total = 0
    numbered: list[tuple[int, int]] = []  # (chain_index, seq)
    unnumbered: list[int] = []
    for index, entry in enumerate(backend.iter_entries()):
        total = index + 1
        seq = _entry_seq(entry)
        if seq is None:
            unnumbered.append(index)
        else:
            numbered.append((index, seq))

    gaps: list[ContiguityGap] = []
    duplicates: list[int] = []
    out_of_order: list[int] = []
    seen: set[int] = set()
    prev_seq: int | None = None
    prev_index = -1
    for index, seq in numbered:
        if seq in seen:
            duplicates.append(seq)
        seen.add(seq)
        if prev_seq is not None:
            if seq <= prev_seq:
                out_of_order.append(index)
            elif seq > prev_seq + 1:
                gaps.append(
                    ContiguityGap(
                        after_index=prev_index,
                        missing_from=prev_seq + 1,
                        missing_to=seq - 1,
                    )
                )
        prev_seq = seq
        prev_index = index

    first_seq = numbered[0][1] if numbered else None
    last_seq = numbered[-1][1] if numbered else None

    boundary_breaks: list[str] = []
    if expected_start is not None and first_seq is not None and first_seq != expected_start:
        boundary_breaks.append(
            f"expected chain to start at seq {expected_start} but first numbered "
            f"entry is seq {first_seq} "
            f"({'head truncated' if first_seq > expected_start else 'unexpected earlier entries'})"
        )
    if expected_end is not None and last_seq is not None and last_seq != expected_end:
        boundary_breaks.append(
            f"expected chain to end at seq {expected_end} but last numbered "
            f"entry is seq {last_seq} "
            f"({'tail truncated' if last_seq < expected_end else 'unexpected later entries'})"
        )
    # A declared boundary on a chain with no numbers at all is itself a
    # finding -- the operator expected sequencing that isn't there.
    if (expected_start is not None or expected_end is not None) and not numbered:
        boundary_breaks.append("a boundary was declared but the chain carries no sequence numbers")

    return ContiguityReport(
        total_entries=total,
        numbered_entries=len(numbered),
        first_seq=first_seq,
        last_seq=last_seq,
        gaps=tuple(gaps),
        duplicates=tuple(duplicates),
        out_of_order_indices=tuple(out_of_order),
        unnumbered_indices=tuple(unnumbered),
        expected_start=expected_start,
        expected_end=expected_end,
        boundary_breaks=tuple(boundary_breaks),
    )


__all__ = [
    "BreakKind",
    "ChainBreak",
    "ChainVerifier",
    "ContiguityGap",
    "ContiguityReport",
    "VerificationReport",
    "verify_contiguity",
    "verify_with_archives",
]
