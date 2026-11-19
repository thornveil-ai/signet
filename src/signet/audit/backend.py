"""Storage backends for the HMAC audit chain.

A backend is a thin protocol: append a serialized entry, iterate previous
entries in order. The default :class:`JsonlBackend` writes one JSON object
per line to an append-only file. Custom backends can target databases,
object stores, or remote log aggregators.

The chain logic (HMAC compute, prev-link wiring) lives in
:mod:`signet.audit.chain` and uses these backends through the
:class:`AuditBackend` protocol so the storage choice is orthogonal to the
crypto.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol

from signet.core.audit import AuditEntry


# Module-level platform-specific lock implementations. Selected at
# import time so mypy's sys.platform narrowing keeps the per-platform
# branch type-checked AND reachable on its own platform.
class _LockImpl(Protocol):
    """Cross-process file-lock primitives. Implementations are platform-
    specific and selected at module import time."""

    def acquire(self, fileno: int) -> None: ...
    def release(self, fileno: int) -> None: ...


if sys.platform == "win32":
    import msvcrt

    class _MsvcrtLock:
        """Windows byte-range lock. Some file modes don't permit byte-range
        locks on append-mode files -- single-process safety still holds via
        threading.Lock in HmacChain. Failures are suppressed."""

        def acquire(self, fileno: int) -> None:
            with contextlib.suppress(OSError):
                msvcrt.locking(fileno, msvcrt.LK_LOCK, 1)

        def release(self, fileno: int) -> None:
            with contextlib.suppress(OSError):
                msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)

    _LOCK_IMPL: _LockImpl = _MsvcrtLock()
else:
    import fcntl

    class _FcntlLock:
        """POSIX advisory file lock via fcntl.flock."""

        def acquire(self, fileno: int) -> None:
            fcntl.flock(fileno, fcntl.LOCK_EX)

        def release(self, fileno: int) -> None:
            fcntl.flock(fileno, fcntl.LOCK_UN)

    _LOCK_IMPL = _FcntlLock()


@contextlib.contextmanager
def exclusive_log_lock(path: Path) -> Iterator[None]:
    """Hold a cross-process exclusive lock on a sidecar of ``path``.

    Used by the compactor to block :class:`FileLockingJsonlBackend`
    writers for the duration of an atomic rewrite. We lock a sidecar
    file (``<path>.lock``) rather than the live log itself because on
    Windows holding any handle on the live log would prevent the
    compactor's own ``os.replace`` from succeeding -- and the whole
    point here is that the compactor can rewrite the log atomically
    while concurrent writers either block or get a clean error.

    Lock primitive: ``fcntl.flock`` on POSIX (blocking by default),
    ``msvcrt.locking`` on Windows (retries internally ~10 s, then
    raises ``OSError`` -- the caller turns that into a useful message).

    The :class:`FileLockingJsonlBackend` already takes a byte-range
    lock on the log itself for serialization between worker
    processes; the compactor's sidecar lock is a *coordination* lock
    one rung above. Appenders that observe the sidecar lock cooperate;
    appenders that don't (e.g. the plain :class:`JsonlBackend`) are
    not constrained -- but those backends are not multi-writer safe to
    begin with.
    """
    lock_path = Path(str(path) + ".lock")
    lock_path.touch(exist_ok=True)
    with open(lock_path, "rb+") as f:
        if sys.platform == "win32":
            # ``msvcrt.locking`` with LK_LOCK retries internally for a
            # bit (~10 s) and raises if still locked. We loop a few
            # times to give the appender a fair window before giving up.
            import time as _time

            attempts = 0
            while True:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    attempts += 1
                    if attempts >= 3:
                        raise
                    _time.sleep(0.1)
        else:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if sys.platform == "win32":
                with contextlib.suppress(OSError):
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


# Round 9 LOW: ``--audit-log`` opens previously used ``Path.open("a", ...)``
# unconditionally, which follows symlinks. A local attacker (or a hostile
# CI runner co-tenant) who plants a symlink at the operator's audit-log
# path can redirect every append to a system file. The threat model
# matches the ``signet init`` symlink gap Round 8 closed: loud
# corruption (operator surely notices) but still a foothold worth
# refusing at the file-open boundary.
#
# Defense strategy:
# * On POSIX: prefer ``os.open`` with ``O_NOFOLLOW`` so the kernel
#   refuses the open atomically. The pre-check below also gives the
#   operator a clearer ``ClickException`` message than a bare
#   ``ELOOP`` ``OSError``.
# * On Windows: ``O_NOFOLLOW`` does not exist, so ``Path.is_symlink``
#   (which uses ``GetFileAttributesW`` under the hood and detects
#   reparse points) is the pragmatic guard. There's a narrow TOCTOU
#   window between the check and the open, but the realistic local-
#   tenancy threat (a pre-planted symlink) is closed.
class AuditLogSymlinkError(Exception):
    """Raised when an audit-log path is a symlink.

    Surfaced to the CLI via :func:`_open_audit_log_append` so the
    operator gets a clear "refusing to follow symlink" error instead of
    the audit chain silently re-routing through a planted link.
    """


def _assert_not_symlink(path: Path) -> None:
    """Refuse to operate on an audit-log path that is a symlink.

    ``os.path.islink`` returns True for both reparse points (Windows)
    and POSIX symlinks, AND for dangling symlinks (where
    ``Path.exists`` returns False), so it's the right primitive for
    the pre-check. The atomic ``O_NOFOLLOW`` guard inside
    :func:`_open_audit_log_append` closes the TOCTOU race on POSIX.

    Scope (Round 11 INFO): both ``os.path.islink`` here and POSIX
    ``O_NOFOLLOW`` in :func:`_open_audit_log_append` check the
    **final component** of ``path`` only. Intermediate directory
    components are resolved through symlinks as usual. The defense's
    threat model is "attacker plants a symlink AT the operator's
    audit-log path" (a co-tenant with write access to the leaf), which
    a final-component check fully addresses. A parent-directory
    symlink bypass requires write access to a parent directory, which
    is a strictly higher capability and a different threat -- in that
    case the attacker can simply redirect the audit log by writing the
    parent directory directly, so guarding against parent symlinks
    here would not meaningfully raise the bar. Operators with
    legitimate use cases for symlinked parent directories (containers,
    chroots, build sandboxes) are also unaffected.

    Hardlinks (Round 14 INFO): hardlinks are intentionally NOT
    detected. A hardlink is a legitimate alternate name for the same
    inode -- the file IS what it appears to be, and ``os.stat`` cannot
    distinguish the "primary" name from any other reference. An
    attacker with parent-directory write access can create hardlinks
    to the audit log, but the same parent-directory-write capability
    already allows replacing the audit log entirely, so detecting
    hardlinks here would not raise the attacker's bar. ``st_nlink > 1``
    is also race-prone (a link can be created between check and open)
    and operationally noisy (legitimate snapshot / backup tooling
    relies on hardlinks). This is the same out-of-scope rationale the
    parent-symlink case uses.
    """
    if os.path.islink(path):
        raise AuditLogSymlinkError(f"refusing to follow symlink at audit log path: {path}")


def _open_audit_log_append(path: Path, encoding: str = "utf-8") -> Any:
    """Open ``path`` for appending, refusing to follow symlinks.

    Returns a text-mode file object with the same semantics as
    ``path.open("a", encoding=encoding)``. Raises
    :class:`AuditLogSymlinkError` when ``path`` is a symlink.

    On POSIX this uses ``os.open`` with ``O_NOFOLLOW`` so the kernel
    refuses to follow a final-component symlink atomically (closing
    the TOCTOU race between the pre-check and the open). On Windows
    we rely on the pre-check alone -- ``O_NOFOLLOW`` is not available.

    Scope (Round 11 INFO): the ``O_NOFOLLOW`` flag and the
    :func:`_assert_not_symlink` pre-check both apply to the **final
    path component only**. Per the Linux ``open(2)`` man page,
    ``O_NOFOLLOW`` fails with ``ELOOP`` "if the trailing component
    (i.e., basename) of pathname is a symbolic link"; intermediate
    components are resolved through symlinks normally. See
    :func:`_assert_not_symlink` for the rationale on why this scope
    matches the threat model.
    """
    _assert_not_symlink(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        # ``O_NOFOLLOW`` triggers ELOOP on POSIX when a final-component
        # symlink was planted between the pre-check and ``os.open``.
        # Surface that as the same clear "refusing to follow symlink"
        # error the pre-check produces.
        if nofollow and getattr(exc, "errno", None) == 40:  # ELOOP
            raise AuditLogSymlinkError(
                f"refusing to follow symlink at audit log path: {path}"
            ) from exc
        raise
    return os.fdopen(fd, "a", encoding=encoding)


def _reject_non_finite_json_constants(value: str) -> float:
    """parse_constant callback that rejects ``NaN`` / ``Infinity`` / ``-Infinity``.

    Python's ``json.loads`` accepts these three non-standard JSON
    constants by default and yields Python floats (``float("nan")``,
    ``float("inf")``, ``float("-inf")``). The writer side
    (:meth:`JsonlBackend.append` and friends) uses ``allow_nan=False``
    so signet never *emits* them, but a tampered or malformed audit
    line could carry one and silently slip past the schema validator.

    Downstream consumers convert ``ts_ns`` via
    ``datetime.fromtimestamp(ts_ns / 1e9, ...)`` which raises
    ``OverflowError`` / ``ValueError`` on ``inf`` -- a raw Python
    traceback escaping ``audit verify`` / ``audit tail`` instead of the
    structured ``MalformedAuditEntry`` channel the rest of the
    iter_entries pipeline guarantees.

    Fail-closed at the JSON boundary: any non-finite constant raises
    ``ValueError`` here, which ``iter_entries`` already catches and
    converts to a :class:`MalformedAuditEntry`. F-R4-1 (v0.1.8.2).
    """
    raise ValueError(f"non-finite JSON constant in audit log: {value!r}")


class MalformedAuditEntry(Exception):
    """Raised when a JSONL audit line cannot be parsed.

    Carries the offending line number (1-based), the raw line text, and
    the underlying parse error so the verifier and CLI surfaces can turn
    it into a structured break instead of a Python traceback.

    Mid-write truncation (the realistic post-crash failure mode) and
    accidental edits both surface here. BOM bytes at the start of the
    file are silently stripped by opening with ``utf-8-sig`` so a
    well-meaning text editor saving the log doesn't trip this.
    """

    def __init__(self, line_number: int, raw_line: str, parse_error: str) -> None:
        super().__init__(f"line {line_number}: {parse_error}")
        self.line_number = line_number
        self.raw_line = raw_line
        self.parse_error = parse_error


class AuditBackend(Protocol):
    """The storage protocol every audit backend implements."""

    def append(self, entry: AuditEntry) -> None:
        """Persist an entry. MUST NOT mutate prior entries.

        The caller (the chain writer) is responsible for setting
        ``entry.prev_hmac`` and ``entry.hmac`` before calling this method.
        """
        ...

    def iter_entries(self) -> Iterator[AuditEntry]:
        """Iterate entries in append order, oldest first.

        Used by :class:`signet.audit.chain.ChainVerifier` to walk the
        chain and check link integrity.
        """
        ...

    def last_entry(self) -> AuditEntry | None:
        """Return the most recently appended entry, or ``None`` if the
        backend is empty.

        Optimized lookup; the chain writer needs this on every append to
        compute the new entry's ``prev_hmac``.
        """
        ...


class JsonlBackend:
    """Append-only JSONL file backend.

    Each entry serializes to one JSON object via
    :meth:`AuditEntry.to_dict` and is written followed by a newline.
    Reads stream the file line by line.

    Suitable for: single-host deployments, low-to-medium volume
    (<10K entries/sec), and any setting where a file on disk is the
    audit-of-record. For higher throughput, multiple writers, or
    cloud-native deployments, plug in a custom backend.

    Durability: by default each append calls :func:`os.fsync` after
    writing so a crash between request handling and disk flush still
    leaves the chain consistent. Disable with ``fsync_after_append=False``
    if you need throughput and accept the post-crash audit-tail-loss
    window. There is no rotation, compression, or indexing -- those
    belong in a dedicated backend.
    """

    def __init__(self, path: Path | str, *, fsync_after_append: bool = True) -> None:
        """Open the backend at ``path``.

        Args:
            path: File path. Created if it does not exist; parent
                directory must already exist.
            fsync_after_append: When True (default), :func:`os.fsync`
                is called after every write so a crash cannot leave
                the audit chain shorter than the responses already
                returned to callers. Set False for benchmark or
                ephemeral use; production must keep fsync on.
        """
        self._path = Path(path)
        # Round 9 LOW: refuse to operate on a symlinked audit-log path.
        # ``Path.touch`` would otherwise follow a pre-planted symlink at
        # construction. Mirrors the ``signet init`` symlink guard from
        # Round 8 -- same threat model (local attacker plants a symlink
        # to redirect the audit chain into a system file).
        _assert_not_symlink(self._path)
        self._path.touch(exist_ok=True)
        self._fsync = fsync_after_append

    @property
    def path(self) -> Path:
        """The underlying file path."""
        return self._path

    def append(self, entry: AuditEntry) -> None:
        line = json.dumps(
            entry.to_dict(),
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=False,
        )
        # Round 9 LOW: open with ``O_NOFOLLOW`` (POSIX) or pre-checked
        # ``is_symlink`` (Windows) so a symlink planted after the
        # backend was constructed still refuses to follow.
        with _open_audit_log_append(self._path) as f:
            f.write(line + "\n")
            if self._fsync:
                f.flush()
                os.fsync(f.fileno())

    def iter_entries(self) -> Iterator[AuditEntry]:
        if not self._path.exists():
            return
        # Read in binary mode so a single bad UTF-8 byte inside ONE
        # line doesn't poison the whole iterator with an unrecoverable
        # ``UnicodeDecodeError`` raised mid-read by the text wrapper.
        # We strip an optional leading BOM (the same single byte
        # sequence ``utf-8-sig`` would have removed) and then decode
        # each line independently so the bad line surfaces as a
        # ``MalformedAuditEntry`` with a line number, not a traceback.
        # NF-R2-1 (v0.1.8): every parse-failure mode -- invalid UTF-8,
        # JSON syntax, missing schema field, bad enum value, wrong
        # type -- becomes a structured ``MalformedAuditEntry`` so the
        # verifier and CLI surfaces can turn it into a
        # ``BreakKind.MALFORMED_LINE`` / ``ClickException`` instead of
        # leaking a Python traceback.
        with self._path.open("rb") as f:
            first = f.read(3)
            if first != b"\xef\xbb\xbf":
                f.seek(0)
            for line_number, raw_bytes in enumerate(f, start=1):
                try:
                    stripped = raw_bytes.decode("utf-8").strip()
                except UnicodeDecodeError as exc:
                    raise MalformedAuditEntry(
                        line_number=line_number,
                        raw_line=repr(raw_bytes[:200]),
                        parse_error=f"line is not valid UTF-8: {exc}",
                    ) from exc
                if not stripped:
                    # Blank lines (including a trailing newline) are
                    # tolerated; they're a common artifact of editors
                    # and don't carry an entry.
                    continue
                try:
                    data = json.loads(
                        stripped,
                        parse_constant=_reject_non_finite_json_constants,
                    )
                except json.JSONDecodeError as exc:
                    raise MalformedAuditEntry(
                        line_number=line_number,
                        raw_line=stripped,
                        parse_error=str(exc),
                    ) from exc
                except ValueError as exc:
                    # F-R4-1 (v0.1.8.2): ``parse_constant`` raised on a
                    # ``NaN`` / ``Infinity`` / ``-Infinity`` token. Same
                    # operational meaning as malformed JSON -- the line
                    # cannot be safely consumed -- so route it through
                    # the same structured channel.
                    raise MalformedAuditEntry(
                        line_number=line_number,
                        raw_line=stripped,
                        parse_error=str(exc),
                    ) from exc
                try:
                    yield AuditEntry.from_dict(data)
                except (KeyError, ValueError, TypeError) as exc:
                    # KeyError: required schema field missing
                    # (e.g. ``owner_type``, ``decision``, ``entry_id``).
                    # ValueError: enum coercion failed on a mutated
                    # value (e.g. ``Decision("alloS")``,
                    # ``OwnerType("policn")``).
                    # TypeError: a JSON-typed value (e.g. ``null``)
                    # reached a slot that demands a string. All three
                    # are operationally equivalent to a malformed
                    # line; route them through the same channel.
                    raise MalformedAuditEntry(
                        line_number=line_number,
                        raw_line=stripped,
                        parse_error=(f"schema validation failed: {type(exc).__name__}: {exc}"),
                    ) from exc

    def file_size(self) -> int:
        """Current byte size of the underlying JSONL log (0 if missing)."""
        if not self._path.exists():
            return 0
        return self._path.stat().st_size

    def iter_entries_from_offset(
        self,
        byte_offset: int,
        *,
        start_line: int = 1,
    ) -> Iterator[tuple[AuditEntry, int]]:
        """Yield ``(entry, end_byte_offset)`` starting from ``byte_offset``.

        Used by :meth:`signet.audit.verifier.ChainVerifier.verify_incremental`
        for O(delta) tail verification without re-reading historical entries.
        Raises :class:`ValueError` if ``byte_offset`` is negative or exceeds
        the current file size (which indicates log truncation).
        """
        if byte_offset < 0:
            raise ValueError(f"byte_offset must be >= 0 (got {byte_offset})")
        if not self._path.exists():
            if byte_offset > 0:
                raise ValueError(
                    f"byte_offset {byte_offset} exceeds missing log file size 0"
                )
            return
        size = self._path.stat().st_size
        if byte_offset > size:
            raise ValueError(
                f"byte_offset {byte_offset} exceeds current log file size {size} (log truncated)"
            )
        with self._path.open("rb") as f:
            if byte_offset == 0:
                first = f.read(3)
                if first != b"\xef\xbb\xbf":
                    f.seek(0)
            else:
                f.seek(byte_offset)
            line_number = start_line
            while True:
                raw_bytes = f.readline()
                if not raw_bytes:
                    break
                end_offset = f.tell()
                try:
                    stripped = raw_bytes.decode("utf-8").strip()
                except UnicodeDecodeError as exc:
                    raise MalformedAuditEntry(
                        line_number=line_number,
                        raw_line=repr(raw_bytes[:200]),
                        parse_error=f"line is not valid UTF-8: {exc}",
                    ) from exc
                if not stripped:
                    line_number += 1
                    continue
                try:
                    data = json.loads(
                        stripped,
                        parse_constant=_reject_non_finite_json_constants,
                    )
                except (json.JSONDecodeError, ValueError) as exc:
                    raise MalformedAuditEntry(
                        line_number=line_number,
                        raw_line=stripped,
                        parse_error=str(exc),
                    ) from exc
                try:
                    entry = AuditEntry.from_dict(data)
                except (KeyError, ValueError, TypeError) as exc:
                    raise MalformedAuditEntry(
                        line_number=line_number,
                        raw_line=stripped,
                        parse_error=(f"schema validation failed: {type(exc).__name__}: {exc}"),
                    ) from exc
                yield entry, end_offset
                line_number += 1

    def last_entry(self) -> AuditEntry | None:
        # JSONL doesn't support efficient seek-to-last without indexing.
        # For the volumes JsonlBackend targets, a linear scan is acceptable;
        # callers needing high-throughput chain extension should use a
        # database-backed backend that exposes O(1) tail access.
        last: AuditEntry | None = None
        for entry in self.iter_entries():
            last = entry
        return last


class FileLockingJsonlBackend(JsonlBackend):
    """JsonlBackend with cross-process file locking for multi-worker deployments.

    The base :class:`JsonlBackend` is safe for single-process use only --
    :class:`signet.audit.chain.HmacChain`'s in-process lock prevents
    coroutine-level forks but does nothing across uvicorn workers. This
    subclass acquires an exclusive OS-level lock on the audit file
    around the read-prev + append sequence, so multiple workers can
    safely share one log file.

    Locking primitive: ``fcntl.flock`` on POSIX, ``msvcrt.locking`` on
    Windows. Both are advisory locks -- they only constrain processes
    that themselves call into this backend. External processes that
    write to the audit file directly are not constrained (and should
    not be doing that anyway).

    The chain's :meth:`HmacChain.append` already calls ``last_entry()``
    once per append (cache-hit path), so this backend overrides
    ``append`` to take the lock, re-read the chain head from disk
    (invalidating any stale in-process cache), perform the chain
    update, and release the lock. To make this work cleanly with
    HmacChain's caching, callers using this backend should construct
    their HmacChain with ``cache_prev=False`` (added in v0.1.3).

    Performance: the lock is held only for the duration of one append
    (microseconds for small entries on local SSD). For high-throughput
    multi-worker deployments, consider a database-backed audit
    backend with native concurrency support instead.
    """

    def append_locked(self, entry: AuditEntry, on_locked: Any = None) -> None:
        """Append under an exclusive cross-process lock.

        ``on_locked`` is an optional zero-arg callable invoked AFTER the
        lock is acquired but BEFORE ``append`` runs. Used by
        :class:`HmacChain` to re-read the chain head under the lock so
        multi-worker prev_hmac stays correct without leaving the
        critical section.

        Coordination with the compactor (A7): we acquire the sidecar
        ``<path>.lock`` lock first (the same lock the compactor holds
        for the duration of an atomic rewrite). If a compaction is in
        progress, this blocks here -- instead of opening the live log
        and racing with the compactor's ``os.replace``. The byte-range
        lock on the log itself is still held during the actual write
        to keep multi-process appenders serialized between
        themselves.
        """
        # Round 9 LOW: O_NOFOLLOW / is_symlink guard around the append-mode
        # open, same as :meth:`JsonlBackend.append`.
        with (
            exclusive_log_lock(self._path),
            _open_audit_log_append(self._path) as f,
        ):
            _LOCK_IMPL.acquire(f.fileno())
            try:
                if on_locked is not None:
                    on_locked()
                line = json.dumps(
                    entry.to_dict(),
                    separators=(",", ":"),
                    sort_keys=True,
                    allow_nan=False,
                    ensure_ascii=False,
                )
                f.write(line + "\n")
                if self._fsync:
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                _LOCK_IMPL.release(f.fileno())

    def append_locked_with_link(
        self,
        link_fn: Callable[[str], AuditEntry],
    ) -> AuditEntry:
        """Read chain tail, build linked entry, write -- all under one lock.

        V2 (v0.1.7 follow-up): previously :class:`HmacChain.append` read
        the previous HMAC OUTSIDE the cross-process file lock, then
        called :meth:`append` to take the lock and write. Two appenders
        in separate processes could both read the same ``prev_hmac``
        before either landed its write, forking the chain. The window
        was narrow on Linux but routinely tripped on Windows where the
        compactor's ``os.replace`` raced with the appender's open.

        This method gives :class:`HmacChain` an atomic read-modify-write:

        1. Acquire the sidecar coordination lock (blocks while the
           compactor is rewriting) and the byte-range lock on the live
           log file.
        2. Call :meth:`_read_tail_hmac` to read the last entry's HMAC
           from disk -- guaranteed not to race with sibling writers
           because they're blocked on the same lock.
        3. Invoke ``link_fn(prev_hmac)``. The callable signs the entry
           with the freshly-read ``prev_hmac`` and returns the linked
           :class:`AuditEntry` ready for persistence.
        4. Write the entry under the same lock.

        Returns the linked entry produced by ``link_fn`` so callers can
        propagate the chain HMACs without a second read.

        File-handle layering: the sidecar coordination lock (held for
        the entire critical section) blocks the compactor and any
        sibling :meth:`append_locked_with_link` callers. The tail read
        happens BEFORE the append-mode handle is opened so Windows
        doesn't refuse the concurrent read+append on the same file
        (msvcrt locks are per-handle and an open append handle blocks
        a read on the same path). The byte-range lock on the
        append-mode handle then serializes us against
        :meth:`append_locked` callers that don't hold the sidecar
        lock.
        """
        with exclusive_log_lock(self._path):
            prev_hmac = self._read_tail_hmac()
            linked = link_fn(prev_hmac)
            # Round 9 LOW: O_NOFOLLOW / is_symlink guard.
            with _open_audit_log_append(self._path) as f:
                _LOCK_IMPL.acquire(f.fileno())
                try:
                    line = json.dumps(
                        linked.to_dict(),
                        separators=(",", ":"),
                        sort_keys=True,
                        allow_nan=False,
                        ensure_ascii=False,
                    )
                    f.write(line + "\n")
                    if self._fsync:
                        f.flush()
                        os.fsync(f.fileno())
                    return linked
                finally:
                    _LOCK_IMPL.release(f.fileno())

    def _read_tail_hmac(self) -> str:
        """Return the HMAC the next append must link to, or ``""`` if empty.

        Intended for use only inside the cross-process lock of
        :meth:`append_locked_with_link`. Performs a linear scan via
        :meth:`iter_entries`; for the volumes this backend targets
        (single-host, low-to-medium throughput) the cost is acceptable.
        High-throughput multi-writer deployments should plug in a
        database-backed backend with O(1) tail access.

        Round 11 HIGH-1: marker-aware tail read. When the on-disk tail
        is a compaction marker (full-sweep result: the live log contains
        only the marker), the next live append must link to the LAST
        ARCHIVED entry's hmac -- the bridge value -- not to the marker's
        hmac. That bridge value is exactly ``last.prev_hmac`` because
        the compactor set ``marker.prev_hmac = eligible[-1].hmac`` and
        signed it into the marker's chain HMAC. The marker payload is
        on-disk, so this works for the multi-process / ``cache_prev=False``
        path that bypasses the in-memory cache-seed in
        :func:`compact_audit_log`.
        """
        last: AuditEntry | None = None
        for entry in self.iter_entries():
            last = entry
        if last is None:
            return ""
        # Lazy import: backend → compactor would otherwise cycle through
        # ``compactor`` importing ``JsonlBackend`` at module load.
        from signet.audit.compactor import _has_marker_shape

        if _has_marker_shape(last):
            return last.prev_hmac
        return last.hmac

    def append(self, entry: AuditEntry) -> None:
        """Single-writer append under cross-process lock.

        Multi-process safe: only one worker holds the lock at a time.
        For chain-aware appends that need to re-read prev_hmac under
        the lock, use :meth:`append_locked` or
        :meth:`append_locked_with_link`.
        """
        self.append_locked(entry)
