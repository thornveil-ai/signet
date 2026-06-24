"""Tests for monotonic sequence numbering + contiguity verification.

The HMAC chain detects modification/insertion/deletion/reorder of entries
you HOLD. Sequence numbers add completeness: a gap proves an entry is
missing from an otherwise-intact run, and a declared boundary catches
tail truncation the chain alone cannot show.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from signet.audit.backend import JsonlBackend
from signet.audit.chain import SEQ_FIELD, HmacChain, _entry_seq
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import ChainVerifier, verify_contiguity
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


def _entry(reason: str = "test") -> AuditEntry:
    return AuditEntry(
        owner=Owner.human("alice@example.com"),
        check_name="owner_resolution",
        decision=Decision.ALLOW,
        reason=reason,
    )


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing(active=Key.generate("k1"))


def _seq_chain(path: Path, keyring: KeyRing) -> HmacChain:
    return HmacChain(backend=JsonlBackend(path), keyring=keyring, sequence=True)


class TestSequenceWriter:
    def test_seq_starts_at_zero_and_increments(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        entries = [chain.append(_entry(f"r{i}")) for i in range(5)]
        assert [_entry_seq(e) for e in entries] == [0, 1, 2, 3, 4]

    def test_seq_survives_reopen(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        _seq_chain(log, keyring).append(_entry("0"))
        _seq_chain(log, keyring).append(_entry("1"))
        # Re-open a third time and the next number must continue from the tail.
        third = _seq_chain(log, keyring).append(_entry("2"))
        assert _entry_seq(third) == 2

    def test_sequence_off_by_default(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        e = HmacChain(backend=JsonlBackend(log), keyring=keyring).append(_entry())
        assert SEQ_FIELD not in e.metadata


class TestContiguityClean:
    def test_clean_sequenced_chain_is_ok(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        for i in range(6):
            chain.append(_entry(f"r{i}"))
        report = verify_contiguity(JsonlBackend(log))
        assert report.ok
        assert report.sequenced
        assert (report.first_seq, report.last_seq) == (0, 5)
        assert report.numbered_entries == 6

    def test_unsequenced_chain_is_not_ok_but_not_a_tamper(
        self, tmp_path: Path, keyring: KeyRing
    ) -> None:
        log = tmp_path / "a.jsonl"
        chain = HmacChain(backend=JsonlBackend(log), keyring=keyring)
        chain.append(_entry("x"))
        report = verify_contiguity(JsonlBackend(log))
        assert not report.sequenced
        assert not report.ok
        assert report.numbered_entries == 0


class TestContiguityDetection:
    def test_interior_drop_creates_gap(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        for i in range(5):
            chain.append(_entry(f"r{i}"))
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:2] + lines[3:]) + "\n")  # drop seq 2

        contig = verify_contiguity(JsonlBackend(log))
        assert not contig.ok
        assert [(g.missing_from, g.missing_to) for g in contig.gaps] == [(2, 2)]
        # The HMAC chain ALSO catches an interior drop (link break).
        assert not ChainVerifier(JsonlBackend(log), keyring).verify().ok

    def test_tail_truncation_needs_declared_boundary(
        self, tmp_path: Path, keyring: KeyRing
    ) -> None:
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        for i in range(5):
            chain.append(_entry(f"r{i}"))
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:3]) + "\n")  # drop seq 3 and 4 from the tail

        # A truncated tail still links cleanly AND has no interior gap...
        assert ChainVerifier(JsonlBackend(log), keyring).verify().ok
        assert verify_contiguity(JsonlBackend(log)).ok
        # ...until the operator declares the true endpoint out-of-band.
        bounded = verify_contiguity(JsonlBackend(log), expected_end=4)
        assert not bounded.ok
        assert bounded.boundary_breaks
        assert "tail truncated" in bounded.boundary_breaks[0]

    def test_head_truncation_caught_by_expected_start(
        self, tmp_path: Path, keyring: KeyRing
    ) -> None:
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        for i in range(5):
            chain.append(_entry(f"r{i}"))
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[2:]) + "\n")  # drop seq 0 and 1

        bounded = verify_contiguity(JsonlBackend(log), expected_start=0)
        assert not bounded.ok
        assert "head truncated" in bounded.boundary_breaks[0]

    def test_duplicate_sequence_detected(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        for i in range(3):
            chain.append(_entry(f"r{i}"))
        lines = log.read_text().splitlines()
        log.write_text("\n".join([lines[0], lines[1], lines[1]]) + "\n")  # repeat seq 1

        contig = verify_contiguity(JsonlBackend(log))
        assert not contig.ok
        assert 1 in contig.duplicates

    def test_dropped_seq_field_is_unnumbered(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        for i in range(3):
            chain.append(_entry(f"r{i}"))
        lines = log.read_text().splitlines()
        d = json.loads(lines[1])
        d["metadata"].pop(SEQ_FIELD)
        lines[1] = json.dumps(d)
        log.write_text("\n".join(lines) + "\n")

        contig = verify_contiguity(JsonlBackend(log))
        assert contig.unnumbered_indices == (1,)
        assert not contig.ok


class TestSequenceIsBound:
    def test_forged_seq_breaks_hmac(self, tmp_path: Path, keyring: KeyRing) -> None:
        # _seq lives in the signed payload: editing it must break the
        # entry's own HMAC, so a forged number can't pass an integrity check.
        log = tmp_path / "a.jsonl"
        chain = _seq_chain(log, keyring)
        for i in range(3):
            chain.append(_entry(f"r{i}"))
        lines = log.read_text().splitlines()
        d = json.loads(lines[2])
        d["metadata"][SEQ_FIELD] = 99
        lines[2] = json.dumps(d)
        log.write_text("\n".join(lines) + "\n")

        report = ChainVerifier(JsonlBackend(log), keyring).verify()
        assert not report.ok
