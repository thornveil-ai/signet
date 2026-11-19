"""Tests for asymmetric Ed25519 audit chains and O(delta) checkpointed verification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from signet.audit import (
    ALG_ED25519,
    ALG_FIELD,
    BreakKind,
    ChainCheckpoint,
    ChainVerifier,
    Ed25519Key,
    HmacChain,
    Key,
    KeyRing,
)
from signet.audit.backend import JsonlBackend
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


class _MemoryBackend:
    """Minimal in-memory AuditBackend for testing generic incremental verification."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(self, entry: AuditEntry) -> None:
        self._entries.append(entry)

    def iter_entries(self):
        return iter(self._entries)

    def last_entry(self) -> AuditEntry | None:
        return self._entries[-1] if self._entries else None


def _make_entry(label: str) -> AuditEntry:
    return AuditEntry(
        owner=Owner.policy("auditor@thornveil.ai"),
        check_name="capability_gate",
        decision=Decision.ALLOW,
        reason=f"authorized {label}",
        metadata={"label": label},
    )


def test_ed25519_chain_sign_and_public_key_verify(tmp_path: Path) -> None:
    """Private ring signs; stripped public-only ring verifies offline without signing rights."""
    ed_key = Ed25519Key.generate("ed-k1")
    assert ed_key.can_sign is True
    assert "redacted" in repr(ed_key)
    assert ed_key.private_bytes is not None
    assert ed_key.private_bytes.hex() not in repr(ed_key)

    signing_ring = KeyRing(active=ed_key)
    backend = JsonlBackend(tmp_path / "ed25519.jsonl", fsync_after_append=False)
    chain = HmacChain(backend, signing_ring, sequence=True)

    e0 = chain.append(_make_entry("first"))
    e1 = chain.append(_make_entry("second"))
    e2 = chain.append(_make_entry("third"))

    assert e0.metadata[ALG_FIELD] == ALG_ED25519
    assert len(e0.hmac) == 128  # 64-byte Ed25519 signature hex-encoded
    assert e1.prev_hmac == e0.hmac
    assert e2.prev_hmac == e1.hmac

    # External auditor holds ONLY public_ring()
    public_ring = signing_ring.public_ring()
    assert public_ring.active.can_sign is False

    report = ChainVerifier(backend, public_ring).verify()
    assert report.ok is True
    assert report.total_entries == 3
    assert report.last_known_good_index == 2
    assert report.last_known_good_hmac == e2.hmac

    # Public-only ring MUST NOT be able to append/forge new entries
    forged_chain = HmacChain(backend, public_ring)
    with pytest.raises(ValueError, match="verify-only"):
        forged_chain.append(_make_entry("forged"))


def test_ed25519_mixed_era_rotation_from_hmac_and_tamper_detection(tmp_path: Path) -> None:
    """Rotating seamlessly from legacy HMAC Key -> Ed25519Key keeps full chain verifiable."""
    hmac_key = Key.generate("hmac-k1")
    ed_key = Ed25519Key.generate("ed-k2")
    ring = KeyRing(active=hmac_key)
    log_path = tmp_path / "mixed.jsonl"
    backend = JsonlBackend(log_path, fsync_after_append=False)
    chain = HmacChain(backend, ring, sequence=True)

    e0 = chain.append(_make_entry("era-hmac"))
    assert ALG_FIELD not in e0.metadata  # legacy HMAC entries remain byte-compatible

    ring.rotate(ed_key)
    e1 = chain.append(_make_entry("era-ed25519"))
    assert e1.metadata[ALG_FIELD] == ALG_ED25519
    assert e1.prev_hmac == e0.hmac

    # Mixed ring cannot export a public_ring (refuses to leak symmetric HMAC secret)
    with pytest.raises(ValueError, match="symmetric"):
        ring.public_ring()

    # Full chain verifies across both eras
    report = ChainVerifier(backend, ring).verify()
    assert report.ok is True
    assert report.total_entries == 2

    # Tampering with Ed25519 payload breaks SELF_MISMATCH
    raw_lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(raw_lines[1])
    tampered["reason"] = "tampered reason"
    raw_lines[1] = json.dumps(tampered, separators=(",", ":"), sort_keys=True)
    log_path.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")

    bad_report = ChainVerifier(backend, ring).verify()
    assert bad_report.ok is False
    assert any(b.kind == BreakKind.SELF_MISMATCH and b.index == 1 for b in bad_report.breaks)


def test_ed25519_algorithm_confusion_rejected(tmp_path: Path) -> None:
    """Flipping _signing_alg to an invalid or mismatched value fails verification."""
    ed_key = Ed25519Key.generate("ed-k1")
    ring = KeyRing(active=ed_key)
    log_path = tmp_path / "alg.jsonl"
    backend = JsonlBackend(log_path, fsync_after_append=False)
    chain = HmacChain(backend, ring)
    chain.append(_make_entry("one"))

    # Claim hmac-sha256 on an entry signed by an ed25519 key -> SELF_MISMATCH
    row = json.loads(log_path.read_text(encoding="utf-8").strip())
    row["metadata"][ALG_FIELD] = "hmac-sha256"
    log_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    r_mismatch = ChainVerifier(backend, ring).verify()
    assert not r_mismatch.ok
    assert r_mismatch.breaks[0].kind == BreakKind.SELF_MISMATCH

    # Claim unknown alg -> MALFORMED_LINE
    row["metadata"][ALG_FIELD] = "rsa-none"
    log_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    r_unknown = ChainVerifier(backend, ring).verify()
    assert not r_unknown.ok
    assert r_unknown.breaks[0].kind == BreakKind.MALFORMED_LINE


def test_ed25519_from_raw_bytes_roundtrip() -> None:
    """Private and public raw 32-byte constructors interoperate cleanly."""
    k = Ed25519Key.generate("ed-raw")
    assert k.private_bytes is not None
    rebuilt_priv = Ed25519Key.from_private_bytes("ed-raw", k.private_bytes)
    rebuilt_pub = Ed25519Key.from_public_bytes("ed-raw", k.public_bytes)
    payload = b"signet-ed25519-test"
    sig = rebuilt_priv.sign(payload)
    assert rebuilt_pub.verify(payload, sig) is True
    assert rebuilt_pub.verify(b"other", sig) is False


def test_verify_incremental_jsonl_and_truncation_detection(tmp_path: Path) -> None:
    """Checkpointed incremental verification seeks O(delta) and catches tail tamper & truncation."""
    ring = KeyRing(active=Ed25519Key.generate("ed-inc"))
    log_path = tmp_path / "inc.jsonl"
    backend = JsonlBackend(log_path, fsync_after_append=False)
    chain = HmacChain(backend, ring, sequence=True)

    for i in range(5):
        chain.append(_make_entry(f"batch1-{i}"))

    verifier = ChainVerifier(backend, ring.public_ring())
    rep1, ckpt1 = verifier.verify_incremental(None)
    assert rep1.ok is True
    assert rep1.total_entries == 5
    assert ckpt1 is not None
    assert ckpt1.last_verified_index == 4
    assert ckpt1.last_verified_seq == 4
    assert ckpt1.file_offset == backend.file_size()

    # JSON checkpoint round-trip
    ckpt1_rt = ChainCheckpoint.from_dict(json.loads(json.dumps(ckpt1.to_dict())))
    assert ckpt1_rt == ckpt1

    # Append 3 more entries and verify only the tail from file_offset
    for i in range(3):
        chain.append(_make_entry(f"batch2-{i}"))

    rep2, ckpt2 = verifier.verify_incremental(ckpt1_rt)
    assert rep2.ok is True
    assert rep2.total_entries == 8
    assert ckpt2 is not None
    assert ckpt2.last_verified_index == 7
    assert ckpt2.last_verified_seq == 7
    assert ckpt2.file_offset == backend.file_size()

    # No-op check when nothing appended stays clean
    rep3, ckpt3 = verifier.verify_incremental(ckpt2)
    assert rep3.ok is True
    assert rep3.total_entries == 8
    assert ckpt3 is not None and ckpt3.last_verified_index == 7

    # Truncating the log below checkpoint offset is caught immediately
    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    rep_trunc, ckpt_trunc = verifier.verify_incremental(ckpt2)
    assert rep_trunc.ok is False
    assert ckpt_trunc is None
    assert rep_trunc.breaks[0].kind == BreakKind.LINK_MISMATCH
    assert "truncated" in rep_trunc.breaks[0].detail


def test_verify_incremental_in_memory_backend() -> None:
    """Generic non-JSONL backend incremental verification checks anchor entry and tail."""
    ring = KeyRing(active=Key.generate("mem-k1"))
    backend = _MemoryBackend()
    chain = HmacChain(backend, ring, sequence=True)
    for i in range(4):
        chain.append(_make_entry(f"m1-{i}"))

    verifier = ChainVerifier(backend, ring)
    rep1, ckpt1 = verifier.verify_incremental(None)
    assert rep1.ok and ckpt1 is not None
    assert ckpt1.file_offset is None
    assert ckpt1.last_verified_index == 3

    for i in range(2):
        chain.append(_make_entry(f"m2-{i}"))

    rep2, ckpt2 = verifier.verify_incremental(ckpt1)
    assert rep2.ok and ckpt2 is not None
    assert rep2.total_entries == 6
    assert ckpt2.last_verified_index == 5
    assert ckpt2.last_verified_seq == 5
