"""Tests for versioned canonicalization (legacy + RFC 8785 JCS).

Two invariants matter:

1. **Backward compatibility:** a chain written without ``canon=`` is
   byte-identical to pre-v0.1.11 output (no ``_canon`` marker, legacy
   compact-JSON serialization).
2. **JCS opt-in works end-to-end:** a ``canon="jcs"`` chain stamps the
   marker, signs via RFC 8785, and verifies; tampering still breaks it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from signet.audit.backend import JsonlBackend
from signet.audit.chain import (
    CANON_FIELD,
    CANON_JCS_V1,
    HmacChain,
    _ijson_safe,
    _serialize_for_signing,
)
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import ChainVerifier
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner

rfc8785 = pytest.importorskip("rfc8785")


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


class TestLegacyUnchanged:
    def test_legacy_chain_has_no_canon_marker(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        e = HmacChain(backend=JsonlBackend(log), keyring=keyring).append(_entry())
        assert CANON_FIELD not in e.metadata

    def test_legacy_serialization_is_compact_json(self, keyring: KeyRing) -> None:
        # A free-standing entry with no _canon marker must serialize via
        # the exact legacy json.dumps form.
        e = _entry("legacy")
        d = e.to_dict()
        d.pop("hmac", None)
        expected = json.dumps(
            d, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False
        ).encode("utf-8")
        assert _serialize_for_signing(e) == expected


class TestJcsChain:
    def test_jcs_chain_stamps_marker_and_verifies(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        chain = HmacChain(backend=JsonlBackend(log), keyring=keyring, canon="jcs")
        e = chain.append(_entry("jcs"))
        assert e.metadata[CANON_FIELD] == CANON_JCS_V1
        assert ChainVerifier(JsonlBackend(log), keyring).verify().ok

    def test_jcs_bytes_differ_from_legacy(self, tmp_path: Path, keyring: KeyRing) -> None:
        legacy_log = tmp_path / "legacy.jsonl"
        jcs_log = tmp_path / "jcs.jsonl"
        legacy = HmacChain(backend=JsonlBackend(legacy_log), keyring=keyring).append(_entry("x"))
        jcs = HmacChain(backend=JsonlBackend(jcs_log), keyring=keyring, canon="jcs").append(
            _entry("x")
        )
        assert _serialize_for_signing(legacy) != _serialize_for_signing(jcs)

    def test_jcs_uses_rfc8785(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        e = HmacChain(backend=JsonlBackend(log), keyring=keyring, canon="jcs").append(_entry("x"))
        d = e.to_dict()
        d.pop("hmac", None)
        assert _serialize_for_signing(e) == rfc8785.dumps(_ijson_safe(d))

    def test_jcs_tamper_breaks_chain(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        chain = HmacChain(backend=JsonlBackend(log), keyring=keyring, canon="jcs")
        for i in range(3):
            chain.append(_entry(f"r{i}"))
        lines = log.read_text().splitlines()
        d = json.loads(lines[1])
        d["reason"] = "tampered"
        lines[1] = json.dumps(d)
        log.write_text("\n".join(lines) + "\n")
        assert not ChainVerifier(JsonlBackend(log), keyring).verify().ok

    def test_stripping_canon_marker_breaks_chain(self, tmp_path: Path, keyring: KeyRing) -> None:
        # Flipping a jcs entry back to legacy changes the serialization
        # and must surface as an integrity break.
        log = tmp_path / "a.jsonl"
        HmacChain(backend=JsonlBackend(log), keyring=keyring, canon="jcs").append(_entry("x"))
        lines = log.read_text().splitlines()
        d = json.loads(lines[0])
        d["metadata"].pop(CANON_FIELD)
        lines[0] = json.dumps(d)
        log.write_text("\n".join(lines) + "\n")
        assert not ChainVerifier(JsonlBackend(log), keyring).verify().ok


class TestIjsonSafe:
    def test_large_int_becomes_string(self) -> None:
        assert _ijson_safe(2**60) == str(2**60)

    def test_small_int_stays_int(self) -> None:
        assert _ijson_safe(42) == 42

    def test_bool_is_preserved(self) -> None:
        assert _ijson_safe(True) is True

    def test_nested_structures(self) -> None:
        out = _ijson_safe({"a": [1, 2**60], "b": {"c": 2**55}})
        assert out == {"a": [1, str(2**60)], "b": {"c": str(2**55)}}


class TestUnknownCanonInvalid:
    def test_bad_canon_constructor_rejected(self, tmp_path: Path, keyring: KeyRing) -> None:
        with pytest.raises(ValueError, match="unknown canon"):
            HmacChain(backend=JsonlBackend(tmp_path / "a.jsonl"), keyring=keyring, canon="cbor")

    def test_unknown_canon_marker_is_malformed_not_crash(
        self, tmp_path: Path, keyring: KeyRing
    ) -> None:
        from signet.audit.verifier import BreakKind

        log = tmp_path / "a.jsonl"
        HmacChain(backend=JsonlBackend(log), keyring=keyring, canon="jcs").append(_entry("x"))
        lines = log.read_text().splitlines()
        d = json.loads(lines[0])
        d["metadata"][CANON_FIELD] = "cbor/v9"
        lines[0] = json.dumps(d)
        log.write_text("\n".join(lines) + "\n")
        report = ChainVerifier(JsonlBackend(log), keyring).verify()
        assert not report.ok
        assert any(b.kind == BreakKind.MALFORMED_LINE for b in report.breaks)
