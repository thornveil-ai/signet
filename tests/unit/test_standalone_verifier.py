"""Tests for the standalone, zero-install verifier (tools/verify_standalone.py).

Two jobs:

1. **Anti-drift parity:** the standalone canonicalization must produce
   bytes identical to the in-tree ``_serialize_for_signing`` for a
   battery of entries (legacy and JCS). If the in-tree serializer
   changes without mirroring it here, this test fails.
2. **Behavior:** the standalone ``verify_chain`` accepts an intact chain
   and rejects tampering / gaps, exactly like the real verifier -- with
   no ``import signet``.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain, _serialize_for_signing
from signet.audit.keyring import Key, KeyRing
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner

_ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "verify_standalone", _ROOT / "tools" / "verify_standalone.py"
)
assert _SPEC is not None and _SPEC.loader is not None
standalone = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(standalone)


def _entry(reason: str = "test", **meta: object) -> AuditEntry:
    return AuditEntry(
        owner=Owner.human("alice@example.com"),
        check_name="owner_resolution",
        decision=Decision.ALLOW,
        reason=reason,
        metadata=dict(meta),
    )


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing(active=Key(key_id="k1", secret=bytes(range(32))))


SECRET_HEX = bytes(range(32)).hex()


class TestParity:
    @pytest.mark.parametrize(
        "entry",
        [
            _entry("plain"),
            _entry("unicode: café—naïve—日本語"),
            _entry("nested", extra={"a": 1, "b": [1, 2, 3], "c": {"d": "e"}}),
            _entry('with quotes " and \\ backslash'),
        ],
    )
    def test_legacy_bytes_match_in_tree(self, entry: AuditEntry, keyring: KeyRing) -> None:
        in_tree = _serialize_for_signing(entry)
        external = standalone.serialize_for_signing(entry.to_dict())
        assert in_tree == external

    def test_jcs_bytes_match_in_tree(self, tmp_path: Path, keyring: KeyRing) -> None:
        pytest.importorskip("rfc8785")
        log = tmp_path / "a.jsonl"
        e = HmacChain(backend=JsonlBackend(log), keyring=keyring, canon="jcs").append(_entry("jcs"))
        assert _serialize_for_signing(e) == standalone.serialize_for_signing(e.to_dict())


class TestStandaloneChainVerify:
    def _write(self, log: Path, keyring: KeyRing, *, n: int = 5, **chain_kw: object) -> None:
        chain = HmacChain(backend=JsonlBackend(log), keyring=keyring, **chain_kw)
        for i in range(n):
            chain.append(_entry(f"r{i}"))

    def test_intact_chain_verifies(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        self._write(log, keyring, sequence=True)
        result = standalone.verify_chain(str(log), SECRET_HEX, "k1")
        assert result["ok"]
        assert result["total_entries"] == 5
        assert (result["first_seq"], result["last_seq"]) == (0, 4)

    def test_wrong_secret_fails(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        self._write(log, keyring)
        result = standalone.verify_chain(str(log), ("11" * 32), "k1")
        assert not result["ok"]
        assert result["integrity_breaks"]

    def test_tamper_detected(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        self._write(log, keyring)
        lines = log.read_text().splitlines()
        d = json.loads(lines[2])
        d["reason"] = "tampered"
        lines[2] = json.dumps(d)
        log.write_text("\n".join(lines) + "\n")
        result = standalone.verify_chain(str(log), SECRET_HEX, "k1")
        assert not result["ok"]

    def test_sequence_gap_detected(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        self._write(log, keyring, sequence=True)
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:2] + lines[3:]) + "\n")  # drop seq 2
        result = standalone.verify_chain(str(log), SECRET_HEX, "k1")
        assert not result["ok"]
        assert any("missing sequence" in g for g in result["contiguity_gaps"])

    def test_tail_truncation_caught_by_expect_end(self, tmp_path: Path, keyring: KeyRing) -> None:
        log = tmp_path / "a.jsonl"
        self._write(log, keyring, sequence=True)  # seq 0..4
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:3]) + "\n")  # keep seq 0..2
        # Without a declared boundary the truncated tail still "passes".
        assert standalone.verify_chain(str(log), SECRET_HEX, "k1")["ok"]
        # With the true endpoint declared, truncation is caught.
        bounded = standalone.verify_chain(str(log), SECRET_HEX, "k1", expected_end=4)
        assert not bounded["ok"]
        assert any("tail truncated" in g for g in bounded["contiguity_gaps"])

    def test_jcs_chain_verifies_standalone(self, tmp_path: Path, keyring: KeyRing) -> None:
        pytest.importorskip("rfc8785")
        log = tmp_path / "a.jsonl"
        self._write(log, keyring, canon="jcs", sequence=True)
        result = standalone.verify_chain(str(log), SECRET_HEX, "k1")
        assert result["ok"]


class TestStandaloneReceiptVerify:
    def test_ed25519_receipt(self, tmp_path: Path, keyring: KeyRing) -> None:
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives import serialization

        from signet.server.receipt import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.generate("ed-1")
        entry = _entry("receipt-me")
        header = signer.sign(entry)
        pub = tmp_path / "pub.pem"
        pub.write_bytes(
            signer._public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        import argparse

        args = argparse.Namespace(
            entry=json.dumps(entry.to_dict()),
            header=header,
            alg="ed25519",
            key_id="ed-1",
            secret=None,
            pub_pem=str(pub),
            pub_raw=None,
        )
        assert standalone.verify_receipt(args) is True
        # Wrong entry must fail.
        args.entry = json.dumps(_entry("other").to_dict())
        assert standalone.verify_receipt(args) is False
