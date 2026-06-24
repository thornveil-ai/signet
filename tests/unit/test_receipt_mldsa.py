"""Tests for the post-quantum ML-DSA-65 receipt signer.

Skips entirely when the optional ``dilithium-py`` backend (signet-sign
[pq]) is not installed.
"""

from __future__ import annotations

import pytest

from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner
from signet.server.receipt import ALG_ML_DSA_65, MLDSAReceiptSigner

pytest.importorskip("dilithium_py")


def _entry(reason: str = "test") -> AuditEntry:
    return AuditEntry(
        owner=Owner.human("alice@example.com"),
        check_name="owner_resolution",
        decision=Decision.ALLOW,
        reason=reason,
    )


class TestRoundTrip:
    def test_sign_and_verify(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        entry = _entry()
        header = signer.sign(entry)
        assert f"alg={ALG_ML_DSA_65}" in header
        assert signer.verify(header, entry)

    def test_verifier_only_needs_public_key(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        entry = _entry()
        header = signer.sign(entry)
        verifier = MLDSAReceiptSigner.from_raw(public_key=signer.public_bytes(), key_id="pq1")
        assert verifier.verify(header, entry)

    def test_key_sizes_match_ml_dsa_65(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        assert len(signer.public_bytes()) == 1952
        assert len(signer.private_bytes()) == 4032


class TestRejection:
    def test_wrong_entry_rejected(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        header = signer.sign(_entry("a"))
        assert not signer.verify(header, _entry("b"))

    def test_tampered_signature_rejected(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        entry = _entry()
        header = signer.sign(entry)
        # Flip a hex nibble inside the signature field.
        flipped = header[:-1] + ("0" if header[-1] != "0" else "1")
        assert not signer.verify(flipped, entry)

    def test_wrong_key_id_rejected(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        entry = _entry()
        header = signer.sign(entry)
        verifier = MLDSAReceiptSigner.from_raw(public_key=signer.public_bytes(), key_id="other")
        assert not verifier.verify(header, entry)

    def test_wrong_public_key_rejected(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        other = MLDSAReceiptSigner.generate(key_id="pq1")
        entry = _entry()
        header = signer.sign(entry)
        verifier = MLDSAReceiptSigner.from_raw(public_key=other.public_bytes(), key_id="pq1")
        assert not verifier.verify(header, entry)


class TestConstruction:
    def test_verify_only_cannot_sign(self) -> None:
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        verifier = MLDSAReceiptSigner.from_raw(public_key=signer.public_bytes(), key_id="pq1")
        with pytest.raises(RuntimeError, match="verify-only"):
            verifier.sign(_entry())

    def test_from_raw_requires_public_key(self) -> None:
        with pytest.raises(ValueError, match="public_key is required"):
            MLDSAReceiptSigner.from_raw(private_key=b"x" * 4032, key_id="pq1")

    def test_empty_key_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="key_id"):
            MLDSAReceiptSigner.from_raw(public_key=b"x" * 1952, key_id="")

    def test_files_round_trip(self, tmp_path: object) -> None:
        from pathlib import Path

        assert isinstance(tmp_path, Path)
        signer = MLDSAReceiptSigner.generate(key_id="pq1")
        priv = tmp_path / "k.priv"
        pub = tmp_path / "k.pub"
        priv.write_bytes(signer.private_bytes())
        pub.write_bytes(signer.public_bytes())
        entry = _entry()
        # A signer loads BOTH files: ML-DSA cannot re-derive the public
        # key from the private one (unlike Ed25519), so the proxy carries
        # both and shares only the public half.
        loaded = MLDSAReceiptSigner.from_files(
            private_key_path=str(priv), public_key_path=str(pub), key_id="pq1"
        )
        header = loaded.sign(entry)
        assert MLDSAReceiptSigner.from_files(public_key_path=str(pub), key_id="pq1").verify(
            header, entry
        )
