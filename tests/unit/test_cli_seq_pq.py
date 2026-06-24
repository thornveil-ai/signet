"""CLI tests for `audit verify-contiguity` and `keys generate-mldsa`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.cli import main
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner

SECRET = b"x" * 32


def _entry(reason: str) -> AuditEntry:
    return AuditEntry(
        owner=Owner.human("alice@example.com"),
        check_name="owner_resolution",
        decision=Decision.ALLOW,
        reason=reason,
    )


def _write(log: Path, *, n: int = 5, **kw: object) -> None:
    ring = KeyRing(active=Key(key_id="k1", secret=SECRET))
    chain = HmacChain(JsonlBackend(log), ring, **kw)
    for i in range(n):
        chain.append(_entry(f"r{i}"))


class TestVerifyContiguityCLI:
    def test_clean_sequenced_chain_ok(self, tmp_path: Path) -> None:
        log = tmp_path / "a.jsonl"
        _write(log, sequence=True)
        res = CliRunner().invoke(
            main, ["audit", "verify-contiguity", str(log), "--hmac-secret", SECRET.hex()]
        )
        assert res.exit_code == 0, res.output
        assert "complete and gap-free" in res.output

    def test_interior_drop_caught_by_integrity_first(self, tmp_path: Path) -> None:
        # An interior drop also breaks the prev_hmac link, so the
        # integrity-first gate fires before contiguity -- sequence
        # numbers from a broken chain must not be trusted. (The standalone
        # verifier, which does not short-circuit, additionally surfaces
        # the gap; see test_standalone_verifier.)
        log = tmp_path / "a.jsonl"
        _write(log, sequence=True)
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
        res = CliRunner().invoke(
            main, ["audit", "verify-contiguity", str(log), "--hmac-secret", SECRET.hex()]
        )
        assert res.exit_code == 2
        assert "INTEGRITY BROKEN" in res.output

    def test_tail_truncation_with_expect_end(self, tmp_path: Path) -> None:
        log = tmp_path / "a.jsonl"
        _write(log, sequence=True)
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:3]) + "\n")
        res = CliRunner().invoke(
            main,
            [
                "audit",
                "verify-contiguity",
                str(log),
                "--hmac-secret",
                SECRET.hex(),
                "--expect-end",
                "4",
            ],
        )
        assert res.exit_code == 2
        assert "tail truncated" in res.output

    def test_unsequenced_chain_is_na(self, tmp_path: Path) -> None:
        log = tmp_path / "a.jsonl"
        _write(log)  # no sequence=True
        res = CliRunner().invoke(
            main, ["audit", "verify-contiguity", str(log), "--hmac-secret", SECRET.hex()]
        )
        assert res.exit_code == 2
        assert "no sequence numbers" in res.output

    def test_broken_integrity_short_circuits(self, tmp_path: Path) -> None:
        log = tmp_path / "a.jsonl"
        _write(log, sequence=True)
        res = CliRunner().invoke(
            main, ["audit", "verify-contiguity", str(log), "--hmac-secret", ("11" * 32)]
        )
        assert res.exit_code == 2
        assert "INTEGRITY BROKEN" in res.output

    def test_json_output(self, tmp_path: Path) -> None:
        log = tmp_path / "a.jsonl"
        _write(log, sequence=True)
        res = CliRunner().invoke(
            main,
            ["audit", "verify-contiguity", str(log), "--hmac-secret", SECRET.hex(), "--json"],
        )
        assert res.exit_code == 0
        payload = json.loads(res.output)
        assert payload["contiguity_ok"] is True
        assert payload["first_seq"] == 0
        assert payload["last_seq"] == 4


class TestGenerateMldsaCLI:
    def test_generates_keys_of_expected_size(self, tmp_path: Path) -> None:
        pytest.importorskip("dilithium_py")
        priv = tmp_path / "k.priv"
        res = CliRunner().invoke(
            main, ["keys", "generate-mldsa", "--out", str(priv), "--key-id", "pq1"]
        )
        assert res.exit_code == 0, res.output
        assert priv.read_bytes().__len__() == 4032
        assert (tmp_path / "k.priv.pub").read_bytes().__len__() == 1952
        # Sidecar metadata records the key-id + alg.
        meta = json.loads((tmp_path / "k.priv.meta.json").read_text())
        assert meta["key_id"] == "pq1"
        assert meta["alg"] == "ml-dsa-65"

    def test_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        pytest.importorskip("dilithium_py")
        priv = tmp_path / "k.priv"
        priv.write_bytes(b"existing")
        res = CliRunner().invoke(main, ["keys", "generate-mldsa", "--out", str(priv)])
        assert res.exit_code != 0
        assert "refusing to overwrite" in res.output
