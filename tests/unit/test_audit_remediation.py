"""Regression tests for security, concurrency, and verifier hardening."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import fakeredis
import httpx
import pytest
from click.testing import CliRunner

from signet.adapters.langchain import SignetCallbackHandler
from signet.audit.backend import FileLockingJsonlBackend, JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.compactor import (
    COMPACTION_CHECK_NAME,
    COMPACTION_MARKER_FIELD,
    COMPACTION_MARKER_SIG_FIELD,
    trim_before_index,
)
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import BreakKind, ChainVerifier, verify_with_archives
from signet.cli import _read_env_var
from signet.cli import main as cli_main
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner
from signet.plugins import resolve
from signet.plugins.discovery import DiscoveredPlugin
from signet.server.receipt import parse_header
from signet.server.redis_session_store import RedisSessionStore


def _make_entry(label: str) -> AuditEntry:
    return AuditEntry(
        entry_id=f"e-{label}",
        owner=Owner.human("alice@example.com"),
        check_name="test.check",
        decision=Decision.ALLOW,
        reason=f"ok-{label}",
    )


class TestTrimBeforeIndexHardening:
    def test_trim_clears_both_prev_and_seq_caches(self, tmp_path: Path) -> None:
        backend = JsonlBackend(tmp_path / "audit.jsonl")
        ring = KeyRing(active=Key.generate("k1"))
        chain = HmacChain(backend, ring, sequence=True)
        chain.append(_make_entry("1"))
        chain.append(_make_entry("2"))
        chain.append(_make_entry("3"))
        assert chain._cached_prev is not None
        assert chain._cached_seq == 2

        remaining = trim_before_index(backend, 3, chain=chain)
        assert remaining == 0
        assert chain._cached_prev is None
        assert chain._cached_seq is None

        # Appending after full trim restarts cleanly from disk truth.
        restarted = chain.append(_make_entry("4"))
        assert restarted.prev_hmac == ""
        report = ChainVerifier(backend, ring).verify()
        assert report.ok
        assert report.total_entries == 1


class TestHmacChainLockingBackendDefault:
    def test_file_locking_backend_defaults_cache_prev_false(self, tmp_path: Path) -> None:
        path = tmp_path / "locked.jsonl"
        ring = KeyRing(active=Key.generate("k1"))
        chain_a = HmacChain(FileLockingJsonlBackend(path), ring)
        chain_b = HmacChain(FileLockingJsonlBackend(path), ring)
        assert chain_a._cache_prev is False
        assert chain_b._cache_prev is False

        chain_a.append(_make_entry("a1"))
        chain_b.append(_make_entry("b1"))
        chain_a.append(_make_entry("a2"))
        chain_b.append(_make_entry("b2"))

        report = ChainVerifier(FileLockingJsonlBackend(path), ring).verify()
        assert report.ok, f"unexpected breaks: {report.breaks}"
        assert report.total_entries == 4

    def test_explicit_cache_prev_true_with_locking_backend_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "warn.jsonl"
        ring = KeyRing(active=Key.generate("k1"))
        with caplog.at_level(logging.WARNING, logger="signet.audit.chain"):
            chain = HmacChain(FileLockingJsonlBackend(path), ring, cache_prev=True)
        assert chain._cache_prev is True
        assert any("cache_prev=True" in rec.message for rec in caplog.records)


class TestLangChainRefusalExtraction:
    def test_extracts_dict_body_from_sdk_status_error(self) -> None:
        handler = SignetCallbackHandler()
        err = Exception("403")
        err.body = {"error": "refused", "correlation_id": "corr-123"}  # type: ignore[attr-defined]
        handler.on_llm_error(err, run_id=uuid.uuid4())
        assert handler.last_refusal == {"error": "refused", "correlation_id": "corr-123"}

    def test_extracts_json_str_body_and_falls_back_to_response(self) -> None:
        handler = SignetCallbackHandler()
        err_str = Exception("403")
        err_str.body = json.dumps({"error": "refused", "correlation_id": "corr-str"})  # type: ignore[attr-defined]
        handler.on_llm_error(err_str, run_id=uuid.uuid4())
        assert handler.last_refusal == {"error": "refused", "correlation_id": "corr-str"}

        handler2 = SignetCallbackHandler()
        err_fallback = Exception("403")
        err_fallback.body = "not-json"  # type: ignore[attr-defined]
        err_fallback.response = SimpleNamespace(  # type: ignore[attr-defined]
            json=lambda: {"error": "signet refused this request", "reason": "blocked"}
        )
        handler2.on_llm_error(err_fallback, run_id=uuid.uuid4())
        assert handler2.last_refusal == {
            "error": "signet refused this request",
            "reason": "blocked",
        }


class TestVerifyWithArchivesMalformedMarker:
    def test_malformed_compacted_count_emits_structured_break(self, tmp_path: Path) -> None:
        backend = JsonlBackend(tmp_path / "audit.jsonl")
        ring = KeyRing(active=Key.generate("k1"))
        chain = HmacChain(backend, ring)

        bad_marker = AuditEntry(
            entry_id="marker-bad",
            owner=Owner.policy("compactor"),
            check_name=COMPACTION_CHECK_NAME,
            decision=Decision.ALLOW,
            reason="compacted",
            metadata={
                COMPACTION_MARKER_FIELD: {
                    "archive_path": str(tmp_path / "missing.jsonl.gz"),
                    "merkle_root": "0" * 64,
                    "compacted_count": "not-an-int",
                    COMPACTION_MARKER_SIG_FIELD: "a" * 64,
                }
            },
        )
        chain.append(bad_marker)

        report = verify_with_archives(backend, ring, archive_dir=tmp_path)
        assert not report.ok
        assert any(b.kind == BreakKind.ARCHIVE_FORMAT_INVALID for b in report.breaks)


class TestRedisSessionStoreAtomicCreate:
    def test_get_or_create_does_not_clobber_raced_session(self) -> None:
        client = fakeredis.FakeRedis(decode_responses=True)
        store = RedisSessionStore(client=client, ttl_seconds=60)

        # Simulate another replica writing a progressed session between initial GET and SET NX.
        raced_session = store.get_or_create("sess-race")
        raced_session.touch()
        raced_session.scratch["step"] = "committed"
        store.save(raced_session)

        original_get = store.get
        calls = {"n": 0}

        def racy_get(sid: str):
            calls["n"] += 1
            if calls["n"] == 1:
                return None  # Pretend the session did not exist on the initial read.
            return original_get(sid)

        with patch.object(store, "get", side_effect=racy_get):
            result = store.get_or_create("sess-race")

        assert result.request_count == 1
        assert result.scratch == {"step": "committed"}


class TestKeyRingThreadSafety:
    def test_concurrent_rotations_and_lookups_preserve_all_keys(self) -> None:
        ring = KeyRing(active=Key.generate("k0"))

        def rotate_worker(idx: int) -> None:
            ring.rotate(Key.generate(f"k{idx}"))

        def read_worker(_: int) -> None:
            for kid in ring.all_known_ids():
                assert ring.get(kid) is not None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(rotate_worker, i) for i in range(1, 33)]
            futs += [pool.submit(read_worker, i) for i in range(32)]
            for f in futs:
                f.result()

        known = set(ring.all_known_ids())
        assert known == {f"k{i}" for i in range(33)}
        for kid in known:
            assert ring.get(kid) is not None


class TestReceiptParseHeaderGuard:
    def test_non_str_input_returns_none(self) -> None:
        assert parse_header(None) is None  # type: ignore[arg-type]
        assert parse_header(b"signet=v1; entry=e; key=k; sig=s") is None  # type: ignore[arg-type]
        assert parse_header(123) is None  # type: ignore[arg-type]


class TestCliDoctorAndEnvSymlinkHardening:
    def test_doctor_handles_non_json_health_and_version(self) -> None:
        def fake_get(url: str, timeout: float = 5.0) -> httpx.Response:
            return httpx.Response(502, text="<html>Bad Gateway</html>")

        def fake_post(url: str, **kwargs: object) -> httpx.Response:
            return httpx.Response(403, json={"error": "refused"})

        runner = CliRunner()
        with (
            patch("httpx.get", side_effect=fake_get),
            patch("httpx.post", side_effect=fake_post),
        ):
            res = runner.invoke(cli_main, ["doctor", "--self", "http://127.0.0.1:8443"])
        assert res.exit_code == 1
        assert "Traceback" not in res.output
        assert "/health" in res.output
        assert "/version" in res.output

    def test_read_env_var_rejects_symlink(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("SIGNET_UPSTREAM_URL=https://secret.example\n", encoding="utf-8")
        link_file = tmp_path / ".env"
        try:
            os.symlink(secret_file, link_file)
        except OSError:
            pytest.skip("symlinks unavailable in this environment")
        assert _read_env_var(link_file, "SIGNET_UPSTREAM_URL") is None


class TestPluginResolveHardening:
    def test_resolve_rejects_secondary_duplicate_or_missing_obj(self) -> None:
        good = DiscoveredPlugin(
            name="dup_check",
            group="signet.checks",
            package="pkg-a",
            package_version="1.0.0",
            target="pkg_a:CheckA",
            status="loaded",
            abi_declared=1,
            abi_required=1,
            error=None,
            obj=object,
        )
        dup = DiscoveredPlugin(
            name="dup_check",
            group="signet.checks",
            package="pkg-b",
            package_version="1.0.0",
            target="pkg_b:CheckB",
            status="duplicate_name",
            abi_declared=1,
            abi_required=1,
            error=None,
            obj=None,
            duplicate_with=("pkg-a", "pkg-b"),
        )
        with (
            patch("signet.plugins.discover_plugins", return_value=[good, dup]),
            pytest.raises(RuntimeError, match="duplicate"),
        ):
            resolve("dup_check")

        broken = DiscoveredPlugin(
            name="none_obj",
            group="signet.checks",
            package="pkg-c",
            package_version="1.0.0",
            target="pkg_c:CheckC",
            status="loaded",
            abi_declared=1,
            abi_required=1,
            error=None,
            obj=None,
        )
        with (
            patch("signet.plugins.discover_plugins", return_value=[broken]),
            pytest.raises(RuntimeError, match="without a bound class object"),
        ):
            resolve("none_obj")


class TestStandaloneVerifierCleanErrors:
    def test_missing_log_and_bad_entry_exit_cleanly(self, tmp_path: Path) -> None:
        script = Path(__file__).resolve().parents[2] / "tools" / "verify_standalone.py"
        missing = tmp_path / "does_not_exist.jsonl"

        proc1 = subprocess.run(
            [sys.executable, str(script), "chain", str(missing), "--secret", "aa" * 32],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc1.returncode != 0
        assert "Traceback" not in proc1.stderr
        assert "cannot open audit log" in proc1.stderr

        proc2 = subprocess.run(
            [
                sys.executable,
                str(script),
                "receipt",
                "--header",
                "signet=v1; entry=e1; key=k1; sig=00",
                "--entry",
                "{bad-json",
                "--secret",
                "aa" * 32,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc2.returncode != 0
        assert "Traceback" not in proc2.stderr
        assert "--entry is not valid JSON" in proc2.stderr
