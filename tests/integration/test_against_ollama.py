"""End-to-end tests against a local Ollama Gemma 4.

Stands up a SignetApp with Ollama as the upstream and verifies the
real round-trip: caller → signet → Ollama → caller, with policy
enforcement, audit chain writes, and signed receipts all firing.

Skipped automatically when Ollama isn't reachable.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from signet.checks import (
    OwnerResolutionCheck,
    Pattern,
    RegexContentCheck,
    ScopeDriftCheck,
)
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig
from signet.server.receipt import parse_header

pytestmark = pytest.mark.integration


def _build_app(
    upstream: str,
    audit_path: Path,
    *,
    extra_checks: list = (),
) -> TestClient:
    pipeline = Pipeline(
        checks=[
            OwnerResolutionCheck(require_owner=True),
            ScopeDriftCheck(token_tolerance=0.5),  # generous for varied tokenizers
            *extra_checks,
        ]
    )
    config = ServerConfig(
        upstream_url=upstream,
        audit_log_path=audit_path,
        allow_ephemeral_key=True,
        # These tests assert on the human-readable refusal ``reason``, which
        # strict redaction deliberately withholds (production ships only
        # ``{error, correlation_id}`` and keeps detail in the audit chain).
        # The assertions predate strict redaction becoming the default and
        # started KeyError-ing on ``reason`` rather than failing on behavior
        # — the 403s themselves were always correct. Verbose is the
        # documented integration-time posture (``--no-strict-error-redaction``
        # / ``--dev``), so opt into it explicitly here.
        strict_error_redaction=False,
    )
    app = SignetApp(config=config, pipeline=pipeline)
    return TestClient(app.app)


class TestOllamaForward:
    def test_allowed_request_round_trips(
        self,
        ollama_url: str,
        ollama_model: str,
        skip_if_no_ollama: None,
        tmp_path: Path,
    ) -> None:
        client = _build_app(ollama_url, tmp_path / "audit.jsonl")
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": ollama_model,
                "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
                "max_tokens": 10,
                "stream": False,
            },
            headers={"X-Commit-Owner": "human:integration-test"},
            timeout=60,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        # Ollama returns OpenAI-shape; choices[0].message.content
        assert "choices" in data
        assert data["choices"][0]["message"]["content"]

    def test_missing_owner_blocked_before_upstream(
        self,
        ollama_url: str,
        ollama_model: str,
        skip_if_no_ollama: None,
        tmp_path: Path,
    ) -> None:
        client = _build_app(ollama_url, tmp_path / "audit.jsonl")
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": ollama_model,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 5,
                "stream": False,
            },
            timeout=10,
        )
        assert r.status_code == 403
        assert "no commit owner" in r.json()["reason"].lower()

    def test_receipt_emitted_and_parses(
        self,
        ollama_url: str,
        ollama_model: str,
        skip_if_no_ollama: None,
        tmp_path: Path,
    ) -> None:
        client = _build_app(ollama_url, tmp_path / "audit.jsonl")
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": ollama_model,
                "messages": [{"role": "user", "content": "Reply with: ok"}],
                "max_tokens": 5,
                "stream": False,
            },
            headers={"X-Commit-Owner": "human:integration-test"},
            timeout=60,
        )
        assert r.status_code == 200
        receipt = r.headers.get("X-Signet-Receipt") or r.headers.get("x-signet-receipt")
        assert receipt is not None, "expected receipt header"
        parsed = parse_header(receipt)
        assert parsed is not None
        assert parsed["signet"] == "v1"
        assert len(parsed["sig"]) == 64

    def test_regex_block_in_input(
        self,
        ollama_url: str,
        ollama_model: str,
        skip_if_no_ollama: None,
        tmp_path: Path,
    ) -> None:
        client = _build_app(
            ollama_url,
            tmp_path / "audit.jsonl",
            extra_checks=[
                RegexContentCheck(
                    patterns=[Pattern(pattern=r"\bSECRET-API-KEY\b", action="block", label="ssk")]
                )
            ],
        )
        r = client.post(
            "/v1/chat/completions",
            json={
                "model": ollama_model,
                "messages": [{"role": "user", "content": "What is the SECRET-API-KEY here?"}],
                "max_tokens": 5,
                "stream": False,
            },
            headers={"X-Commit-Owner": "human:integration-test"},
            timeout=10,
        )
        assert r.status_code == 403
        assert "matched" in r.json()["reason"].lower()


class TestOllamaAuditChain:
    def test_chain_grows_over_multiple_requests(
        self,
        ollama_url: str,
        ollama_model: str,
        skip_if_no_ollama: None,
        tmp_path: Path,
    ) -> None:
        audit_path = tmp_path / "audit.jsonl"
        client = _build_app(ollama_url, audit_path)
        for _ in range(3):
            r = client.post(
                "/v1/chat/completions",
                json={
                    "model": ollama_model,
                    "messages": [{"role": "user", "content": "Reply: ok"}],
                    "max_tokens": 5,
                    "stream": False,
                },
                headers={"X-Commit-Owner": "human:integration-test"},
                timeout=60,
            )
            assert r.status_code == 200

        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 3
