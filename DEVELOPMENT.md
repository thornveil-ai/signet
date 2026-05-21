# Development

## Setup

```bash
git clone https://github.com/thornveil-ai/signet
cd signet
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e ".[dev,all,docs]"
pre-commit install
```

## Running tests

```bash
# Unit + adapter tests (fast, no network)
pytest

# With coverage report
pytest --cov=signet --cov-report=html
open htmlcov/index.html

# Integration tests (hit live LLM endpoints — slow, opt-in)
pytest -m integration

# Adversarial bypass suite
pytest -m adversarial
```

## Style

- `ruff check src tests` — lint
- `ruff format src tests` — format
- `mypy src` — type check (strict mode)
- All three are enforced by pre-commit and CI.

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `build`, `style`, `perf`, `security`.

The CHANGELOG is generated from these messages.

## Layout

```
src/signet/
├── __init__.py
├── core/              Pipeline, Check ABC, Owner, AuditEntry primitives
├── checks/            built-in Check implementations
├── audit/             HMAC chain writer + verifier
├── adapters/          OpenAI/Anthropic/LangChain SDK wrappers
├── server.py          FastAPI proxy
└── cli.py             click-based CLI

tests/
├── unit/              one file per module under test
├── integration/       hits live LLM endpoints (RigRun, local Ollama)
└── adversarial/       deliberate bypass attempts
```

## Local LLM for integration tests

Tests under `tests/integration/` pull endpoints from environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `SIGNET_TEST_UPSTREAM` | `http://localhost:11434/v1` (Ollama) | OpenAI-compatible upstream |
| `SIGNET_TEST_MODEL` | `gemma4:e2b` | Model name to query |
| `SIGNET_TEST_RIGRUN_URL` | unset | If set, runs the RigRun-specific suite |

Skip integration tests in CI: `pytest -m "not integration"` (CI default).

## Releasing

1. Update `CHANGELOG.md` under the next version heading.
2. Bump version in `src/signet/__init__.py` and `pyproject.toml`.
3. `git tag -a v0.1.0 -m "v0.1.0"`
4. `git push --tags` — the publish workflow builds + uploads to PyPI.
