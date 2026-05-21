# Contributing to signet

Thanks for your interest. signet is Apache-2.0 OSS — contributions of any size are welcome, from typo fixes to new check implementations to entire transport adapters.

## Quick start

```bash
git clone https://github.com/thornveil-ai/signet
cd signet
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev,all,docs]"
pre-commit install
pytest
```

If `pytest` passes locally, you're set up.

## What kinds of changes are most welcome

| Area | Examples | Notes |
|---|---|---|
| Bug fixes | edge case in a check, race in the chain writer, documentation typo | Open a PR; reference the issue if there is one |
| New built-in checks | output PII detector, MIME-type validator, structured-output schema check | Discuss in an issue first if it changes the public API |
| Transport adapters | LiteLLM, vLLM-direct, OpenRouter, custom proxies | Goes in `signet/adapters/` |
| Plugin examples | reference implementations of niche checks | Goes in `signet/plugins/` |
| Documentation | per-check pages, deployment recipes, architecture deep-dives | Goes in `docs/` |
| Adversarial tests | new attack categories, edge cases for existing categories | Goes in `tests/adversarial/` — this is the trust artifact |

## What needs careful review before opening a PR

- Changes to the `Pipeline`, `Check`, or `AuditEntry` public APIs (potential breaking change)
- Changes to the audit chain serialization format (breaks chain verification across versions)
- Changes to the `X-Signet-Receipt` header format (breaks offline verifiers)
- Changes that loosen any default-on enforcement (default-off opt-ins are fine; changing default-on to default-off is a behavior break)

For these, please open an issue first to discuss.

## Style

We use `ruff` for both lint and format, `mypy --strict` for types. The pre-commit hooks enforce all three.

```bash
ruff check src tests
ruff format src tests
mypy src
```

CI runs the same checks plus the test matrix (Python 3.11 / 3.12 / 3.13 × Linux / macOS / Windows). Your PR needs to pass the full matrix.

## Commit message format

[Conventional Commits](https://www.conventionalcommits.org/). Types:

- `feat:` new functionality
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding or modifying tests
- `refactor:` restructure without behavior change
- `chore:` build, tooling, dependencies
- `ci:` GitHub Actions / publish workflow
- `style:` ruff format
- `perf:` performance only
- `security:` security-impacting

Optional scope in parentheses: `feat(checks): add MIME-type validator`.

The CHANGELOG is generated from these.

## Adding a new built-in check

1. Create `src/signet/checks/your_check.py` subclassing `Check`. Set `name` and `stage`.
2. Implement only the hooks you need; defaults are permissive `allow()`.
3. Re-export from `src/signet/checks/__init__.py`.
4. Add tests in `tests/unit/test_checks.py`. Cover both happy and refuse paths.
5. Add adversarial tests in `tests/adversarial/test_bypass_attempts.py` if your check defends against a specific attack class.
6. Add a docs page at `docs/checks/your_check.md`.
7. Update the README's "Built-in checks" table.

## Adding a plugin

Plugins live outside the signet repo — they're separate packages that declare entry points under the `signet.checks` group:

```toml
[project.entry-points."signet.checks"]
your_check = "your_pkg.module:YourCheck"
```

The reference plugins (`signet.plugins.tribunal`, `signet.plugins.sandbox`) live in this repo as built-in examples. Most production plugins should ship as their own packages.

See [`docs/plugin_dev.md`](https://github.com/thornveil-ai/signet/blob/main/docs/plugin_dev.md).

## Reporting security issues

Do not file public issues for vulnerabilities. See [`SECURITY.md`](https://github.com/thornveil-ai/signet/blob/main/SECURITY.md).

## License

By contributing, you agree your contribution is licensed under Apache-2.0, the same as the rest of the project.

## Code of conduct

See [`CODE_OF_CONDUCT.md`](https://github.com/thornveil-ai/signet/blob/main/CODE_OF_CONDUCT.md).
