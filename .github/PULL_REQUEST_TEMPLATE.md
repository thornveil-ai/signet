<!--
Thanks for contributing to signet. A few quick checks before you submit
keep review fast and predictable.
-->

## What does this change?

<!-- One or two sentences. The "why" matters more than the "what" since reviewers can read the diff. -->

## What kind of change?

<!-- Pick one. Delete the others. -->

- Bug fix (something signet did wrong)
- New feature (a check, an endpoint, a CLI command)
- Documentation only
- Refactor (no behavior change)
- Build / CI / repo housekeeping

## Checklist

- [ ] I read [CONTRIBUTING.md](https://github.com/thornveil-ai/signet/blob/main/CONTRIBUTING.md)
- [ ] Tests added or updated for the change
- [ ] `pytest tests/unit tests/adversarial -q` passes locally
- [ ] `ruff check src tests` and `ruff format --check src tests` pass
- [ ] `mypy src` passes
- [ ] Docs updated if behavior changed (README, docs/, or per-check page)
- [ ] CHANGELOG.md updated under `[Unreleased]`

## Anything else reviewers should know?

<!-- Tradeoffs, alternative approaches you considered, anything that's intentionally not in scope for this PR. -->
