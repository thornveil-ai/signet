# Signet — Roadmap

**Status:** Production-shipping public OSS. Pre-1.0.
**Visibility:** Public. Apache-2.0.
**Owner:** Thornveil LLC.
**Last reviewed:** 2026-05-22

This roadmap is the source-of-truth narrative for where Signet is, and what
gets it to "contract-ready" status. Live tracking lives on the
[Thornveil Roadmap project](https://github.com/orgs/thornveil-ai/projects/1)
with `Repository = signet` filter.

---

## What "contract-ready" means for Signet

Signet itself does not sign federal contracts directly — Signet is OSS, and
its commercial role is as the credibility anchor for [Auspex](https://github.com/thornveil-ai/auspex-contact).
"Contract-ready" for Signet therefore means: **in a state where pointing a
federal evaluator at the public Signet repository materially advances an
Auspex sales conversation.**

Concretely, that requires:

1. **v1.0 stable**, semver-committed, no breaking changes pending.
2. **Visible production usage** — public adopters, healthy weekly PyPI
   downloads, real stars/forks.
3. **Federal-procurement legibility** — NIST AI RMF crosswalk published,
   OWASP LLM Top 10 reference, conference talk delivered.
4. **External validation** — bug-hunt-log carries findings from hunters
   beyond the founder; community-submitted plugins exist.

Cross-references the federal IL5 trio: [Auspex](https://github.com/thornveil-ai/auspex-contact)
extends the Signet vocabulary with engagement-specific checks. A federal
evaluator who reads Signet first should arrive at Auspex already trusting
the safety substrate.

---

## Now — already shipped (as of 2026-05-22)

The baseline. These are facts on the ground, not aspirations.

- **v0.1.10.1 live on PyPI** as `signet-sign` (490+ downloads/week, 2,335 last month).
- **25,012 LOC source, 31,451 LOC tests** (1.26× test:source ratio).
- **1,175 test functions** across 52 test files. 86.25% line coverage.
- **11 hunt-fix cycles documented** in [`docs/bug-hunt-log.md`](docs/bug-hunt-log.md) — every published bug recorded in chronological order.
- **mkdocs documentation site** live with architecture, deployment, plugins, security, integrations.
- **3 official integration examples** (OpenAI, Anthropic, LangChain) + 3 deployment templates (docker-compose, GitHub Actions, Kubernetes).
- **Apache-2.0 + NOTICE** published; CODE_OF_CONDUCT, CONTRIBUTING, DEVELOPMENT all present.
- **CI workflows:** ci.yml, docs.yml, label-sync.yml, publish.yml.
- **Substack launch post** live and indexed.
- **Org transfer to `thornveil-ai`** complete with CODEOWNERS + label-sync.

---

## Next 90 days (target: 2026-08-20)

Post-transfer hardening + visible-growth phase. Recover any signal lost in
the org transfer; convert the launch-artifact backlog (`growth/`) into
sustained outbound.

### M01. PyPI metadata migration to thornveil-ai
**Target: 2026-05-29.** Current PyPI project URLs still point at `jeranaias/signet`. Update pyproject.toml `[project.urls]` (Homepage, Documentation, Issues, Repository), bump version, re-publish to PyPI. Trusted Publisher binding already re-issued for `thornveil-ai/signet`.
**Success:** `pip show signet-sign` displays thornveil-ai URLs.

### M02. Documentation site URL migration
**Target: 2026-05-29.** docs.yml GitHub Pages workflow already targets `thornveil-ai.github.io/signet`. Verify the site renders and the PyPI badge in README links correctly.
**Success:** thornveil-ai.github.io/signet loads; no 404s from PyPI links.

### M03. Growth artifacts URL sweep
**Target: 2026-06-05.** 10+ files in `growth/` still reference `jeranaias` URLs. Sweep before any execute pass to avoid re-launching with broken inbound links.
**Success:** `grep -rln "jeranaias" growth/` returns empty.

### M04. v0.1.11 hardening release
**Target: 2026-06-12.** Roll up any post-transfer fixes + scheduled-but-deferred polish into one cycle-12 release. Keep the 11-cycle discipline going.
**Success:** v0.1.11 tagged + published, bug-hunt-log entry added.

### M05. README social-proof slot
**Target: 2026-06-12.** Add a "Production users" or "Adopters" section to README listing 2-3 named integrations (anonymous-OK form acceptable). Auspex is the first adopter and can be named.
**Success:** README has ADOPTERS.md or a Users section with 2+ entries.

### M06. PyPI downloads + GitHub stars baseline recovery
**Target: 2026-07-15.** Org transfer typically drops both. Recover to pre-transfer levels: ~500 weekly downloads, ~10 stars minimum (org repo is brand-new — counts start at 0).
**Success:** 500+ weekly PyPI downloads sustained for 4 weeks; ≥10 GitHub stars.

### M07. Awesome-list submissions executed
**Target: 2026-07-15.** Template at `growth/06-awesome-list-prs.md`. Submit to: awesome-llm-safety, awesome-ai-security, awesome-langchain, awesome-anthropic.
**Success:** 3+ awesome-list PRs merged.

### M08. OWASP LLM Top 10 PR submitted
**Target: 2026-07-15.** Template at `growth/07-owasp-pr.md`. Submit reference to OWASP LLM Top 10 LLM06 (Sensitive Information Disclosure) and LLM08 (Excessive Agency).
**Success:** OWASP LLM Top 10 references Signet in at least one entry.

### M09. NIST AI RMF crosswalk published
**Target: 2026-08-20.** Publish `docs/nist-ai-rmf-crosswalk.md` mapping Signet's 11 production checks to NIST AI RMF 1.0 controls (Govern, Map, Measure, Manage). This is the federal-procurement legibility artifact.
**Success:** Document published, linked from README, referenced in PyPI description.

---

## Next 6 months (target: 2027-02-22)

Move from "production-shipping pre-1.0" to "OSS-mature 1.x stable."

### M10. Plugin ecosystem expansion
**Target: 2026-09-30.** Three community-submitted plugins or third-party check examples added to `docs/integrations/` or a `community/` directory. The `plugin_dev.md` infrastructure already exists.
**Success:** 3+ external plugins live, each with passing CI tests.

### M11. Conference talk submitted
**Target: 2026-10-15.** CFP templates already drafted at `growth/09-cfp-templates.md`. Submit to: DEF CON AppSec Village 2027, OWASP Global AppSec 2027, BSidesDC 2027, USENIX SREcon (AI safety track).
**Success:** 2+ talks submitted; at least 1 accepted.

### M12. External hunters in bug-hunt-log
**Target: 2026-11-30.** Bug-hunt-log currently only carries founder-driven cycles. Need a cycle credited to external hunters (security researchers, customer reports, fuzz reports). This is the credibility test.
**Success:** ≥1 bug-hunt-log cycle with external hunter credit.

### M13. v1.0.0 release candidate cut
**Target: 2026-12-15.** Feature lock, semver commitment statement, breaking-change deadline. Includes:
  - Stable API surface documented + versioned
  - Migration guide for 0.x → 1.0 callers
  - LTS commitment for v1.x line (24 months minimum)
**Success:** v1.0.0-rc1 tagged; migration guide published.

### M14. Auspex-Signet public integration case study
**Target: 2027-01-15.** Public case study showing "Signet inside Auspex" — how Auspex's 13-check engagement gate composes the Signet substrate with engagement-specific checks. This is the dogfooding artifact that lands federal pitches.
**Success:** Case study published at thornveil-ai.github.io/signet/case-studies/auspex (or similar), referenced from Auspex contact page.

### M15. v1.0.0 stable released
**Target: 2027-02-15.** Final v1.0.0 published to PyPI. Announce on Substack + relevant communities. Hacker News submission.
**Success:** v1.0.0 live, 1,000+ weekly PyPI downloads sustained, HN front-page (top 30 minimum) for ≥30 minutes.

---

## Contract-ready (target: 2027-12-31)

The state where Signet materially advances Auspex federal sales.

### M16. 500+ stars, 1,000+ weekly PyPI downloads
**Target: 2027-04-30.** Quantitative social-proof floor. Below these numbers, federal evaluators dismiss as "not yet adopted." Above them, the project reads as community-validated.
**Success:** Sustained ≥500 stars and ≥1,000 weekly downloads for 8+ weeks.

### M17. 10+ external contributors with merged PRs
**Target: 2027-06-30.** Real community signal. Distinct from "10 stars" — actually shipping code to the project from outside Thornveil.
**Success:** `git log --format='%aE' | grep -v '@thornveil.ai$' | sort -u | wc -l` ≥ 10.

### M18. Conference talk delivered + recording public
**Target: 2027-08-31.** Aligns with the 2027 conference calendar — execute one of the M11 accepted talks. Recording publicly available; deck on the docs site.
**Success:** Recording link on docs site; talk listed on speaker's profile.

### M19. Peer-reviewed venue publication
**Target: 2027-10-31.** Workshop paper minimum. Targets: USENIX Security AISec workshop, ACM CCS AISec, IEEE SaTML.
**Success:** Paper accepted to peer-reviewed venue; preprint on arXiv.

### M20. Federal procurement reference
**Target: 2027-12-31.** Bonus / stretch milestone. Signet referenced in 1+ federal procurement requirements document (BAA, SOW, capability description). Even a single SBIR Phase II call mentioning "Signet-compatible" or "capability-gated safety" is a major win.
**Success:** Public federal procurement document references Signet by name OR by capability pattern.

### M21. v1.x stable, 18+ months without breaking change
**Target: 2027-08-15.** Demonstrate API stability discipline. From v1.0.0 release (~2027-02-15) plus 18 months = mid-2028 actually. By end of 2027 we'd be at 10 months stable — milestone target reframed to "no breaking change since v1.0 cut".
**Success:** v1.0 → v1.x line has zero breaking changes; semver-discipline visible from CHANGELOG.

---

## Dependencies + cross-system flow

```
   ┌──────────────────────────┐
   │  Signet (public OSS)     │  ← THIS ROADMAP
   │  Capability vocabulary   │
   └──────────────┬───────────┘
                  │ extends
                  ▼
   ┌──────────────────────────┐
   │  Auspex (federal-gated)  │  ← Signet's commercial story
   │  Engagement-specific     │
   │  checks built on Signet  │
   └──────────────────────────┘
```

**Critical path:** Signet M01-M09 (post-transfer hardening + federal-procurement legibility) must complete before Auspex begins federal pilot conversations. M14 (case study) is the artifact that makes the Signet→Auspex pull-through visible to evaluators.

**Decoupled from:** Mycelium, RigRun, HawkStack, Meridian, Canopy, Pyros, Navigator, Alchemist — Signet does not block any of them.

---

## Owner notes

- The `growth/` folder ships in the public repo by user direction. Will revisit at M16 (visible-growth threshold) — if the project is at 500+ stars, the launch artifacts can move to a private launch-materials repo since the public-evidence-of-execution case is closed.
- Bug-hunt-log discipline is the differentiator. Every other LLM safety library hides failures. Don't lose this.
- v1.0 timing depends on M12 (external hunters) — cutting v1.0 before external validation looks premature. Hold v1.0 until at least one external hunt cycle is in the log.
