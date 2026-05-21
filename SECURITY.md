# Security policy

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Preferred channel: open a [private security advisory](https://github.com/thornveil-ai/signet/security/advisories/new). GitHub coordinates the disclosure timeline and notifies maintainers without exposing the report.

Backup channel: `jesse@thornveil.ai` (subject prefix `[signet-security]`). Until the project has a hosted domain, this single inbox is the only out-of-band path; expect occasional delays.

Include:

- A description of the issue.
- Steps to reproduce or proof-of-concept.
- Versions of signet affected (if known).
- Whether the issue is currently being exploited or publicly disclosed elsewhere.

Acknowledgement: within 3 business days. Status update: within 10 business days.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✓ |
| < 0.1 | ✗ |

Pre-1.0 means the API surface may change in minor versions. Security fixes will be applied to the latest minor only.

## Threat model

### Read this first — what the audit log actually proves

Two limits worth understanding before you build on signet:

1. **Owner identity is caller-asserted, not authenticated.** The
   `X-Commit-Owner` / `X-Agent-Id` / `X-Policy-Name` headers are taken
   at face value. signet does not verify a JWT, OIDC token, mTLS
   client cert, or SSO session. Every audit row records *what the
   caller said the owner was* — useful for accountability inside a
   trust boundary you already control, **not** as proof of identity
   to a third party. Layer real authentication (mTLS, OIDC,
   `LoopbackTrustCheck` over a tailnet) at or before signet's
   ADMISSION stage if your threat model needs it.

2. **The HMAC chain alone is tamper-evident, not tamper-proof.** It
   detects modification of any subset of entries when verified by a
   party that holds the same key. It does **not** prevent rewriting
   by an attacker who holds both file-write access AND the HMAC
   secret. To close that gap, pair the chain with
   :class:`signet.audit.anchor.Rfc3161Anchor` — every entry's HMAC
   is anchored against an external RFC 3161 Time Stamp Authority
   (FreeTSA by default, or any TSA you have a contract with). The
   anchor receipt is bound to the entry by the chain HMAC itself,
   so swapping either fails verification. WORM storage (S3 Object
   Lock, immutable filesystem) is the other proven path and stacks
   cleanly with anchoring. Both are operator choices; signet ships
   the anchor pluggability and reference adapter in v0.1.3.

signet defends against:

- **An LLM ignoring "stop and wait" instructions.** The pipeline runs out-of-process; the model's compliance is not load-bearing.
- **Unattributable requests** (within the assumption above): owner resolution refuses requests with no resolvable commit owner before the model is consulted.
- **Output spillage above declared classification.** ScopeDriftCheck aborts streams whose content drifts above the request's `X-Classification`.
- **Tamper of post-hoc audit logs by parties without the HMAC key.** HMAC chain detects modify, delete, reorder, and forged-insert tampering.
- **Off-path commits.** Adversarial test suite asserts that every routed handler writes an audit entry.
- **Race-induced chain corruption from in-process concurrent writers.** `HmacChain.append` holds an internal lock; the FastAPI event loop cannot fork the chain by interleaving two appends.

signet does **not** defend against:

- A compromised proxy host. The HMAC key lives on disk; a host-level attacker can rewrite the chain end-to-end and re-sign. Pair the chain with :class:`signet.audit.anchor.Rfc3161Anchor` so even an end-to-end rewrite is externally provable.
- A persuasive model talking a tired human into approving a bad action via the escalation path.
- Composed-action drift across many small approved actions adding to one bad outcome (partially mitigated by INSPECTION-stage checks; not fully solved).
- Network-level attacks (use TLS).
- Supply-chain attacks on the model weights themselves.

signet provides — but operator must opt in:

- **Receipt forgery by a verifier** (default symmetric receipts). The built-in `HmacReceiptSigner` is symmetric; anyone who can verify a receipt holds the secret to forge one. For deployments handing receipts to outside parties (customers, regulators), swap in :class:`signet.server.receipt.Ed25519ReceiptSigner` (verifiers hold only the public key; cannot forge). `signet keys generate-ed25519` writes the keypair. Optional dep `pip install signet-sign[ed25519]`.
- **Multi-process audit writers**. The default `JsonlBackend` is single-writer; `uvicorn --workers N>1` against it can fork the chain. Use :class:`signet.audit.backend.FileLockingJsonlBackend` (POSIX `fcntl.flock` + Windows `msvcrt.locking`) plus `HmacChain(cache_prev=False)` for cross-process safety.

## Hardening recommendations

For production deployments:

1. Run `signet serve` behind a reverse proxy that terminates TLS.
2. Restrict the bind interface (`--host 127.0.0.1` for sidecar; explicit network for public).
3. Set `SIGNET_HMAC_SECRET` from a secrets manager — never check it into source.
4. **Tighten audit log file mode.** signet creates `--audit-log` with the OS default umask (typically `0644`, world-readable). Before you start the proxy, `touch` the path and `chmod 0600` it (owner-only) so non-signet processes on the host cannot read attribution data. signet does not enforce this from inside the process — it would prevent legitimate co-readers (verifier crons running as a different user) from working.
5. **Multi-worker uvicorn deployments** must use `signet.audit.backend.FileLockingJsonlBackend` (cross-process locking) and pass `HmacChain(cache_prev=False)`. The default `JsonlBackend` is single-writer; pairing the locking backend with `cache_prev=False` makes `uvicorn --workers N>1` safe.
6. Cap inbound body size at the reverse-proxy layer too. signet enforces `SIGNET_MAX_REQUEST_BODY_BYTES` (default 4 MiB) but defense in depth.
7. Run the audit verifier nightly via cron: `signet audit verify <log> --hmac-secret <secret>`.
8. Subscribe to releases (https://github.com/thornveil-ai/signet/releases) so you see security advisories.

## Disclosure policy

We coordinate disclosure with reporters. Default timeline:

1. Acknowledged report.
2. Fix developed in a private fork.
3. Patch released; advisory published with the release notes (CVE assigned if appropriate).
4. Reporter credited (with permission).

We try to ship a patched release before public disclosure unless the issue is already being exploited in the wild.

## Supply chain

Every published release attaches a CycloneDX SBOM (`signet-sbom.cdx.json`) generated from the build environment to the corresponding GitHub Release. Use it to audit transitive dependencies without reproducing the build.

Verify install integrity by comparing the wheel hash on PyPI against the GitHub Release artifact.

For sigstore-signed releases (`cosign` attestation), SLSA Level 3 build provenance via the GitHub OIDC reusable workflow, and reproducible-build instructions, see "When you need more than the OSS" in the README — these are operational additions that benefit from dedicated engineering support per deployment.
