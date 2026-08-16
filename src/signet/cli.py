"""signet CLI -- operations interface.

Subcommands:

* ``signet init`` -- scaffold a starter project (pipeline.py,
  client_example.py, .env.example, .gitignore).
* ``signet serve`` -- run the FastAPI proxy. ``--dev`` bundles the
  three usual local-development flags into one.
* ``signet doctor`` -- preflight check: prints versions, probes
  ``--upstream`` reachability, probes a running ``--self`` for
  /health, /version, and a no-owner refusal round-trip. With
  ``--probe-injection`` (v0.1.6+), runs the static obfuscated-
  injection corpus against ``--self`` and asserts every probe
  refuses.
* ``signet audit verify`` -- walk an HMAC-chained log and report any
  tampering. With ``--including-archives <dir>`` (v0.1.6+), also
  walks every referenced compaction archive end-to-end.
* ``signet audit show`` -- pretty-print one entry by ID.
* ``signet audit count`` / ``audit tail`` -- quick group-by counts
  and tail with field filters.
* ``signet audit compact`` (v0.1.6+) -- Merkle-archive a prefix of
  the chain and replace it with a compaction marker. Operator MUST
  quiesce the chain first (``--quiesce-confirm``).
* ``signet audit report`` (v0.1.6+) -- periodic decision summary:
  decision distribution, top firing checks, top blocked owners
  (anonymized by default), deltas vs the prior period, chain-
  integrity attestation. Markdown or JSON.
* ``signet replay <id>`` -- first-class shorthand for
  ``signet audit show <id>``. Promoted to first-class in v0.1.6;
  the v0.1.0 deprecation note has been retired since the name
  applies just fine to "replay this audit row to my eyeballs"
  even though true pipeline re-execution remains roadmap.
* ``signet plugins list`` (v0.1.6+) -- discover installed
  ``signet.checks`` / ``signet.adapters`` / ``signet.anchors``
  entry points and report load status (``loaded``,
  ``incompatible_abi``, ``load_error``).
* ``signet keys generate-ed25519`` -- fresh keypair for asymmetric
  receipt signing.
* ``signet lint`` -- static analysis on a pipeline file.
* ``signet bench`` (v0.1.8+) -- measure per-request pipeline
  overhead, decomposed by stage and check. Supports markdown / JSON /
  CSV output and a ``--gate p95=10ms`` flag for CI regression
  detection.

Built on click. Entry point ``signet`` is registered in
``pyproject.toml`` under ``[project.scripts]``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from signet import __version__

if TYPE_CHECKING:
    from signet.core.pipeline import Pipeline

logger = logging.getLogger("signet.cli")


# Round 7 MED/LOW: terminal-escape-injection defense. Several CLI surfaces
# echo bytes that ultimately come from a network peer (the upstream proxy
# being probed by ``signet doctor --self``, the contents of an audit row's
# ``metadata`` block surfaced by ``signet replay``, or a ``.env`` file in
# the operator's CWD picked up by ``_doctor_autodetect``). A malicious or
# compromised producer of those bytes can embed ANSI / OSC escape
# sequences (title-rewrite, screen-clear, OSC-52 clipboard write, OSC-8
# hyperlink phish, etc.) that a real terminal will interpret. We
# centralize the defense in one helper so every echo path uses the same
# replacement table.
_CONTROL_BYTE_REPLACEMENTS: dict[int, str] = {c: f"\\x{c:02x}" for c in range(0x20)} | {
    0x7F: "\\x7f"
}
# Tab is preserved -- it's the only sub-0x20 byte that is both common in
# legitimate values and harmless to a terminal renderer.
_CONTROL_BYTE_REPLACEMENTS.pop(0x09, None)
# Round 14 INFO: extend coverage beyond ASCII control bytes. The R13
# audit found four Unicode classes that pass through the ASCII-only
# translation table but render in modern terminals (xterm, Windows
# Terminal, VS Code integrated terminal):
#   - C1 controls (U+0080-U+009F): some terminals interpret these as
#     8-bit CSI / OSC equivalents over UTF-8 (CSI = U+009B as the 1-byte
#     equivalent of ``ESC [``), making ANSI sequences reachable without
#     an actual ESC byte.
#   - Bidirectional overrides (U+202A LRE, U+202B RLE, U+202C PDF,
#     U+202D LRO, U+202E RLO) and isolates (U+2066-U+2069): the "Trojan
#     Source" attack class (CVE-2021-42574, Boucher & Anderson 2021).
#     An attacker-supplied check_name like ``"safe<RLO>check"`` renders
#     as ``"safekcehc"`` and an audit reader sees a different identifier
#     than what is stored.
#   - Line / paragraph separators (U+2028, U+2029): rendered as line
#     breaks by terminals, which can split or hide adjacent content in
#     audit verify / tail / replay output.
#   - BOM / ZWNBSP (U+FEFF): a long-standing display-confusion vector.
# We render each as a textual ``\\uNNNN`` escape, consistent with how
# the ASCII control bytes already render as ``\\xNN``.
_UNICODE_CONTROL_CODEPOINTS: tuple[int, ...] = (
    *range(0x80, 0xA0),  # C1 controls
    *range(0x202A, 0x202F),  # bidi overrides (LRE, RLE, PDF, LRO, RLO)
    *range(0x2066, 0x206A),  # bidi isolates (LRI, RLI, FSI, PDI)
    0x2028,  # LINE SEPARATOR
    0x2029,  # PARAGRAPH SEPARATOR
    0xFEFF,  # ZWNBSP / BOM
)
for _cp in _UNICODE_CONTROL_CODEPOINTS:
    _CONTROL_BYTE_REPLACEMENTS[_cp] = f"\\u{_cp:04x}"
del _cp


def _sanitize_for_terminal(value: object) -> str:
    """Render *value* as a terminal-safe string.

    Replaces ASCII control bytes (< 0x20 except ``\\t``, plus 0x7f) with
    their ``\\xNN`` textual escape so a malicious upstream cannot inject
    ANSI / OSC sequences into the operator's terminal.

    Round 14 INFO: also escapes Unicode classes that pass through
    ASCII-only sanitization but render in modern terminals -- C1 controls
    (U+0080-U+009F), bidirectional overrides (U+202A-U+202E) and isolates
    (U+2066-U+2069), line / paragraph separators (U+2028 / U+2029), and
    BOM / ZWNBSP (U+FEFF). These close the Trojan Source (CVE-2021-42574)
    deception vector and the 8-bit-CSI / line-splice surfaces. They
    render as ``\\uNNNN`` text so an operator can still see the shape of
    the attacker-supplied bytes in the audit / replay output.

    Accepts any object; non-strings are coerced via ``str()`` first so
    callers can pass arbitrary metadata values straight through.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    # Round 29 MED (F-R29-1): use the unbound ``str.translate`` so a
    # hostile ``str``-subclass with an overridden ``translate`` cannot
    # crash or escape the sanitizer. Same pattern as R26-R28 helpers
    # (``str.__str__(value)``) -- the unbound method invokes the plain
    # ``str`` implementation regardless of subclass overrides.
    return str.translate(value, _CONTROL_BYTE_REPLACEMENTS)


# Round 14 INFO: reject Windows reserved device names at the CLI
# boundary. ``Path("CON").exists()`` returns True on Windows because the
# reserved names live in the Win32 namespace as character devices, which
# means Click's ``Path(exists=True, dir_okay=False)`` validator happily
# accepts ``CON``, ``NUL``, ``COM1``, etc. Real-world effects:
#   * ``signet audit count CON`` opens the console for read and the
#     iterator blocks indefinitely waiting for keyboard input.
#   * ``signet audit count NUL`` reports 0 entries silently.
#   * ``serve --audit-log COM1`` either fails opaquely or routes the
#     audit chain to a serial port.
# This is operator-driven, not a security boundary, but it's a UX foot-
# gun for any script that templates ``$LOG_PATH`` and substitutes a
# reserved name accidentally. We reject by matching the basename (sans
# extension, case-insensitive) against the reserved set.
_WINDOWS_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset(
    {"CON", "NUL", "PRN", "AUX"}
    | {f"COM{n}" for n in range(1, 10)}
    | {f"LPT{n}" for n in range(1, 10)}
)


def _is_windows_reserved_device_name(path: Path) -> bool:
    """Return True if *path*'s basename matches a Windows reserved
    device name (``CON``, ``NUL``, ``PRN``, ``AUX``, ``COM1``-``COM9``,
    ``LPT1``-``LPT9``).

    The check is platform-agnostic: we match on the path text alone so
    a POSIX deployment templating ``$LOG_PATH`` to ``CON`` also gets the
    same clear error. The candidate name is the basename with any
    extension stripped, upper-cased -- this matches the Win32 namespace
    behavior where ``CON.txt`` and ``CON`` alias the same device.

    Round 15 MED (F-R15-1): Win32 also normalizes basenames by stripping
    trailing spaces/tabs/dots BEFORE the namespace lookup, so
    ``"CON "`` (trailing space), ``"CON."``, ``"CON  "``, ``"CON .txt"``,
    etc. all route to the CON device. The R14 split-on-dot only
    stripped a single trailing dot via the ``split(".", 1)[0]`` shape
    (``"CON."`` -> ``"CON"`` happens to work); a trailing space or tab
    bypassed entirely. We now rstrip the basename of trailing
    ``" \\t."`` before the suffix split so every Win32-normalized form
    reaches the same reserved-name comparison.

    Round 23 LOW (F-R23-10): NTFS Alternate Data Stream syntax
    (``CON:streamname``) also routes to the CON device on Windows --
    the colon introduces the data-stream name, the head of the basename
    is still the device name. The R15 split on ``.`` did not split on
    ``:``, so a basename like ``"CON:foo"`` survived the reserved-name
    check intact. ``:`` is not a legitimate filename character on Windows
    (it's reserved for drive letters and ADS), so we reject any path
    whose basename contains ``:`` outright -- both ``CON:foo`` and the
    benign-looking ``stream:name`` route into the rejection path, which
    is the correct operator-facing behavior because either is going to
    surprise a caller that templated ``$LOG_PATH`` into the basename.
    POSIX deployments treat ``:`` as a legal filename character, but
    the check is platform-agnostic by design (see the function docstring):
    a CON-like basename should reject everywhere for predictable
    cross-platform script behavior.
    """
    basename = os.path.basename(str(path))
    if not basename:
        return False
    # Round 23 F-R23-10: a ``:`` in the basename is always either an NTFS
    # Alternate Data Stream reference (``CON:foo`` -> CON device) or a
    # drive-letter prefix that ``os.path.basename`` failed to strip.
    # Either way the basename is not a legitimate Windows filename --
    # reject the whole path so the reserved-name check is not bypassable
    # via the ADS shape.
    if ":" in basename:
        return True
    # Win32 strips trailing spaces / tabs / dots from the basename
    # before the namespace lookup. Mirror that normalization so e.g.
    # ``"CON "`` and ``"CON.txt"`` both reduce to ``"CON"`` for the
    # reserved-set check. We strip BOTH the full basename (covers
    # ``"CON "`` / ``"CON."``) AND the stem after the suffix split
    # (covers ``"CON .txt"`` / ``"NUL\t.log"``, where the trailing
    # whitespace sits between the stem and the extension and would
    # survive the first rstrip).
    basename = basename.rstrip(" \t.")
    if not basename:
        return False
    stem = basename.split(".", 1)[0].rstrip(" \t.")
    if not stem:
        return False
    return stem.upper() in _WINDOWS_RESERVED_DEVICE_NAMES


def _reject_windows_reserved_device_name(path: Path, *, kind: str = "audit log path") -> None:
    """Raise ``click.ClickException`` if *path* is a Windows reserved
    device name. Used by every CLI subcommand that writes to an
    operator-supplied output path.

    Round 17 MED (F-R17-1): the original wording named only "audit log
    path"; the helper is now also called for ``keys generate-ed25519
    --out`` and ``--public-out`` (where ``--out CON`` silently routed
    the private-key bytes to the console device). ``kind`` lets callers
    name the specific surface so the operator-facing message points at
    the right CLI option. The substring ``Windows reserved device name``
    is preserved verbatim for downstream regex / output assertions.
    """
    if _is_windows_reserved_device_name(path):
        raise click.ClickException(
            f"{kind} must be a regular file, not a Windows reserved "
            f"device name: {_sanitize_for_terminal(str(path))!r}"
        )


def _open_jsonl_backend(log_path: Path) -> Any:
    """Construct a :class:`JsonlBackend` and surface the Round 9 symlink
    guard as a clear :class:`click.ClickException` instead of a Python
    traceback. Used by every CLI subcommand that opens an audit log.

    Round 14 INFO: also rejects Windows reserved device names (CON, NUL,
    PRN, AUX, COM1-COM9, LPT1-LPT9) at the CLI boundary so
    ``signet audit count CON`` produces a clear ``ClickException``
    instead of hanging on a blocking console read.
    """
    from signet.audit.backend import AuditLogSymlinkError, JsonlBackend

    _reject_windows_reserved_device_name(log_path)
    try:
        return JsonlBackend(log_path)
    except AuditLogSymlinkError as exc:
        raise click.ClickException(_sanitize_for_terminal(exc)) from exc


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="signet")
def main() -> None:
    """signet -- capability-based safety gates for LLM agents."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )


@main.command()
@click.option(
    "--upstream",
    "upstream_url",
    required=True,
    envvar="SIGNET_UPSTREAM_URL",
    help="OpenAI-compatible upstream URL (e.g. http://localhost:11434/v1).",
)
@click.option(
    "--request-timeout",
    "request_timeout_s",
    type=float,
    default=None,
    envvar="SIGNET_REQUEST_TIMEOUT_S",
    help=(
        "Seconds to wait for an upstream response (default 120). Raise this "
        "when fronting a local reasoning model: a long single-shot generation "
        "returns nothing until it completes, so the whole run must fit inside "
        "this window or the gate reports ReadTimeout and the work is lost."
    ),
)
@click.option(
    "--host",
    default="127.0.0.1",
    envvar="SIGNET_HOST",
    show_default=True,
    help="Bind interface.",
)
@click.option(
    "--port",
    default=8443,
    # Round-4 NEW-9: clamp to the TCP port range so values like
    # ``--port 99999`` raise a click range error (exit 2) instead of an
    # OverflowError bubbling out of uvicorn's socket() call.
    type=click.IntRange(0, 65535),
    envvar="SIGNET_PORT",
    show_default=True,
    help="Bind port.",
)
@click.option(
    "--audit-log",
    "audit_log_path",
    type=click.Path(dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain (omit to disable persistent audit).",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    help="HMAC secret as hex (e.g. `openssl rand -hex 32`).",
)
@click.option(
    "--allow-ephemeral-key",
    is_flag=True,
    envvar="SIGNET_ALLOW_EPHEMERAL_KEY",
    help="Generate a temporary HMAC key on startup (DEV ONLY).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a Python file defining a `pipeline` variable. "
    "Without this, an open-by-default pipeline runs (no checks).",
)
@click.option(
    "--upstream-label",
    envvar="SIGNET_UPSTREAM_LABEL",
    default=None,
    help="Optional human-readable name for the upstream, surfaced in "
    "the X-Signet-Upstream response header so callers can finger-point "
    "upstream errors vs. signet errors. Defaults to a derivation of "
    "the upstream URL.",
)
@click.option(
    "--dev",
    "dev",
    is_flag=True,
    help="Bundle the dev defaults in one flag: --allow-ephemeral-key, "
    "--audit-log audit.jsonl, --config pipeline.py, "
    "--no-strict-error-redaction (so 4xx bodies surface check names + "
    "reasons during integration). Each is only set if not otherwise "
    "specified. Intended for local development only.",
)
@click.option(
    "--strict-error-redaction/--no-strict-error-redaction",
    "strict_error_redaction",
    default=None,
    envvar="SIGNET_STRICT_ERROR_REDACTION",
    help="Coarsen 4xx refusal bodies so they expose only "
    "{error, correlation_id} (default in production). Full detail "
    "remains in the audit chain -- incident response correlates via the "
    "ID. Disable to surface check name + reason in the response body, "
    "useful while integrating. --dev disables automatically.",
)
@click.option(
    "--shadow/--no-shadow",
    "shadow",
    default=None,
    envvar="SIGNET_SHADOW",
    help="Run in shadow mode: pipeline runs but block/escalate "
    "decisions become allow at the response layer. Audit chain "
    "and metrics still record the original decision; the response "
    "carries X-Signet-Shadow-* headers describing the would-be "
    "refusal and a correlation ID. Use to pilot enforcement.",
)
@click.option(
    "--log-format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    envvar="SIGNET_LOG_FORMAT",
    help="Output format for application logs. 'text' (default) is the "
    "human-readable plain logging format. 'json' emits one JSON object "
    "per line via structlog -- wire to your log aggregator (Loki, "
    "Datadog, ELK, etc.) for searchable structured logs.",
)
def serve(
    upstream_url: str,
    request_timeout_s: float | None,
    host: str,
    port: int,
    audit_log_path: Path | None,
    hmac_secret: str | None,
    allow_ephemeral_key: bool,
    config_path: Path | None,
    upstream_label: str | None,
    dev: bool,
    strict_error_redaction: bool | None,
    shadow: bool | None,
    log_format: str,
) -> None:
    """Run the signet proxy."""
    import uvicorn

    if log_format == "json":
        _configure_structlog_json()

    from signet.core.pipeline import Pipeline
    from signet.server.app import SignetApp
    from signet.server.config import ServerConfig

    # --dev shorthand: fill in the four obvious dev defaults if the
    # user did not pass them explicitly. This keeps the most common
    # local invocation down to `signet serve --upstream <url> --dev`.
    if dev:
        if not allow_ephemeral_key and not hmac_secret:
            allow_ephemeral_key = True
        if audit_log_path is None:
            audit_log_path = Path("audit.jsonl")
        if config_path is None and Path("pipeline.py").exists():
            config_path = Path("pipeline.py")
        if strict_error_redaction is None:
            # Surface full refusal detail during integration so the
            # operator can see *which* check fired without tailing audit
            # logs. Production should use the strict default.
            strict_error_redaction = False

    # Round 14 INFO: reject Windows reserved device names at the CLI
    # boundary so ``signet serve --audit-log CON`` produces a clear error
    # instead of routing the audit chain at the console / null device.
    # Done after the ``--dev`` defaulting so a stray ``CON`` from the
    # environment still trips the guard.
    if audit_log_path is not None:
        _reject_windows_reserved_device_name(audit_log_path)

    # Load pipeline from config file or use empty one.
    if config_path:
        click.secho(
            f"warning: --config executes arbitrary Python from {config_path}. "
            "Only run with config files you control.",
            err=True,
            fg="yellow",
        )
        pipeline = _load_pipeline_from_path(config_path)
    else:
        click.echo(
            "warning: no --config provided; running with an empty pipeline (no checks).",
            err=True,
        )
        pipeline = Pipeline(checks=[])

    cfg = ServerConfig(
        upstream_url=upstream_url,
        host=host,
        port=port,
        audit_log_path=audit_log_path,
        hmac_secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET")
        if hmac_secret
        else None,
        allow_ephemeral_key=allow_ephemeral_key,
        upstream_label=upstream_label,
        # Omitted -> keep the dataclass default (120s). Passing None here
        # would fail the numeric validator.
        **({"request_timeout_s": request_timeout_s} if request_timeout_s is not None else {}),
    )
    # CLI flag wins over the dataclass default (True), and over
    # SIGNET_STRICT_ERROR_REDACTION's env-driven value if both are set.
    if strict_error_redaction is not None:
        cfg.strict_error_redaction = strict_error_redaction
    if shadow is not None:
        cfg.shadow = shadow

    # Round 9 LOW: surface the audit-log symlink guard as a clear
    # ClickException instead of letting the AuditLogSymlinkError bubble
    # out as a Python traceback.
    from signet.audit.backend import AuditLogSymlinkError

    try:
        signet_app = SignetApp(config=cfg, pipeline=pipeline)
    except AuditLogSymlinkError as exc:
        raise click.ClickException(_sanitize_for_terminal(exc)) from exc
    app = signet_app.app
    # ASCII arrow (-> not unicode) so the banner renders on Windows
    # cp1252 stdout without UnicodeEncodeError.
    # Round 9 MED: ``upstream_url`` is env-derived (or CLI-supplied) and
    # the banner stays in scrollback. Even if config validation now
    # restricts schemes, control bytes can still appear in the URL
    # query/path portion -- sanitize before echo.
    click.echo(
        f"signet {__version__} -> {_sanitize_for_terminal(upstream_url)}  "
        f"(listening on {host}:{port})"
    )

    # If we generated an ephemeral key, print it as hex so the user can
    # save it for post-mortem `signet audit verify`. Otherwise the audit
    # log we just spent the run building is unverifiable forever.
    if allow_ephemeral_key and not hmac_secret:
        ephemeral_hex = signet_app._keyring.active.secret.hex()
        click.secho(
            "EPHEMERAL HMAC KEY (save this if you want to verify the audit log later):",
            err=True,
            fg="yellow",
        )
        click.secho(f"  {ephemeral_hex}", err=True, fg="yellow")
        click.secho(
            "  (will be lost on restart; set SIGNET_HMAC_SECRET for production)",
            err=True,
            fg="yellow",
        )

    # Print loaded checks so operators can verify the configuration
    # without re-reading the file. Quiet on the empty-pipeline path
    # since the warning above is already loud about it.
    #
    # Round 11 LOW: ``c.name`` is a class attribute on each Check; a
    # hostile plugin (entry-point group ``signet.checks``) that the
    # operator wires into pipeline.py can declare a ``name`` carrying
    # OSC / control bytes. Sanitize for parity with Round 10's plugins
    # list / plugins doctor surfaces. ``c.stage.value`` is a ``Stage``
    # enum member and safe.
    if pipeline.checks:
        click.echo(f"pipeline ({len(pipeline.checks)} checks):")
        for c in pipeline.checks:
            click.echo(f"  [{c.stage.value}] {_sanitize_for_terminal(c.name)}")

    uvicorn.run(app, host=host, port=port, log_level="info")


@main.group()
def keys() -> None:
    """Cryptographic key management commands."""


@keys.command("generate-ed25519")
@click.option(
    "--out",
    "out_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path to write the PEM-encoded ed25519 private key. "
    "File mode is set to 0600 (owner read/write only) where supported.",
)
@click.option(
    "--public-out",
    "public_out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to write the matching public key. Defaults to "
    "<--out>.pub if not specified.",
)
@click.option(
    "--key-id",
    default=None,
    help="Optional key identifier to print alongside the public key for "
    "convenience. Not embedded in the key files themselves. If --key-id "
    "is provided, a sidecar <out>.meta.json is written so the binding "
    "survives terminal close.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite the output files if they already exist.",
)
def keys_generate_ed25519(
    out_path: Path,
    public_out_path: Path | None,
    key_id: str | None,
    force: bool,
) -> None:
    """Generate a fresh ed25519 keypair for asymmetric receipt signing.

    The private key goes to ``--out`` (chmod 0600). The matching public
    key goes to ``<--out>.pub`` by default, or to ``--public-out`` if
    you want them in different locations. The public key is what you
    share with verifiers -- they cannot forge receipts with it.

    Requires ``pip install signet-sign[ed25519]``.
    """
    # Round 9 LOW: reject ``--key-id`` that contains ASCII control bytes
    # at parse time. A key-id with control bytes is a misconfiguration
    # regardless of intent: it cannot be safely pasted into source code
    # (the "copy this into your code" output below is exactly that
    # surface), and it would invisibly mismatch a verifier reading the
    # printable form. Defense in depth -- the three echo sites also
    # sanitize, so a key-id that somehow slips through still renders
    # safely.
    #
    # Round 15 LOW (F-R15-3): the R9 check refused only ASCII control
    # bytes (< 0x20 or 0x7F). R14 extended ``_sanitize_for_terminal``
    # to cover C1 controls, bidi overrides/isolates, LSEP/PSEP, and
    # BOM, but the parse-time guard did not match that wider set. A
    # ``--key-id "‮hacked"`` would pass the parse check and only get
    # neutralized at echo time. The fix tightens the parse-time guard
    # to a strict allowlist: key IDs in practice are short ASCII
    # identifiers (``prod-2024-01``, ``kms-rotated-foo``), so the
    # ``[A-Za-z0-9_.:\-]+`` charset is more than enough. Rejecting
    # Unicode at the parser is cleaner than depending on the echo-site
    # sanitizer, and removes any ambiguity about what a "key id" can
    # contain in operator pipelines.
    # Round 17 MED (F-R17-1): reject Windows reserved device names on
    # both ``--out`` and ``--public-out`` at parse time. Same guard
    # class as the R14/R15 audit-log surface
    # (``_reject_windows_reserved_device_name``) -- a bare ``CON`` /
    # ``NUL`` / ``COM1`` basename routes the ``write_bytes`` call to
    # the Win32 console / null device and silently consumes the PEM-
    # encoded private key. The CLI would otherwise report success while
    # only the ``.pub`` file was actually persisted (the ``.pub``
    # suffix breaks the device-name match). Operators who share the
    # orphaned public key with verifiers cannot produce matching
    # signatures.
    _reject_windows_reserved_device_name(out_path, kind="--out")
    if public_out_path is not None:
        _reject_windows_reserved_device_name(public_out_path, kind="--public-out")
    if key_id is not None:
        # Round 9 / R15 / R23: charset validation extracted into
        # ``_validate_key_id_charset`` (single source of truth shared
        # across every ``--key-id`` flag site).
        _validate_key_id_charset(key_id, source="--key-id")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise click.ClickException(
            "ed25519 key generation requires the cryptography package. "
            "Install with: pip install signet-sign[ed25519]"
        ) from exc

    if public_out_path is None:
        public_out_path = out_path.with_suffix(out_path.suffix + ".pub")

    for p in (out_path, public_out_path):
        if p.exists() and not force:
            raise click.ClickException(
                f"refusing to overwrite existing file {p}; pass --force to override"
            )

    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    out_path.write_bytes(priv_pem)
    public_out_path.write_bytes(pub_pem)

    # Best-effort 0600 on POSIX. Windows ACLs differ -- operator should
    # configure permissions through their normal IAM tooling.
    import contextlib
    import os

    if hasattr(os, "chmod"):
        with contextlib.suppress(OSError):
            os.chmod(out_path, 0o600)

    click.secho(f"  wrote private key:  {out_path} (chmod 0600 attempted)", fg="green")
    click.secho(f"  wrote public key:   {public_out_path}", fg="green")
    # C9 (v0.1.7): when --key-id is supplied, write a sidecar
    # ``<out>.meta.json`` so the operator does not lose the
    # key-id-to-key binding the moment they close their terminal.
    # The PEM file itself stays bit-identical to a no-key-id run --
    # the sidecar is purely metadata.
    if key_id:
        from datetime import UTC, datetime

        meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
        meta = {
            "key_id": key_id,
            "generated_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
            "signet_version": __version__,
        }
        meta_path.write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        click.secho(f"  wrote key metadata: {meta_path}", fg="green")
        # Round 9 LOW: key_id is rejected at parse-time if it contains
        # control bytes, but sanitize at every echo for defense in depth.
        click.echo(f"\nkey_id (record this; verifiers need it): {_sanitize_for_terminal(key_id)}")
    click.echo("\nNext: configure signet with this key for asymmetric receipts.")
    # C4 (v0.1.7): emit Python's safe ``repr()`` of the path so Windows
    # backslashes (``D:\tmp\priv.pem``) are properly escaped. Previously
    # we wrapped the path in double quotes and let click format it,
    # which produced ``"D:\tmp\priv.pem"`` -- pasting that into Python
    # interprets ``\t`` as a tab and ``\p`` as an invalid escape.
    # ``repr(str(path))`` produces ``'D:\\tmp\\priv.pem'`` (or just
    # ``'/tmp/priv.pem'`` on POSIX), which always parses cleanly.
    out_repr = repr(str(out_path))
    public_repr = repr(str(public_out_path))
    # Round 9 LOW: sanitize the key-id value rendered in the "paste this
    # into source code" template. Parse-time validation already refuses
    # control bytes; this is defense in depth.
    key_id_value = _sanitize_for_terminal(key_id) if key_id else "REPLACE_ME"
    click.echo(
        "  In your pipeline / app code:\n"
        "    from signet.server.receipt import Ed25519ReceiptSigner\n"
        f"    signer = Ed25519ReceiptSigner.from_pem(\n"
        f"        private_pem_path={out_repr},\n"
        f'        key_id="{key_id_value}",\n'
        "    )\n"
        "    SignetApp(config=cfg, pipeline=pipeline, receipt_signer=signer)"
    )
    click.echo(
        "\n  Share the public key with verifiers. They construct a verify-only signer:\n"
        "    Ed25519ReceiptSigner.from_pem(\n"
        f"        public_pem_path={public_repr},\n"
        f'        key_id="{key_id_value}",\n'
        "    )"
    )


@keys.command("generate-mldsa")
@click.option(
    "--out",
    "out_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path to write the raw ML-DSA-65 private key (4032 bytes). "
    "File mode is set to 0600 where supported.",
)
@click.option(
    "--public-out",
    "public_out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path for the matching public key (1952 bytes). Defaults to <--out>.pub if not specified.",
)
@click.option(
    "--key-id",
    default=None,
    help="Optional key identifier. If provided, a sidecar <out>.meta.json records the binding.",
)
@click.option("--force", is_flag=True, help="Overwrite output files if they exist.")
def keys_generate_mldsa(
    out_path: Path,
    public_out_path: Path | None,
    key_id: str | None,
    force: bool,
) -> None:
    """Generate a post-quantum ML-DSA-65 (FIPS 204) keypair.

    The lattice-based counterpart to ``generate-ed25519`` for receipts
    that must resist a future quantum adversary. Keys are RAW bytes (no
    standard PEM OID for ML-DSA yet): private 4032 bytes, public 1952
    bytes. Share the public key with verifiers; they cannot forge.

    EXPERIMENTAL. Requires ``pip install signet-sign[pq]``.
    """
    _reject_windows_reserved_device_name(out_path, kind="--out")
    if public_out_path is not None:
        _reject_windows_reserved_device_name(public_out_path, kind="--public-out")
    if key_id is not None:
        _validate_key_id_charset(key_id, source="--key-id")

    try:
        from signet.server.receipt import _load_mldsa_backend

        backend = _load_mldsa_backend()
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc

    if public_out_path is None:
        public_out_path = out_path.with_suffix(out_path.suffix + ".pub")
    for p in (out_path, public_out_path):
        if p.exists() and not force:
            raise click.ClickException(
                f"refusing to overwrite existing file {p}; pass --force to override"
            )

    public_key, private_key = backend.keygen()
    out_path.write_bytes(private_key)
    public_out_path.write_bytes(public_key)

    import contextlib
    import os

    if hasattr(os, "chmod"):
        with contextlib.suppress(OSError):
            os.chmod(out_path, 0o600)

    click.secho(f"  wrote private key:  {out_path} (chmod 0600 attempted)", fg="green")
    click.secho(f"  wrote public key:   {public_out_path}", fg="green")
    if key_id:
        from datetime import UTC, datetime

        meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
        meta_path.write_text(
            json.dumps(
                {
                    "key_id": key_id,
                    "alg": "ml-dsa-65",
                    "generated_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
                    "signet_version": __version__,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        click.secho(f"  wrote key metadata: {meta_path}", fg="green")
        click.echo(f"\nkey_id (record this; verifiers need it): {_sanitize_for_terminal(key_id)}")
    out_repr = repr(str(out_path))
    public_repr = repr(str(public_out_path))
    key_id_value = _sanitize_for_terminal(key_id) if key_id else "REPLACE_ME"
    click.echo(
        "\n  In your pipeline / app code (a signer loads BOTH key files --\n"
        "  ML-DSA cannot re-derive the public key from the private one):\n"
        "    from signet.server.receipt import MLDSAReceiptSigner\n"
        "    signer = MLDSAReceiptSigner.from_files(\n"
        f"        private_key_path={out_repr},\n"
        f"        public_key_path={public_repr},\n"
        f'        key_id="{key_id_value}",\n'
        "    )\n"
        "    SignetApp(config=cfg, pipeline=pipeline, receipt_signer=signer)"
    )
    click.echo(
        "\n  Verifiers construct a verify-only signer from the public key:\n"
        "    MLDSAReceiptSigner.from_files(\n"
        f"        public_key_path={public_repr},\n"
        f'        key_id="{key_id_value}",\n'
        "    )"
    )


@main.command()
@click.option(
    "--upstream",
    "upstream_url",
    envvar="SIGNET_UPSTREAM_URL",
    help="OpenAI-compatible upstream URL to probe for reachability.",
)
@click.option(
    "--self",
    "signet_url",
    default=None,
    help="signet proxy URL to probe for /health, /version, and a "
    "no-owner refusal round-trip. Use this to verify a running proxy "
    "against the gate's documented behavior.",
)
@click.option(
    "--probe-injection",
    "probe_injection",
    is_flag=True,
    help="Send a corpus of obfuscated injection attempts to --self "
    "and assert every one is blocked. Catches 'someone "
    "mis-edited the rule list and the prompt-injection check "
    "stopped firing' regressions in CI.",
)
def doctor(
    upstream_url: str | None,
    signet_url: str | None,
    probe_injection: bool,
) -> None:
    """Preflight check -- is everything wired the way you think?

    Always prints versions and dependency status. With ``--upstream``,
    probes the upstream LLM endpoint. With ``--self``, probes a running
    signet proxy: hits /health, /version, and sends a no-owner POST
    that should come back 403 (proving the gate is enforcing). Neither
    flag is required; pass what you have.

    Auto-detection: when ``pipeline.py`` is present in the current
    directory (the layout produced by ``signet init``), doctor will
    pick up ``SIGNET_UPSTREAM_URL`` from a sibling ``.env`` /
    ``.env.example`` if ``--upstream`` was not supplied, and default
    ``--self`` to ``http://127.0.0.1:8443`` if that flag was also
    omitted. Mirrors the convenience that ``serve --dev`` already has.

    Exit code is 0 on success, 1 if any probe failed.
    """
    import platform

    import httpx

    failed = False

    upstream_url, signet_url = _doctor_autodetect(upstream_url, signet_url)

    click.echo(f"signet         {__version__}")
    click.echo(f"python         {platform.python_version()} ({platform.system()})")
    click.echo(f"httpx          {httpx.__version__}")

    try:
        import fastapi

        click.echo(f"fastapi        {fastapi.__version__}")
    except ImportError:  # pragma: no cover -- installed by core deps
        click.secho("fastapi        MISSING (broken install)", fg="red")
        failed = True

    if upstream_url:
        # Round 7 LOW: ``upstream_url`` can come from a hostile ``.env``
        # picked up by ``_doctor_autodetect``, and httpx's exceptions
        # echo the URL bytes back to us verbatim. Sanitize both surfaces.
        click.echo(f"\nprobing upstream: {_sanitize_for_terminal(upstream_url)}")
        try:
            resp = httpx.get(
                upstream_url.rstrip("/") + "/models", timeout=5.0, follow_redirects=True
            )
            if resp.status_code < 500:
                click.secho(f"  upstream reachable (HTTP {resp.status_code})", fg="green")
            else:
                click.secho(f"  upstream returned HTTP {resp.status_code}", fg="yellow")
        except httpx.HTTPError as exc:
            click.secho(
                f"  upstream unreachable: {type(exc).__name__}: {_sanitize_for_terminal(exc)}",
                fg="red",
            )
            failed = True
        except httpx.InvalidURL as exc:  # pragma: no cover -- defense in depth
            click.secho(
                f"  upstream URL rejected: {_sanitize_for_terminal(exc)}",
                fg="red",
            )
            failed = True

    if signet_url:
        click.echo(f"\nprobing signet:   {_sanitize_for_terminal(signet_url)}")
        base = signet_url.rstrip("/")
        try:
            health = httpx.get(f"{base}/health", timeout=5.0)
            if health.status_code == 200 and health.json().get("status") == "ok":
                click.secho("  /health         ok", fg="green")
            else:
                click.secho(f"  /health         unexpected ({health.status_code})", fg="red")
                failed = True
        except httpx.HTTPError as exc:
            click.secho(
                f"  /health         unreachable: {_sanitize_for_terminal(exc)}",
                fg="red",
            )
            failed = True
            # Fall through to the rest of the doctor flow -- each
            # subsequent probe will surface its own failure and the
            # final ``sys.exit(1 if failed else 0)`` reports the
            # overall status. Previously a stray ``return`` here exited
            # the function before ``sys.exit(...)`` could fire, so
            # ``signet doctor --self <down>`` exited 0 despite the red
            # banner.

        try:
            ver = httpx.get(f"{base}/version", timeout=5.0).json()
            # Round 7 MED: sanitize the upstream-supplied version string
            # before echo so a malicious peer cannot inject terminal
            # escape sequences via the JSON response body.
            ver_str = (
                _sanitize_for_terminal(ver.get("version", "?")) if isinstance(ver, dict) else "?"
            )
            click.secho(f"  /version        signet {ver_str}", fg="green")
        except httpx.HTTPError as exc:
            click.secho(
                f"  /version        unreachable: {_sanitize_for_terminal(exc)}",
                fg="red",
            )
            failed = True

        # No-owner probe: should be refused if OwnerResolutionCheck is
        # configured. If it succeeds, the operator is running with no
        # owner enforcement (open-by-default). Either is honest output.
        try:
            no_owner = httpx.post(
                f"{base}/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
                timeout=5.0,
            )
            if no_owner.status_code == 403:
                click.secho("  no-owner probe  refused (gate is enforcing)", fg="green")
            elif no_owner.status_code == 202:
                click.secho(
                    "  no-owner probe  escalated (gate is enforcing via escalation)",
                    fg="green",
                )
            else:
                click.secho(
                    f"  no-owner probe  HTTP {no_owner.status_code} -- gate is "
                    "OPEN (no owner enforcement). Add OwnerResolutionCheck "
                    "to your pipeline.",
                    fg="yellow",
                )
        except httpx.HTTPError as exc:
            # Round 9 MED: httpx error text echoes the URL bytes; the
            # URL can come from a hostile env-derived
            # ``SIGNET_UPSTREAM_URL``. Sanitize to match the pattern
            # Round 8 applied to the other three httpx.HTTPError sites
            # in this function.
            click.secho(
                f"  no-owner probe  errored: {_sanitize_for_terminal(exc)}",
                fg="red",
            )
            failed = True

        # F-R5-B: probe-corpus drift detection. A stale signet install on
        # the operator's machine ships fewer (or different) probes than
        # the current canonical set, so ``--probe-injection`` would
        # under-test the running proxy. Emit a yellow WARN -- not a
        # failure -- so CI doesn't turn red on every minor-version skew,
        # but the operator knows to upgrade.
        drift = _check_probe_corpus_drift()
        if drift is not None:
            click.secho(f"  probe corpus    WARN: {drift}", fg="yellow")

    if not upstream_url and not signet_url:
        click.echo("\n(pass --upstream <url> and/or --self <url> to probe endpoints)")

    if probe_injection:
        if not signet_url:
            click.secho(
                "  --probe-injection requires --self <url>; the corpus must "
                "be sent against a running signet proxy.",
                fg="red",
            )
            sys.exit(1)
        probe_failed = _run_probe_injection_corpus(signet_url)
        if probe_failed:
            failed = True

    sys.exit(1 if failed else 0)


#: F-R5-B: canonical probe IDs the current signet release ships. Keep in
#: sync with :data:`signet.cli_helpers.probe_injection_corpus.PROMPT_INJECTION_PROBE_CORPUS`.
#: This list is the ground truth the doctor checks the installed corpus
#: against -- if a downgraded install has fewer entries (e.g., 21 instead
#: of 23), the doctor warns rather than silently under-testing.
#:
#: R9 expansion: the original 23-entry baseline (R7 + Round-8 follow-ons)
#: grew to 44 with the nested-base64 / depth-3 polyglot / base32hex /
#: base36 / base58 / base62 / MIME-base64-with-newlines /
#: hex-with-separators / Greek-cluster / cipher-overlay (reverse / atbash /
#: Caesar-N) / gzip-url-percent / markdown-split / backslash-split /
#: Punycode / quoted-printable additions.
_CANONICAL_PROBE_IDS: tuple[str, ...] = (
    "plain_ignore_previous",
    "cyrillic_confusable",
    "stretched_whitespace",
    "zero_width_inserts",
    "base64_encoded",
    "rot13_encoded",
    "base32_encoded",
    "hex_encoded",
    "dan_persona_attack",
    "rot13_english_prefix_bypass",
    "truncation_tail_bypass",
    "base64_unpadded_bypass",
    "base32_lowercase_bypass",
    "base85_bypass",
    "ascii85_bypass",
    "url_percent_bypass",
    "html_decimal_entity_bypass",
    "html_hex_entity_bypass",
    "unicode_escape_bypass",
    "b64_rot13_polyglot_bypass",
    "rot13_b64_polyglot_bypass",
    "gzip_hex_bypass",
    "zlib_b64_bypass",
    # R9 additions (data-only sync; the corpus IDs are the source of truth).
    "nested_b64_depth2_bypass",
    "nested_b64_depth3_bypass",
    "b64_rot13_b64_polyglot_bypass",
    "b85_b64_rot13_polyglot_bypass",
    "rot13_b85_b64_polyglot_bypass",
    "base32hex_bypass",
    "base36_bypass",
    "base58_bypass",
    "base62_bypass",
    "mime_base64_newlines_bypass",
    "hex_spaced_bypass",
    "hex_0x_commas_bypass",
    "greek_cluster_homoglyph_bypass",
    "reverse_string_bypass",
    "atbash_bypass",
    "caesar_5_bypass",
    "gzip_url_percent_bypass",
    "markdown_emphasis_bypass",
    "backslash_split_bypass",
    "punycode_bypass",
    "quoted_printable_bypass",
    # R11 additions (F-R11-1 byte-budget exhaustion, F-R11-2 ES6 curly-
    # brace escapes, F-R11-3 depth-4+, F-R11-4 non-Latin homoglyphs).
    # Data-only sync — the canonical source of truth is the corpus
    # module; the doctor uses this list only for the install-drift check.
    "byte_budget_exhaustion_bypass",
    "es6_curly_brace_escape_bypass",
    "es6_x_curly_brace_escape_bypass",
    "b64_depth_4_bypass",
    "b64_depth_7_bypass",
    "non_latin_homoglyph_bypass",
    # R13 additions (F-R13-1 per-depth budget tier-0/1, F-R13-2 depth
    # 9+, F-R13-3 missing Latin confusables, F-R13-4 UUencode channel,
    # F-R13-5 reverse-then-b64 cipher overlay). Same data-only sync
    # contract as the R9/R11 blocks above.
    "byte_budget_exhaustion_100k_bypass",
    "b64_depth_12_bypass",
    "latin_iota_homoglyph_bypass",
    "latin_polyglot_homoglyph_bypass",
    "uuencode_bypass",
    "reverse_then_b64_bypass",
    "atbash_then_b64_bypass",
    # R16 additions (F-R14-5 missing confusables documented in R13,
    # F-R14-6 jailbreak-keyword). Same data-only sync contract as
    # the earlier blocks above — the corpus module is the source of
    # truth; this list exists only for the install-drift check.
    "devanagari_zero_homoglyph_bypass",
    "greek_lambda_homoglyph_bypass",
    "jailbreak_standalone_bypass",
    # R18 additions (P0 boundary-bypass closure, MED jailbreak space-
    # split, MED decimal-codepoint channel, HIGH lowercase Greek
    # confusables). Same data-only sync contract as earlier rounds.
    "boundary_bypass_ignore_glued",
    "boundary_bypass_disregard_glued",
    "boundary_bypass_forget_glued",
    "boundary_bypass_jailbreak_glued",
    "boundary_bypass_developer_mode_glued",
    "boundary_bypass_no_restrictions_glued",
    "jailbreak_space_split_bypass",
    "jailbreak_hyphen_split_bypass",
    "decimal_codepoint_space_bypass",
    "decimal_codepoint_comma_bypass",
    "lowercase_greek_sigma_homoglyph_bypass",
    "lowercase_greek_omega_homoglyph_bypass",
)


def _check_probe_corpus_drift() -> str | None:
    """Return a human-readable drift message, or ``None`` if the corpus is
    aligned with :data:`_CANONICAL_PROBE_IDS`.

    Compares the installed corpus length and entry ``name`` set against
    the canonical set. The doctor surfaces the result as a yellow WARN
    line; this is a stale-install signal, not a broken-install failure,
    so the doctor does NOT exit non-zero on drift.
    """
    from signet.cli_helpers.probe_injection_corpus import (
        PROMPT_INJECTION_PROBE_CORPUS,
    )

    canonical = set(_CANONICAL_PROBE_IDS)
    installed_ids = {probe.name for probe in PROMPT_INJECTION_PROBE_CORPUS}
    installed_count = len(PROMPT_INJECTION_PROBE_CORPUS)
    canonical_count = len(_CANONICAL_PROBE_IDS)

    if installed_count == canonical_count and installed_ids == canonical:
        return None

    missing = sorted(canonical - installed_ids)
    extra = sorted(installed_ids - canonical)
    parts = [f"probe corpus has {installed_count} entries, expected {canonical_count}"]
    if missing:
        parts.append(f"missing: {', '.join(missing)}")
    if extra:
        parts.append(f"unexpected: {', '.join(extra)}")
    parts.append("your signet install may be stale.")
    return "; ".join(parts)


def _run_probe_injection_corpus(signet_url: str) -> bool:
    """Send every probe in :data:`PROMPT_INJECTION_PROBE_CORPUS` and
    assert every one is refused.

    Returns ``True`` if any probe leaked through (gate failure),
    ``False`` if every probe was correctly blocked.

    Each probe is sent as an OpenAI-shaped chat-completion to
    ``<signet_url>/v1/chat/completions`` with a default
    ``X-Commit-Owner: human:doctor-probe`` header so OwnerResolutionCheck
    doesn't fire first. A successful probe sees one of:

    * HTTP 403 -- strict-error-redaction default refusal.
    * HTTP 202 -- escalation path (still a refusal at the response
      layer).
    * HTTP 200 with ``X-Signet-Shadow-Decision: block`` -- shadow mode
      on the target.

    Any 200 without a shadow-block header counts as a leak.
    """
    import httpx

    from signet.cli_helpers.probe_injection_corpus import (
        PROMPT_INJECTION_PROBE_CORPUS,
    )

    base = signet_url.rstrip("/")
    click.echo(f"\nprobing prompt-injection corpus against: {base}")
    click.echo(f"  ({len(PROMPT_INJECTION_PROBE_CORPUS)} probes)")
    leaked = False
    # v0.1.7 F3: when EVERY probe leaks with a plain HTTP 200 (no
    # shadow decision, no refusal), the most likely cause is that the
    # operator's pipeline does not register PromptInjectionCheck. Track
    # the leak shape so we can give an actionable hint instead of a
    # red wall of "LEAKED" lines.
    plain_200_leaks = 0
    total_probes = len(PROMPT_INJECTION_PROBE_CORPUS)

    for probe in PROMPT_INJECTION_PROBE_CORPUS:
        try:
            resp = httpx.post(
                f"{base}/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    # Pre-resolved owner so OwnerResolutionCheck does not
                    # fire first and shadow our intended target check.
                    "X-Commit-Owner": "human:doctor-probe",
                },
                json={
                    "model": "test",
                    "messages": [
                        {"role": "user", "content": probe.payload},
                    ],
                },
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            click.secho(
                f"  [{probe.name:<24}] errored: {type(exc).__name__}: "
                f"{_sanitize_for_terminal(exc)}",
                fg="red",
            )
            leaked = True
            continue

        # Decide pass/fail. The "shadow-mode block" path is the only
        # case where 200 is acceptable.
        #
        # Round 7 MED: ``shadow_decision`` and ``firing_check`` are both
        # supplied by the proxy being probed; if that proxy is a hostile
        # impostor it may try to embed ANSI / OSC escape sequences in
        # those values. Sanitize before interpolation.
        shadow_decision = _sanitize_for_terminal(resp.headers.get("X-Signet-Shadow-Decision", ""))
        firing_check = _probe_firing_check(resp)
        if resp.status_code == 403 or resp.status_code == 202:
            click.secho(
                f"  [{probe.name:<24}] refused HTTP {resp.status_code} "
                f"(check={firing_check or 'redacted'})",
                fg="green",
            )
        elif resp.status_code == 200 and shadow_decision == "block":
            click.secho(
                f"  [{probe.name:<24}] shadow-blocked (check={firing_check or 'redacted'})",
                fg="green",
            )
        else:
            click.secho(
                f"  [{probe.name:<24}] LEAKED HTTP {resp.status_code} "
                f"(expected refusal; shadow_decision={shadow_decision!r})",
                fg="red",
            )
            leaked = True
            if resp.status_code == 200 and not shadow_decision:
                plain_200_leaks += 1

    if leaked:
        click.secho("\n  prompt-injection probe: FAIL (gate let one through)", fg="red")
        # F3 hint: if every probe came back as a plain HTTP 200 with no
        # shadow decision, the pipeline almost certainly has no
        # PromptInjectionCheck registered. Tell the operator how to fix
        # it, instead of leaving them with N red "LEAKED" lines and no
        # next step.
        if plain_200_leaks == total_probes and total_probes > 0:
            click.secho(
                "\n  hint: every probe returned plain HTTP 200 with no "
                "X-Signet-Shadow-Decision header. The proxy at "
                f"{base} likely has no PromptInjectionCheck in its "
                "pipeline; the probes pass straight through to the "
                "upstream. Add ``PromptInjectionCheck()`` to your "
                "pipeline.py (ADMISSION stage) and restart `signet "
                "serve`. The default scaffold from ``signet init`` "
                "includes this check; only hand-written pipelines miss it.",
                fg="yellow",
            )
    else:
        click.secho("\n  prompt-injection probe: ok (all probes blocked)", fg="green")
    return leaked


def _probe_firing_check(resp: Any) -> str | None:
    """Best-effort extraction of the firing check name from a refusal.

    Looks first at the ``X-Signet-Shadow-Decision-Check`` header
    (shadow mode), then at the response JSON body's ``check`` field
    (only populated when ``--no-strict-error-redaction`` is on the
    target). Returns ``None`` when neither channel surfaces it.

    Round 7 MED: the returned value is interpolated into terminal
    output by the doctor's ``--probe-injection`` flow, so we sanitize
    ASCII control bytes here -- a hostile proxy could otherwise embed
    escape sequences in either channel.
    """
    name = resp.headers.get("X-Signet-Shadow-Decision-Check")
    if name:
        return _sanitize_for_terminal(name)
    try:
        body = resp.json()
    except (ValueError, AttributeError):
        return None
    if isinstance(body, dict):
        check = body.get("check") or body.get("firing_check")
        if isinstance(check, str):
            return _sanitize_for_terminal(check)
    return None


@main.group()
def audit() -> None:
    """Audit-chain operations."""


@audit.command("verify")
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    required=True,
    help="HMAC secret as hex (the same one used to write the chain).",
)
@click.option(
    "--key-id",
    "key_id",
    default="k1",
    show_default=True,
    envvar="SIGNET_HMAC_KEY_ID",
    help="ID of the active key. Match the writer's --hmac-key-id.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of colored text. Use this "
    "from cron jobs, CI checks, and any scripted invocation.",
)
@click.option(
    "--including-archives",
    "archive_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Walk the live chain plus every referenced compaction archive "
    "as one logical chain. Recomputes Merkle roots and reports "
    "MERKLE_MISMATCH / ARCHIVE_MISSING / ARCHIVE_FORMAT_INVALID.",
)
@click.option(
    "--summarize-cascades",
    is_flag=True,
    help="Collapse cascading link_mismatch breaks downstream of a "
    "single tamper into one CASCADE_SUPPRESSED summary break. Useful "
    "for keeping large-chain reports readable when one forgery would "
    "otherwise surface as N+ link breaks. Mirrors the verifier's "
    "compact_breaks parameter (A11).",
)
def audit_verify(
    log_path: Path,
    hmac_secret: str,
    key_id: str,
    as_json: bool,
    archive_dir: Path | None,
    summarize_cascades: bool,
) -> None:
    """Walk LOG_PATH and report any tampering."""
    # Round 23 LOW (F-R23-9): charset validation, mirroring
    # ``keys generate-ed25519``. ``--key-id`` (or ``SIGNET_HMAC_KEY_ID``)
    # is plumbed straight into operator-facing banners and the integrity
    # message body, so the same strict ASCII allowlist applies.
    _validate_key_id_charset(key_id, source="--key-id/SIGNET_HMAC_KEY_ID")
    from signet.audit.backend import MalformedAuditEntry
    from signet.audit.keyring import Key, KeyRing
    from signet.audit.verifier import ChainVerifier, verify_with_archives

    keyring = KeyRing(
        active=Key(
            key_id=key_id,
            secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
        )
    )
    backend = _open_jsonl_backend(log_path)
    try:
        if archive_dir is None:
            report = ChainVerifier(backend, keyring, compact_breaks=summarize_cascades).verify()
        else:
            report = verify_with_archives(
                backend,
                keyring,
                archive_dir,
                compact_breaks=summarize_cascades,
            )
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    if as_json:
        # A13 (v0.1.7): surface ``signet_version`` and ``verified_at``
        # from the VerificationReport dataclass so a stored JSON report
        # is self-describing for long-term forensics. The dataclass
        # already populates both via default factories (see
        # signet.audit.verifier.VerificationReport); the CLI just has
        # to pass them through.
        payload = {
            "ok": report.ok,
            "signet_version": report.signet_version,
            "verified_at": report.verified_at,
            "total_entries": report.total_entries,
            "last_known_good_index": report.last_known_good_index,
            "last_known_good_hmac": report.last_known_good_hmac,
            "breaks": [
                {
                    "index": b.index,
                    "entry_id": b.entry_id,
                    "kind": b.kind.value,
                    "detail": b.detail,
                }
                for b in report.breaks
            ],
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        sys.exit(0 if report.ok else 2)

    if report.ok:
        # A15 (v0.1.7): drop the dangling ``(last hmac=)`` parenthesis
        # when the chain is empty. There's no head HMAC on a zero-entry
        # chain, so the empty parens just looked like a render bug.
        if report.total_entries == 0:
            click.secho("OK: 0 entries (chain is empty)", fg="green")
        else:
            # Round 11 MED: ``last_known_good_hmac`` is sourced from
            # ``entry.hmac`` which ``AuditEntry.from_dict`` only
            # type-checks as ``str`` -- a tampered chain can carry
            # control bytes here. Sanitize before echo so the success
            # banner cannot leak escape sequences into the operator's
            # terminal. ``b.kind.value`` (enum) and integers below are
            # not attacker-controlled.
            click.secho(
                f"OK: {report.total_entries} entries, chain intact "
                f"(last hmac="
                f"{_sanitize_for_terminal(report.last_known_good_hmac[:16])}...)",
                fg="green",
            )
        return

    click.secho(
        f"BROKEN: {len(report.breaks)} issue(s) across {report.total_entries} entries",
        fg="red",
        bold=True,
    )
    # Round 11 MED: ``b.entry_id`` comes from ``AuditEntry.entry_id``
    # which is only validated as a string -- a tampered audit row can
    # plant control bytes (backspace, OSC title-set, BEL) that the
    # terminal will interpret. ``b.detail`` likewise embeds
    # attacker-controlled ``prev_hmac`` / ``hmac`` prefixes for the
    # LINK_MISMATCH / SELF_MISMATCH / UNKNOWN_KEY / MISSING_KEY_ID
    # kinds. Wrap both with ``_sanitize_for_terminal`` to match the
    # Round 10 audit-tail / audit-report fixes. ``b.index`` is int and
    # ``b.kind.value`` is an enum member, neither needs sanitization.
    for b in report.breaks[:50]:
        click.echo(
            f"  line {b.index} [{b.kind.value}] "
            f"entry={_sanitize_for_terminal(b.entry_id)}: "
            f"{_sanitize_for_terminal(b.detail)}"
        )
        hint = _verify_break_hint(b.kind.value)
        if hint:
            click.echo(f"      hint: {hint}")
    if len(report.breaks) > 50:
        click.echo(f"  ... and {len(report.breaks) - 50} more")
    sys.exit(2)


def _verify_break_hint(kind: str) -> str:
    """Return an operator-readable hint for a verify break kind.

    The new v0.1.6 archive-aware kinds (``MERKLE_MISMATCH``,
    ``ARCHIVE_MISSING``, ``ARCHIVE_FORMAT_INVALID``) get explicit
    remediation guidance because they're brand new to operators
    upgrading from v0.1.5. The pre-existing kinds already render with
    enough detail in ``b.detail``.
    """
    if kind == "merkle_mismatch":
        return (
            "the marker's claimed Merkle root no longer matches the archive. "
            "Either the marker or the archive was tampered with."
        )
    if kind == "archive_missing":
        return (
            "pass --including-archives <dir> pointing at the directory that "
            "contains the referenced archive file."
        )
    if kind == "archive_format_invalid":
        return (
            "the archive on disk is malformed (bad magic, version mismatch, "
            "or truncated). Restore from a known-good copy."
        )
    return ""


@audit.command("verify-contiguity")
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    required=True,
    help="HMAC secret as hex. Contiguity is only trustworthy on an "
    "HMAC-intact chain, so this command verifies integrity first.",
)
@click.option(
    "--key-id",
    "key_id",
    default="k1",
    show_default=True,
    envvar="SIGNET_HMAC_KEY_ID",
    help="ID of the active key. Match the writer's --hmac-key-id.",
)
@click.option(
    "--expect-start",
    type=int,
    default=None,
    help="Assert the chain's first sequence number equals this value. "
    "Lets you catch head truncation when you know the true start "
    "out-of-band (e.g. from an externally anchored receipt).",
)
@click.option(
    "--expect-end",
    type=int,
    default=None,
    help="Assert the chain's last sequence number equals this value. "
    "Catches tail truncation -- the one tamper an intact HMAC chain "
    "cannot show on its own.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def audit_verify_contiguity(
    log_path: Path,
    hmac_secret: str,
    key_id: str,
    expect_start: int | None,
    expect_end: int | None,
    as_json: bool,
) -> None:
    """Check LOG_PATH for sequence-number gaps (missing entries).

    The HMAC chain proves nothing you HOLD was altered; this proves
    nothing was DROPPED. It first runs the integrity verify (a forged
    sequence number is just an unverified integer) and then reports any
    gap, duplicate, out-of-order, or unnumbered entry.
    """
    _validate_key_id_charset(key_id, source="--key-id/SIGNET_HMAC_KEY_ID")
    from signet.audit.backend import MalformedAuditEntry
    from signet.audit.keyring import Key, KeyRing
    from signet.audit.verifier import ChainVerifier, verify_contiguity

    keyring = KeyRing(
        active=Key(
            key_id=key_id,
            secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
        )
    )

    try:
        integrity = ChainVerifier(_open_jsonl_backend(log_path), keyring).verify()
        contiguity = verify_contiguity(
            _open_jsonl_backend(log_path),
            expected_start=expect_start,
            expected_end=expect_end,
        )
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    if as_json:
        click.echo(
            json.dumps(
                {
                    "integrity_ok": integrity.ok,
                    "contiguity_ok": contiguity.ok,
                    "sequenced": contiguity.sequenced,
                    "total_entries": contiguity.total_entries,
                    "numbered_entries": contiguity.numbered_entries,
                    "first_seq": contiguity.first_seq,
                    "last_seq": contiguity.last_seq,
                    "gaps": [
                        {"after_index": g.after_index, "from": g.missing_from, "to": g.missing_to}
                        for g in contiguity.gaps
                    ],
                    "duplicates": list(contiguity.duplicates),
                    "out_of_order_indices": list(contiguity.out_of_order_indices),
                    "unnumbered_indices": list(contiguity.unnumbered_indices),
                    "boundary_breaks": list(contiguity.boundary_breaks),
                    "signet_version": contiguity.signet_version,
                    "verified_at": contiguity.verified_at,
                },
                indent=2,
                sort_keys=True,
            )
        )
        sys.exit(0 if (integrity.ok and contiguity.ok) else 2)

    if not integrity.ok:
        click.secho(
            f"INTEGRITY BROKEN: {len(integrity.breaks)} issue(s) -- "
            "sequence numbers cannot be trusted until the chain verifies. "
            "Run 'signet audit verify' for detail.",
            fg="red",
            bold=True,
        )
        sys.exit(2)

    if not contiguity.sequenced:
        click.secho(
            f"N/A: {contiguity.total_entries} entries carry no sequence numbers "
            "(chain was written without sequence=True); completeness cannot be checked.",
            fg="yellow",
        )
        sys.exit(2)

    if contiguity.ok:
        click.secho(
            f"OK: {contiguity.numbered_entries} entries, "
            f"sequence {contiguity.first_seq}..{contiguity.last_seq} complete and gap-free",
            fg="green",
        )
        return

    click.secho("INCOMPLETE: the chain is intact but entries are missing", fg="red", bold=True)
    for g in contiguity.gaps:
        click.echo(
            f"  gap after entry {g.after_index}: "
            f"missing sequence {g.missing_from}..{g.missing_to} ({g.count} entr"
            f"{'y' if g.count == 1 else 'ies'})"
        )
    for dup in contiguity.duplicates:
        click.echo(f"  duplicate sequence number: {dup}")
    for idx in contiguity.out_of_order_indices:
        click.echo(f"  out-of-order sequence at entry {idx}")
    if contiguity.unnumbered_indices:
        click.echo(
            f"  {len(contiguity.unnumbered_indices)} entr"
            f"{'y' if len(contiguity.unnumbered_indices) == 1 else 'ies'} "
            "missing a sequence number (possible dropped marker)"
        )
    for b in contiguity.boundary_breaks:
        click.echo(f"  boundary: {b}")
    sys.exit(2)


@audit.command("count")
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--by",
    "group_by",
    type=click.Choice(["check", "owner", "decision", "owner_type", "stage"]),
    default=None,
    help="Group counts by this field. Default: just print total entries.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON.",
)
def audit_count(log_path: Path, group_by: str | None, as_json: bool) -> None:
    """Count entries in LOG_PATH, optionally grouped by a field.

    Quick incident-response primitive: how many blocks today? how many
    by which check? how many per owner? Reads the log lazily so it's
    safe on multi-GB chains.
    """
    from collections import Counter

    from signet.audit.backend import MalformedAuditEntry

    backend = _open_jsonl_backend(log_path)
    if group_by is None:
        try:
            total = sum(1 for _ in backend.iter_entries())
        except MalformedAuditEntry as exc:
            raise _malformed_audit_to_click_exception(exc) from exc
        if as_json:
            click.echo(json.dumps({"total": total}))
        else:
            click.echo(f"{total} entries")
        return

    counts: Counter[str] = Counter()
    try:
        for entry in backend.iter_entries():
            # Round 9 MED: group keys derived from attacker-controlled
            # fields (check_name, owner string, stage from metadata) need
            # sanitization before they enter the Counter, so both the
            # tabular and the JSON branches render terminal-safe keys.
            # The --json branch is also safe via json.dumps, but
            # sanitizing once at insertion keeps the two outputs aligned.
            # Enum-derived keys (decision.value, owner_type.value) are
            # constrained by construction and don't need sanitizing.
            if group_by == "check":
                counts[_sanitize_for_terminal(entry.check_name)] += 1
            elif group_by == "decision":
                counts[entry.decision.value] += 1
            elif group_by == "owner":
                counts[_sanitize_for_terminal(entry.owner)] += 1
            elif group_by == "owner_type":
                counts[entry.owner.owner_type.value] += 1
            elif group_by == "stage":
                stage = _sanitize_for_terminal(entry.metadata.get("_stage", "unknown"))
                counts[stage] += 1
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    if as_json:
        click.echo(json.dumps(dict(counts.most_common()), indent=2, sort_keys=True))
        return
    width = max((len(k) for k in counts), default=10)
    for key, n in counts.most_common():
        click.echo(f"  {key:<{width}}  {n}")
    click.echo(f"({sum(counts.values())} total)")


@audit.command("tail")
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-n", "n_lines", type=int, default=10, show_default=True, help="Show last N entries.")
@click.option(
    "--filter",
    "filter_expr",
    default=None,
    help="Filter expression in form FIELD=VALUE (check, decision, owner_type). "
    "Multiple comma-separated. Example: decision=block,check=owner_resolution",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit one JSON object per line (JSONL, the same shape as the chain).",
)
def audit_tail(log_path: Path, n_lines: int, filter_expr: str | None, as_json: bool) -> None:
    """Show the last N entries from LOG_PATH (optionally filtered)."""
    from signet.audit.backend import MalformedAuditEntry

    # C7 (v0.1.7): validate filter field names up-front. Previously an
    # unknown field (``foo=bar``) silently filtered out every entry --
    # the operator saw zero output and assumed the chain was empty.
    # Allowed fields are documented in the --filter help text and
    # mirror the comparison branches below.
    _ALLOWED_FILTER_FIELDS = {"check", "decision", "owner_type"}

    filters: dict[str, str] = {}
    if filter_expr:
        for clause in filter_expr.split(","):
            if "=" not in clause:
                raise click.ClickException(f"bad --filter clause {clause!r}; expected FIELD=VALUE")
            k, v = clause.split("=", 1)
            field_name = k.strip()
            if field_name not in _ALLOWED_FILTER_FIELDS:
                raise click.ClickException(
                    f"unknown filter field {field_name!r}; "
                    f"known fields: {', '.join(sorted(_ALLOWED_FILTER_FIELDS))}"
                )
            filters[field_name] = v.strip()

    from signet.core.audit import AuditEntry

    backend = _open_jsonl_backend(log_path)
    matched: list[AuditEntry] = []
    try:
        for entry in backend.iter_entries():
            if filters:
                ok = True
                for f, v in filters.items():
                    actual = (
                        entry.check_name
                        if f == "check"
                        else entry.decision.value
                        if f == "decision"
                        else entry.owner.owner_type.value
                        if f == "owner_type"
                        else None
                    )
                    if actual != v:
                        ok = False
                        break
                if not ok:
                    continue
            matched.append(entry)
            if len(matched) > n_lines:
                matched.pop(0)
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    for entry in matched:
        if as_json:
            click.echo(json.dumps(entry.to_dict(), separators=(",", ":"), sort_keys=True))
        else:
            # Round 9 MED: every interpolated field is attacker-controlled
            # (check_name / owner / reason can be smuggled in via metadata
            # or upstream-derived values), so each one is sanitized before
            # rendering to a terminal. The --json branch is already safe
            # because json.dumps escapes control bytes.
            ts_iso = _sanitize_for_terminal(_ns_to_iso(entry.ts_ns))
            click.echo(
                f"{ts_iso}  {_sanitize_for_terminal(entry.decision.value):8s} "
                f"{_sanitize_for_terminal(entry.check_name):20s} "
                f"owner={_sanitize_for_terminal(entry.owner)} "
                f"reason={_sanitize_for_terminal(entry.reason)}"
            )


def _ns_to_iso(ts_ns: int) -> str:
    """Format a nanosecond wall-clock timestamp as ISO 8601 in UTC."""
    import datetime

    return datetime.datetime.fromtimestamp(ts_ns / 1e9, tz=datetime.UTC).isoformat(
        timespec="seconds"
    )


def _malformed_audit_to_click_exception(exc: Any) -> click.ClickException:
    """Wrap a :class:`signet.audit.backend.MalformedAuditEntry` into a
    one-line :class:`click.ClickException`.

    Surfaces the offending line number, the parse error, and a
    truncated raw line (capped at 200 chars) plus a one-line operator
    fix instruction. Used by every CLI surface that walks the live
    audit log so a corrupted JSONL line gives an operator-readable
    error instead of a Python traceback. Mid-write truncation after a
    crash is the realistic source of a malformed line, so the message
    points at the audit-archive operator playbook for restore-from-
    backup as the canonical fix.
    """
    raw = exc.raw_line if isinstance(exc.raw_line, str) else str(exc.raw_line)
    # Round 9 MED: the raw audit line is by definition not trusted JSON
    # (we're inside the malformed-line branch), and the parse_error from
    # stdlib json can include a slice of the malformed line. Both can
    # carry ANSI / OSC bytes that would otherwise re-render directly on
    # the operator's terminal when this ClickException is printed.
    return click.ClickException(
        f"audit log line {exc.line_number} is malformed: "
        f"{_sanitize_for_terminal(exc.parse_error)}\n"
        f"  raw line: {_sanitize_for_terminal(raw[:200])}\n"
        f"  fix: edit the file to remove or fix the bad line, "
        f"or restore from backup."
    )


@audit.command("show")
@click.argument("entry_id")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain.",
)
def audit_show(entry_id: str, audit_log_path: Path) -> None:
    """Pretty-print the audit row for ENTRY_ID.

    Deterministic re-evaluation of ADMISSION-stage checks against an
    archived request requires the original request body to be stored
    alongside the audit row -- that's roadmap, not v0.1. For now this
    command reads the matching entry, pretty-prints it, and exits 0.
    Useful for incident response (`why did we block this entry?`) and
    for confirming receipts.
    """
    _show_entry(entry_id, audit_log_path)


@audit.command("compact")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the live JSONL audit chain to compact.",
)
@click.option(
    "--before",
    required=True,
    help="ISO 8601 UTC timestamp; entries with ts strictly < this are compacted into the archive.",
)
@click.option(
    "--output",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path to write the archive file. Parent directory is created if missing.",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    required=True,
    help="HMAC secret as hex (the same one the chain was written with).",
)
@click.option(
    "--key-id",
    "key_id",
    envvar="SIGNET_HMAC_KEY_ID",
    default="k1",
    show_default=True,
    help="ID of the active key. The compaction marker is signed with this key.",
)
@click.option(
    "--quiesce-confirm",
    is_flag=True,
    help="Confirm you have stopped all writers to the chain. "
    "Compaction WILL corrupt the chain if writers are active. "
    "See docs/audit-archive-format.md for the operator playbook.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing archive file at --output. The default "
    "is refusal so an accidental re-run with the same --output never "
    "destroys an archive on disk.",
)
def audit_compact(
    audit_log_path: Path,
    before: str,
    output: Path,
    hmac_secret: str,
    key_id: str,
    quiesce_confirm: bool,
    force: bool,
) -> None:
    """Archive entries before --before into --output and replace them
    with a compaction marker in the live chain.

    The live chain MUST be quiesced first (no concurrent writers).
    Concurrent writes during compaction will corrupt the chain.
    """
    # Round 23 LOW (F-R23-9): charset validation, mirroring
    # ``keys generate-ed25519``. The compaction marker carries
    # ``key_id`` so a hostile env var here would forge a poisoned
    # marker even though the echo sites sanitize.
    _validate_key_id_charset(key_id, source="--key-id/SIGNET_HMAC_KEY_ID")
    if not quiesce_confirm:
        raise click.ClickException(
            "audit compact REQUIRES --quiesce-confirm because the live "
            "chain MUST be quiesced first (no concurrent writers). "
            "Concurrent writes during compaction WILL corrupt the chain. "
            "See docs/audit-archive-format.md threat-model section before "
            "proceeding."
        )

    # Round 17 MED (F-R17-1) sweep: the ``--audit-log`` path passes
    # through ``_open_jsonl_backend`` which already rejects Windows
    # reserved device names. The ``--output`` archive path is normally
    # safe because ``compact_audit_log`` does ``Path(output).resolve()``
    # before writing -- the fully-qualified form is treated as a
    # regular file by Win32. We still refuse the reserved-name shape
    # here so the resulting archive is not a UX foot-gun (a file named
    # ``CON`` is awkward to open or delete from Windows Explorer) and
    # so the device-name guard fires consistently across every CLI
    # surface that writes to an operator-supplied output path.
    _reject_windows_reserved_device_name(output, kind="--output")

    from datetime import UTC, datetime

    from signet.audit.chain import HmacChain
    from signet.audit.compactor import compact_audit_log
    from signet.audit.keyring import Key, KeyRing

    # Parse --before. Accept ``Z`` suffix and bare ISO; reject ambiguity
    # by normalizing to UTC.
    try:
        before_dt = datetime.fromisoformat(before.replace("Z", "+00:00"))
    except ValueError as exc:
        raise click.ClickException(
            f"--before {before!r} is not valid ISO 8601 ({exc}). Try e.g. '2026-05-01T00:00:00Z'."
        ) from exc
    if before_dt.tzinfo is None:
        before_dt = before_dt.replace(tzinfo=UTC)

    keyring = KeyRing(
        active=Key(
            key_id=key_id,
            secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
        )
    )
    from signet.audit.backend import MalformedAuditEntry

    backend = _open_jsonl_backend(audit_log_path)
    chain = HmacChain(backend, keyring)

    # ``compact_audit_log`` raises ``FileExistsError`` when output
    # exists and ``force`` is False, and ``ValueError`` for other
    # operator-fixable conditions (most prominently the A2 stacked-
    # compaction guard: "previous compaction marker in eligible-entries
    # window"). v0.1.7 F1: surface both as ClickException so operators
    # see an actionable message instead of a raw Python traceback.
    # ``--force`` overrides the file-overwrite refusal but does NOT
    # silence the stacked-compaction ValueError (the marker check is a
    # data-integrity guard, not a UX nicety).
    # Round-4 NEW-3: compact also walks the live JSONL via
    # ``backend.iter_entries()``, so a mid-write truncated row would
    # raise ``MalformedAuditEntry``. Mirror the v0.1.7 C6 contract used
    # by every other audit subcommand: one-line operator-readable error,
    # no traceback.
    try:
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=before_dt,
            output=output,
            force=force,
        )
    except FileExistsError as exc:
        raise click.ClickException(
            f"refusing to overwrite existing archive at {output}; pass --force to override ({exc})"
        ) from exc
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if result is None:
        click.secho(
            f"no-op: nothing before {before_dt.isoformat()}",
            fg="yellow",
        )
        sys.exit(0)

    click.secho("compaction complete:", fg="green")
    click.echo(f"  marker_entry_id:   {result.marker_entry_id}")
    click.echo(f"  merkle_root:       {result.merkle_root}")
    click.echo(f"  compacted_count:   {result.compacted_count}")
    click.echo(f"  range_start:       {result.range[0]}")
    click.echo(f"  range_end:         {result.range[1]}")
    click.echo(f"  archive_path:      {result.archive_path}")
    click.echo(
        "\nverify with:\n"
        f"  signet audit verify {audit_log_path} --hmac-secret <hex> "
        f"--including-archives {result.archive_path.parent}"
    )


@audit.command("report")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain.",
)
@click.option(
    "--since",
    default="24h",
    show_default=True,
    help=(
        "Duration of the report window. Accepts: <int>m (minutes), "
        "<int>h (hours), <int>d (days), <int>w (weeks), or an ISO 8601 "
        "duration like PT1H30M, P1D, P1W. Examples: 30m, 1h, 24h, 7d, "
        "1w, PT90M."
    ),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    show_default=True,
    help="Output format. ``markdown`` is human-readable; ``json`` is "
    "structured for downstream tooling.",
)
@click.option(
    "--anonymize/--no-anonymize",
    default=True,
    show_default=True,
    help="Hash owner IDs with a salted SHA-256 before rendering. "
    "--no-anonymize emits raw owner IDs (only safe in private "
    "incident-response channels).",
)
@click.option(
    "--anonymize-salt",
    envvar="SIGNET_ANONYMIZE_SALT",
    default=None,
    help="Salt used for owner-ID anonymization. Required with "
    "--anonymize unless SIGNET_ANONYMIZE_SALT env is set.",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    default=None,
    help="HMAC secret as hex. When provided, the chain is verified "
    "and the integrity section reports ok/breaks. Without it the "
    "integrity section is omitted (still safe for ops dashboards).",
)
@click.option(
    "--key-id",
    "key_id",
    envvar="SIGNET_HMAC_KEY_ID",
    default="k1",
    show_default=True,
    help="ID of the active key for chain integrity verification.",
)
@click.option(
    "--service-label",
    "service_label",
    default=None,
    help="Optional service label rendered in the report header (e.g. "
    "'thornveil-prod'). Defaults to omitting the suffix.",
)
def audit_report(
    audit_log_path: Path,
    since: str,
    fmt: str,
    anonymize: bool,
    anonymize_salt: str | None,
    hmac_secret: str | None,
    key_id: str,
    service_label: str | None,
) -> None:
    """Periodic decision summary suitable for dashboards and weekly
    reviews.

    Aggregates decisions, top firing checks, top blocked owners
    (anonymized by default), deltas vs the prior equivalent period,
    and the chain-integrity attestation when --hmac-secret is supplied.
    """
    # Round 23 LOW (F-R23-9): charset validation, mirroring
    # ``keys generate-ed25519``. The report header / integrity section
    # renders ``key_id`` and would otherwise leak attacker-controlled
    # bytes through banners if the env var is hostile.
    _validate_key_id_charset(key_id, source="--key-id/SIGNET_HMAC_KEY_ID")
    from datetime import UTC, datetime

    if anonymize and not anonymize_salt:
        raise click.ClickException(
            "--anonymize requires --anonymize-salt or SIGNET_ANONYMIZE_SALT. "
            "Pass --no-anonymize only if you understand the disclosure risk."
        )

    duration = _parse_duration(since)
    now = datetime.now(tz=UTC)
    window_start = now - duration
    prior_start = now - 2 * duration
    prior_end = window_start

    from signet.audit.backend import MalformedAuditEntry

    backend = _open_jsonl_backend(audit_log_path)
    cur_window: list[Any] = []
    prior_window: list[Any] = []
    try:
        for entry in backend.iter_entries():
            ts = datetime.fromtimestamp(entry.ts_ns / 1e9, tz=UTC)
            if window_start <= ts <= now:
                cur_window.append(entry)
            elif prior_start <= ts < prior_end:
                prior_window.append(entry)
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    integrity_section: dict[str, Any] | None = None
    if hmac_secret:
        from signet.audit.keyring import Key, KeyRing
        from signet.audit.verifier import ChainVerifier

        keyring = KeyRing(
            active=Key(
                key_id=key_id,
                secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
            )
        )
        report = ChainVerifier(backend, keyring).verify()
        head_hmac = report.last_known_good_hmac
        integrity_section = {
            "ok": report.ok,
            "breaks": len(report.breaks),
            "head_hmac_short": head_hmac[-8:] if head_hmac else "",
            "total_entries": report.total_entries,
        }

    aggregates = _aggregate_audit_window(
        cur_window,
        anonymize=anonymize,
        salt=anonymize_salt or "",
    )
    prior_aggregates = _aggregate_audit_window(
        prior_window,
        anonymize=anonymize,
        salt=anonymize_salt or "",
    )

    payload = {
        "range": {
            "start": window_start.isoformat(timespec="minutes"),
            "end": now.isoformat(timespec="minutes"),
            "duration": since,
        },
        "service": service_label,
        "signet_version": __version__,
        "total_decisions": aggregates["total"],
        "decision_counts": aggregates["decision_counts"],
        "top_checks": aggregates["top_checks"],
        "top_blocked_owners": aggregates["top_blocked_owners"],
        "deltas": _compute_deltas(aggregates, prior_aggregates),
        "integrity": integrity_section,
        # Carried into the markdown renderer so the section header
        # ("(anonymized)") matches the anonymize flag operators
        # actually passed (A5).
        "anonymize": anonymize,
    }

    if fmt == "json":
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    click.echo(_render_audit_report_markdown(payload))


_MAX_DURATION_DAYS = 36500  # ~100 years; see ``_clamp_duration``.


def _clamp_duration(td: Any, spec: str) -> Any:
    """Reject duration windows larger than ~100 years.

    Round-4 NEW-10: the report path computes ``now - duration`` and
    ``now - 2 * duration``, which the standard library's ``datetime``
    rejects with :class:`OverflowError` once the result drifts past
    ``datetime.min``. Operators that fat-finger a giant ``--since``
    (e.g. ``999999999d``) used to see a raw traceback. Clamping at the
    parse step gives them a one-line actionable error and also pins a
    sane upper bound that doubles cleanly without overflow on prior-
    window computation.
    """
    if td.days > _MAX_DURATION_DAYS:
        raise click.ClickException(
            f"--since {spec!r} duration too large; maximum is 100 years "
            f"({_MAX_DURATION_DAYS} days)."
        )
    return td


def _parse_duration(spec: str) -> Any:
    """Parse a duration spec to a :class:`datetime.timedelta`.

    Accepted formats:

    * ``<int>m`` -- N minutes
    * ``<int>h`` -- N hours
    * ``<int>d`` -- N days
    * ``<int>w`` -- N weeks
    * ISO 8601 duration with a ``P`` prefix -- ``P1D``, ``P1W``,
      ``PT1H30M``, ``PT90M``, etc. Years and months are rejected
      because their length depends on the calendar position.

    Raises :class:`click.ClickException` on bad input so the operator
    gets a clear error rather than a ValueError.

    Returns a :class:`datetime.timedelta`; typed as :class:`Any` only
    because importing ``datetime`` at module top would force every
    other CLI subcommand to pay that import even when not needed.
    """
    import re
    from datetime import timedelta

    raw = spec.strip()
    if not raw:
        raise click.ClickException(
            "--since cannot be empty; expected e.g. '30m', '1h', "
            "'24h', '7d', '1w', or an ISO 8601 duration like 'PT1H30M'."
        )

    # Suffix forms first -- the original v0.1.6 surface plus minutes
    # and weeks. Reject negatives and overflow before they reach
    # timedelta() (which would raise OverflowError on huge values).
    suffix_match = re.fullmatch(r"(\d+)\s*([mhdw])", raw, flags=re.IGNORECASE)
    if suffix_match:
        n = int(suffix_match.group(1))
        unit = suffix_match.group(2).lower()
        factor_seconds = {
            "m": 60,
            "h": 3600,
            "d": 86400,
            "w": 604800,
        }[unit]
        try:
            td = timedelta(seconds=n * factor_seconds)
        except OverflowError as exc:
            raise click.ClickException(f"--since {spec!r} overflows timedelta: {exc}") from exc
        return _clamp_duration(td, spec)

    # ISO 8601 duration -- accept ``PnW`` or ``PnDTnHnMnS`` shapes.
    # Years/months are intentionally rejected because their length is
    # ambiguous (a "1 month" report window is meaningless without a
    # calendar anchor). isodate is a third-party dep; rather than
    # adding it just for a fallback, parse the subset we actually
    # care about with a regex.
    iso_match = re.fullmatch(
        r"P(?:(\d+)W"
        r"|(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?)",
        raw,
        flags=re.IGNORECASE,
    )
    if iso_match and any(g is not None for g in iso_match.groups()):
        weeks_grp, days_grp, hours_grp, minutes_grp, seconds_grp = iso_match.groups()
        try:
            if weeks_grp is not None:
                td = timedelta(weeks=int(weeks_grp))
            else:
                td = timedelta(
                    days=int(days_grp) if days_grp else 0,
                    hours=int(hours_grp) if hours_grp else 0,
                    minutes=int(minutes_grp) if minutes_grp else 0,
                    seconds=float(seconds_grp) if seconds_grp else 0,
                )
        except OverflowError as exc:
            raise click.ClickException(f"--since {spec!r} overflows timedelta: {exc}") from exc
        return _clamp_duration(td, spec)

    raise click.ClickException(
        f"--since {spec!r} is not a valid duration; expected forms: "
        "30m, 1h, 24h, 7d, 1w, or an ISO 8601 duration like PT1H30M, "
        "P1D, P1W. Years/months (P1Y, P1M) are rejected -- use weeks "
        "or days for an unambiguous window."
    )


def _aggregate_audit_window(
    entries: list[Any],
    *,
    anonymize: bool,
    salt: str,
) -> dict[str, Any]:
    """Roll up an audit-log window into the report's aggregate fields.

    Memory note: this loads the entries that fall in the window into
    memory before aggregating. For chains with very large 24h windows
    that's the cap on this command's footprint -- see the report-back
    note about scalability.
    """
    from collections import Counter

    decision_counts: Counter[str] = Counter()
    check_counts: Counter[str] = Counter()
    check_owner_sets: dict[str, set[str]] = {}
    check_decision_breakdown: dict[str, Counter[str]] = {}
    blocked_owner_counts: Counter[str] = Counter()

    for entry in entries:
        d = entry.decision.value
        decision_counts[d] += 1
        if d in {"block", "escalate", "redact"}:
            check_counts[entry.check_name] += 1
            check_owner_sets.setdefault(entry.check_name, set()).add(str(entry.owner))
            check_decision_breakdown.setdefault(entry.check_name, Counter())[d] += 1
        if d == "block":
            owner_str = str(entry.owner)
            rendered = _maybe_anonymize_owner(owner_str, anonymize=anonymize, salt=salt)
            blocked_owner_counts[rendered] += 1

    top_checks: list[dict[str, Any]] = []
    for name, count in check_counts.most_common(10):
        top_checks.append(
            {
                "name": name,
                "firings": count,
                "distinct_owners": len(check_owner_sets.get(name, set())),
                "by_decision": dict(check_decision_breakdown.get(name, Counter())),
            }
        )
    top_blocked_owners = [
        {"owner": k, "blocks": v} for k, v in blocked_owner_counts.most_common(10)
    ]
    return {
        "total": sum(decision_counts.values()),
        "decision_counts": dict(decision_counts),
        "top_checks": top_checks,
        "top_blocked_owners": top_blocked_owners,
    }


def _maybe_anonymize_owner(owner_str: str, *, anonymize: bool, salt: str) -> str:
    """Render an owner string for the report.

    With ``anonymize=True``, returns ``owner_<16hex>`` where the 16 hex
    characters are the first 16 of ``SHA-256(salt + ":" + owner_str)``,
    i.e. 64 bits of slug entropy. The v0.1.7 charter bumped this from 8
    to 16 hex chars to widen the search space against rainbow-table
    attacks on plausible owner IDs (an 8-hex slug is only 32 bits, well
    inside precompute range for a small enumerable owner namespace).
    With ``anonymize=False``, returns the raw owner string.
    """
    if not anonymize:
        return owner_str
    import hashlib

    h = hashlib.sha256(f"{salt}:{owner_str}".encode()).hexdigest()
    return f"owner_{h[:16]}"


def _compute_deltas(cur: dict[str, Any], prior: dict[str, Any]) -> dict[str, Any]:
    """Compute "current vs prior" deltas the report renders.

    Two notable signals:

    * ``check_pct_delta`` -- for every name in the current top-10, what
      was its count in the prior window? Render ``inf`` when the prior
      count was zero (genuinely new firing).
    * ``new_blocked_owners`` -- owners in the current top-10 not present
      in the prior top-10. ``len(...)`` is the headline number; the
      list of names is the supporting detail.
    """
    prior_check_counts = {row["name"]: row["firings"] for row in prior.get("top_checks", [])}
    check_pct_delta: list[dict[str, Any]] = []
    for row in cur.get("top_checks", []):
        prev = prior_check_counts.get(row["name"], 0)
        cur_n = row["firings"]
        if prev == 0:
            pct: float | None = float("inf") if cur_n > 0 else 0.0
        else:
            pct = (cur_n - prev) / prev * 100.0
        check_pct_delta.append(
            {
                "name": row["name"],
                "prior": prev,
                "current": cur_n,
                "pct_delta": pct,
            }
        )

    prior_owner_set = {row["owner"] for row in prior.get("top_blocked_owners", [])}
    cur_owner_list = [row["owner"] for row in cur.get("top_blocked_owners", [])]
    new_owners = [o for o in cur_owner_list if o not in prior_owner_set]
    return {
        "check_pct_delta": check_pct_delta,
        "new_blocked_owners": new_owners,
    }


def _strip_utc_suffix(iso: str) -> str:
    """Strip the trailing ``+00:00`` from an ISO 8601 string.

    A12 (v0.1.7): the report header used to render
    ``2026-05-09T12:00+00:00 UTC``, double-tagging the timezone. The
    payload's ISO timestamp is already known to be in UTC by
    construction (``datetime.now(tz=UTC)``), so the explicit ``UTC``
    suffix is the human-readable label and the ``+00:00`` is
    redundant. Strip the offset from the ISO portion before
    interpolating into the markdown.
    """
    return iso.replace("+00:00", "")


def _pluralize_blocks(n: int) -> str:
    """Render ``n blocks`` / ``1 block`` correctly.

    Tiny but worth its own helper because the report renders the
    string in two places (raw and anonymized owner lists) and the bug
    of "1 blocks" was loud enough to flag in ergonomics review.
    """
    return f"{n} block{'s' if n != 1 else ''}"


def _render_audit_report_markdown(payload: dict[str, Any]) -> str:
    """Render the report payload as the operator-facing markdown doc."""
    lines: list[str] = []
    rng = payload["range"]
    service_suffix = f" @ {payload['service']}" if payload.get("service") else ""
    lines.append("# signet audit report")
    lines.append(
        f"**Range:** {_strip_utc_suffix(rng['start'])} -> "
        f"{_strip_utc_suffix(rng['end'])} UTC ({rng['duration']})"
    )
    lines.append(f"**Service:** signet {payload['signet_version']}{service_suffix}")
    lines.append(f"**Total decisions:** {payload['total_decisions']:,}")
    lines.append("")

    lines.append("## Decision distribution")
    lines.append("| Decision  | Count | %     |")
    lines.append("|-----------|-------|-------|")
    total = max(1, payload["total_decisions"])
    for d in ("allow", "block", "escalate", "redact"):
        n = payload["decision_counts"].get(d, 0)
        pct = n / total * 100.0
        lines.append(f"| {d:<9} | {n:>5} | {pct:5.1f}% |")
    lines.append("")

    lines.append("## Top firing checks (block + escalate + redact)")
    if not payload["top_checks"]:
        lines.append("(no block/escalate/redact decisions in the window)")
    else:
        for i, row in enumerate(payload["top_checks"], start=1):
            by = row.get("by_decision", {})
            if by and len(by) > 1:
                breakdown = ", ".join(f"{v} {k}" for k, v in sorted(by.items()))
                detail = f"{row['firings']} firings ({breakdown})"
            else:
                detail = f"{row['firings']} firings, {row['distinct_owners']} distinct owners"
            # Round 9 MED: row['name'] is check_name, attacker-controlled.
            # Markdown itself doesn't interpret ANSI bytes, but operators
            # routinely view the report through ``less`` / ``cat`` / pipe
            # into chat -- all of which DO render the bytes. Sanitize
            # before interpolation so the markdown output is terminal-safe.
            lines.append(f"{i}. `{_sanitize_for_terminal(row['name'])}` -- {detail}")
    lines.append("")

    # A5 (v0.1.7): only mark the section header as "(anonymized)" when
    # owners actually were anonymized. The previous header was
    # hard-coded regardless of the --anonymize/--no-anonymize flag.
    is_anonymized = bool(payload.get("anonymize", True))
    if payload.get("top_blocked_owners"):
        if is_anonymized:
            lines.append("## Top blocked owners (anonymized)")
        else:
            lines.append("## Top blocked owners")
        for i, row in enumerate(payload["top_blocked_owners"], start=1):
            # Round 9 MED: owner string attacker-controlled when
            # --no-anonymize is set. Sanitize for the same reason as the
            # check name above.
            lines.append(
                f"{i}. `{_sanitize_for_terminal(row['owner'])}` -- "
                f"{_pluralize_blocks(row['blocks'])}"
            )
        lines.append("")
    else:
        lines.append("")

    lines.append("## Notable deltas vs prior period")
    deltas = payload.get("deltas", {})
    rendered_any = False
    for d in deltas.get("check_pct_delta", []):
        pct = d["pct_delta"]
        if pct is None or pct == 0.0:
            continue
        # Round 9 MED: d['name'] is check_name, attacker-controlled.
        name_safe = _sanitize_for_terminal(d["name"])
        if pct == float("inf"):
            lines.append(
                f"- `{name_safe}` firings NEW in this window ({d['current']} firings; prior=0)"
            )
        else:
            arrow = "up" if pct > 0 else "down"
            lines.append(
                f"- `{name_safe}` firings {arrow} {abs(pct):.0f}% ({d['prior']} -> {d['current']})"
            )
        rendered_any = True
    new_owners = deltas.get("new_blocked_owners", [])
    if new_owners:
        lines.append(
            f"- New blocked owners: {len(new_owners)} first-time appearances in the top-10"
        )
        rendered_any = True
    if not rendered_any:
        lines.append("(no notable deltas)")
    lines.append("")

    if payload.get("integrity"):
        i = payload["integrity"]
        lines.append("## Audit chain integrity")
        lines.append(f"- Verified: ok={i['ok']}, breaks={i['breaks']}")
        if i.get("head_hmac_short"):
            lines.append(f"- Head HMAC (last 8 hex): `{i['head_hmac_short']}`")
        lines.append(f"- Total entries (entire chain): {i['total_entries']:,}")
    return "\n".join(lines).rstrip() + "\n"


@main.command()
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("pipeline.py"),
)
@click.option(
    "--strict/--no-strict",
    default=False,
    help="Treat warnings as errors. CI invocation pattern: "
    "`signet lint --strict` exits non-zero on any finding.",
)
def lint(config_path: Path, strict: bool) -> None:
    """Static analysis on a pipeline file. Catches the four most common
    misconfigurations operators ship with:

    \b
    1. RateLimitCheck registered before content checks (RegexContent,
       PromptInjection): a refused request still drains the bucket.
       Fixed in v0.1.5 by RateLimitCheck.priority=100, but
       user-defined Check subclasses can still get this wrong.
    2. No OwnerResolutionCheck registered: every audit row will record
       Owner.unresolved(), which makes attribution-based incident
       response impossible.
    3. ToolCallInspectorCheck(allow_unregistered=True): registered
       tools are gated by risk tier, but anything outside the registry
       is silently allowed. Almost always a mistake outside dev.
    4. ClassificationGateCheck without a matching ScopeDriftCheck at
       INSPECTION: ADMISSION-stage classification ladders only check
       what was *requested*; they do not see what the model actually
       generated. Pair them.

    Exits 0 with no findings, 0 with warnings (without ``--strict``),
    or 1 with findings (with ``--strict``).

    \b
    SECURITY NOTE: ``signet lint`` imports the pipeline file the same
    way ``signet serve --config`` does -- arbitrary Python execution.
    Run only against files you control.
    """
    findings = _lint_pipeline(config_path)

    if not findings:
        click.secho(
            f"OK: pipeline passes the v{__version__} lint checks.",
            fg="green",
        )
        sys.exit(0)

    for f in findings:
        color = "red" if f.severity == "error" else "yellow"
        click.secho(f"  [{f.severity.upper()}] {f.code}: {f.message}", fg=color)
        if f.hint:
            click.echo(f"      hint: {f.hint}")

    has_errors = any(f.severity == "error" for f in findings)
    if has_errors or strict:
        sys.exit(1)
    sys.exit(0)


@main.group()
def plugins() -> None:
    """Plugin discovery and management.

    signet discovers third-party plugins via Python entry points under
    these groups:

    \b
    - signet.checks: full Check subclasses
    - signet.adapters: HTTP adapter shims
    - signet.anchors: external anchor backends

    Each discovered plugin is reported with one of four statuses:

    \b
    - loaded: ABI-compatible, ready to use
    - incompatible_abi: declares a CHECK_ABI_VERSION signet doesn't know
    - load_error: import/instantiation failed
    - duplicate_name: another package registers the same (group, name)

    Use 'signet plugins list' to see what's installed and 'signet plugins
    doctor' to gate CI on plugin health.
    """


@plugins.command("list")
@click.option(
    "--group",
    type=click.Choice(["signet.checks", "signet.adapters", "signet.anchors", "all"]),
    default="all",
    show_default=True,
    help="Restrict the listing to a single entry-point group.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit a JSON array matching the DiscoveredPlugin shape.",
)
def plugins_list(group: str, as_json: bool) -> None:
    """List discovered plugins.

    Reports every entry point under ``signet.checks``,
    ``signet.adapters`` and ``signet.anchors``, including
    ``loaded``, ``incompatible_abi`` and ``load_error`` statuses so
    misconfiguration is visible (rather than silently dropped).
    """
    from signet.plugins import discover_plugins

    plugins_found = discover_plugins(refresh=True)
    if group != "all":
        plugins_found = [p for p in plugins_found if p.group == group]

    if as_json:
        payload = []
        for p in plugins_found:
            payload.append(
                {
                    "group": p.group,
                    "name": p.name,
                    "package": p.package,
                    "package_version": p.package_version,
                    "target": p.target,
                    "status": p.status,
                    "abi_declared": p.abi_declared,
                    "abi_required": p.abi_required,
                    "error": p.error,
                }
            )
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    # Group rows by group for readability. Order: checks, adapters,
    # anchors. Empty sections render an explicit "(none)" line so the
    # operator can tell "no plugins" apart from "we forgot to scan".
    group_titles = {
        "signet.checks": "INSTALLED CHECKS",
        "signet.adapters": "INSTALLED ADAPTERS",
        "signet.anchors": "INSTALLED ANCHORS",
    }
    seen_any = False
    for grp in ("signet.checks", "signet.adapters", "signet.anchors"):
        if group != "all" and group != grp:
            continue
        rows = [p for p in plugins_found if p.group == grp]
        click.echo(f"\n{group_titles[grp]} ({len(rows)})")
        if not rows:
            click.echo("  (none)")
            continue
        seen_any = True
        # Round 9 MED: plugin metadata (entry-point name, distribution,
        # version, load error text) is attacker-influenceable -- a
        # typosquatted plugin can carry ANSI bytes in any of those
        # fields. Sanitize every attribute before interpolation so the
        # CLI render path is terminal-safe. The width computation must
        # use the sanitized strings too or the column padding will be
        # off-by-N (where N is the expansion of the textual ``\xNN``
        # form).
        sanitized_names = [_sanitize_for_terminal(p.name) for p in rows]
        sanitized_pkgs = [_render_pkg(p) for p in rows]
        name_w = max(len(n) for n in sanitized_names)
        pkg_w = max(len(pkg) for pkg in sanitized_pkgs)
        for p, name_safe, pkg in zip(rows, sanitized_names, sanitized_pkgs, strict=True):
            abi_seg = ""
            if grp == "signet.checks":
                abi = p.abi_declared if p.abi_declared is not None else "?"
                abi_seg = f"ABI {_sanitize_for_terminal(abi):<3}"
            status_seg = _render_plugin_status(p)
            line = f"  {name_safe:<{name_w}}  {pkg:<{pkg_w}}  {abi_seg:<8}{status_seg}".rstrip()
            color = (
                "green" if p.status == "loaded" else "red" if p.status == "load_error" else "yellow"
            )
            click.secho(line, fg=color)

    if not seen_any and group == "all":
        click.echo(
            "\n(no plugins discovered; install signet plugin packages to populate this list)"
        )


@plugins.command("doctor")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit a JSON object describing the issues found.",
)
def plugins_doctor(as_json: bool) -> None:
    """Lint the discovered plugin set and exit non-zero on any issue.

    Wraps :func:`discover_plugins` (with refresh on) and reports two
    classes of failure that ``plugins list`` would otherwise show
    only via color in the terminal:

    * **Duplicate (group, name) pairs** -- two plugin packages
      registering the same entry-point name within one group. The
      resolver picks one and silently shadows the other; in CI you
      want the build to fail.
    * **Plugins with non-loaded status** -- ``incompatible_abi`` (the
      plugin declares a CHECK_ABI_VERSION signet does not accept) and
      ``load_error`` (import or type-validation failure during
      :meth:`EntryPoint.load`).

    Exit code is 0 when both classes are empty, 1 otherwise. Intended
    to be the CI gate for plugin-heavy deployments -- pair with
    ``signet lint --strict`` and ``signet doctor --probe-injection``.
    """
    from signet.plugins import discover_plugins

    plugins_found = discover_plugins(refresh=True)

    # Detect duplicate (group, name) pairs. ``discover_plugins`` does
    # not deduplicate -- both entries surface as separate
    # ``DiscoveredPlugin`` rows -- so we can group them here.
    seen: dict[tuple[str, str], list[Any]] = {}
    for p in plugins_found:
        seen.setdefault((p.group, p.name), []).append(p)
    duplicates = {(group, name): rows for (group, name), rows in seen.items() if len(rows) > 1}

    # Plugins that failed to come up at all.
    failed = [p for p in plugins_found if p.status != "loaded"]

    if as_json:
        payload = {
            "ok": not duplicates and not failed,
            "duplicate_count": len(duplicates),
            "failed_count": len(failed),
            "duplicates": [
                {
                    "group": group,
                    "name": name,
                    "packages": [_render_pkg(r) for r in rows],
                }
                for (group, name), rows in sorted(duplicates.items())
            ],
            "failed": [
                {
                    "group": p.group,
                    "name": p.name,
                    "package": _render_pkg(p),
                    "status": p.status,
                    "error": p.error,
                }
                for p in failed
            ],
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        sys.exit(0 if payload["ok"] else 1)

    issues = 0
    if duplicates:
        click.secho(f"DUPLICATE PLUGIN NAMES ({len(duplicates)})", fg="red", bold=True)
        for (group, name), rows in sorted(duplicates.items()):
            # Round 9 MED: plugin name + packages are attacker-influenceable.
            packages = ", ".join(_render_pkg(r) for r in rows)
            click.secho(
                f"  [{_sanitize_for_terminal(group)}] "
                f"{_sanitize_for_terminal(name)} registered by: {packages}",
                fg="red",
            )
        issues += len(duplicates)
        click.echo("")

    if failed:
        click.secho(
            f"PLUGINS WITH NON-LOADED STATUS ({len(failed)})",
            fg="red",
            bold=True,
        )
        for p in failed:
            # Round 9 MED: every interpolated attribute (group, name,
            # package, status, error) can carry ANSI bytes from a
            # hostile plugin's metadata or ImportError text.
            click.secho(
                f"  [{_sanitize_for_terminal(p.group)}] "
                f"{_sanitize_for_terminal(p.name)} ({_render_pkg(p)}): "
                f"{_sanitize_for_terminal(p.status)} -- "
                f"{_sanitize_for_terminal(p.error or 'unknown')}",
                fg="red",
            )
        issues += len(failed)
        click.echo("")

    if issues == 0:
        click.secho(
            f"OK: {len(plugins_found)} plugin(s) discovered, all loaded "
            "cleanly with unique (group, name) pairs.",
            fg="green",
        )
        sys.exit(0)

    click.secho(
        f"FAIL: {issues} plugin issue(s) detected; resolve before deploy.",
        fg="red",
    )
    sys.exit(1)


def _render_pkg(p: Any) -> str:
    """Render a plugin's package name + version in one column.

    Empty package strings happen for dynamically-registered entry
    points (test fixtures, in-process registration). Render those as
    ``-`` so the column never collapses.

    Round 9 MED: package + version are derived from installed
    distribution metadata, which a hostile/typosquatted plugin can
    inject ANSI bytes into. Sanitize before returning so callers can
    interpolate the result into terminal output without re-checking.
    """
    pkg = _sanitize_for_terminal(p.package or "-")
    ver = _sanitize_for_terminal(p.package_version or "")
    return f"{pkg} {ver}".strip() if pkg != "-" else "-"


def _render_plugin_status(p: Any) -> str:
    """Format the status column for one plugin.

    Round 9 MED: error text + ABI declarations originate in plugin
    code / metadata and may carry ANSI control bytes. Sanitize before
    returning the column.
    """
    if p.status == "loaded":
        return "loaded"
    if p.status == "incompatible_abi":
        # Use the structured error if present; otherwise synthesize.
        err = p.error or (
            f"declares CHECK_ABI_VERSION={_sanitize_for_terminal(p.abi_declared)}; "
            f"signet requires {_sanitize_for_terminal(p.abi_required)}"
        )
        return f"incompatible_abi: {_sanitize_for_terminal(err)}"
    if p.status == "load_error":
        return f"load_error: {_sanitize_for_terminal(p.error or 'unknown')}"
    return _sanitize_for_terminal(p.status)  # forward-compat for new statuses


@main.command()
@click.argument("entry_id")
@click.option(
    "--audit-log",
    "audit_log_path",
    default=Path("audit.jsonl"),
    show_default=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain.",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    default=None,
    help="HMAC secret as hex. When provided, the entry's HMAC is "
    "verified against this key and the hmac line is annotated as "
    "``(verified against ring <key-id>)``. Without it, the hmac is "
    "rendered unverified.",
)
@click.option(
    "--key-id",
    "key_id",
    default="k1",
    show_default=True,
    envvar="SIGNET_HMAC_KEY_ID",
    help="ID of the active key to verify against when --hmac-secret is provided.",
)
def replay(
    entry_id: str,
    audit_log_path: Path,
    hmac_secret: str | None,
    key_id: str,
) -> None:
    """Pretty-print the audit row for ENTRY_ID.

    First-class incident-response surface. Hand it the
    ``correlation_id`` from a 403/202 refusal body and it prints the
    full audit row with field labels aligned. With
    ``SIGNET_HMAC_SECRET`` (or ``--hmac-secret``) configured, the hmac
    line is verified against the active key and annotated.

    Equivalent to ``signet audit show <id>`` (which remains as the
    canonical alias). Exit 0 if found, 1 if not.
    """
    # Round 23 LOW (F-R23-9): charset validation, mirroring
    # ``keys generate-ed25519``. The replay output interpolates
    # ``entry_key_id`` from the keyring fallback into the hmac
    # verification annotation; validating up-front keeps the asymmetry
    # closed between every ``--key-id`` flag in the CLI.
    _validate_key_id_charset(key_id, source="--key-id/SIGNET_HMAC_KEY_ID")
    _replay_pretty_print(
        entry_id=entry_id,
        audit_log_path=audit_log_path,
        hmac_secret=hmac_secret,
        key_id=key_id,
    )


def _show_entry(entry_id: str, audit_log_path: Path) -> None:
    from signet.audit.backend import MalformedAuditEntry

    # UUIDs are case-insensitive per RFC 4122; operators paste from
    # logs with whatever case the source rendered them in. Normalize
    # both sides to lowercase for the compare.
    target = entry_id.strip().lower()
    backend = _open_jsonl_backend(audit_log_path)
    try:
        for entry in backend.iter_entries():
            if entry.entry_id.lower() == target:
                click.echo(json.dumps(entry.to_dict(), indent=2, sort_keys=True))
                return
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc
    click.secho(f"no entry with id {entry_id!r} found in {audit_log_path}", fg="red")
    sys.exit(1)


def _replay_pretty_print(
    *,
    entry_id: str,
    audit_log_path: Path,
    hmac_secret: str | None,
    key_id: str,
) -> None:
    """Look up ENTRY_ID in ``audit_log_path`` and pretty-print it.

    Output format mirrors the ``signet replay`` example in the v0.1.6
    docs: aligned ``label: value`` rows, ISO timestamps, indented
    metadata block, and an optional ``(verified against ring k1)``
    annotation on the hmac line when ``hmac_secret`` is supplied and
    the recomputed HMAC matches.
    """
    import hashlib
    import hmac as _hmac

    from signet.audit.backend import MalformedAuditEntry
    from signet.audit.chain import KEY_ID_FIELD, _serialize_for_signing

    target = entry_id.strip().lower()
    backend = _open_jsonl_backend(audit_log_path)
    found = None
    try:
        for entry in backend.iter_entries():
            if entry.entry_id.lower() == target:
                found = entry
                break
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    if found is None:
        click.secho(f"no entry with id {entry_id!r} found in {audit_log_path}", fg="red")
        sys.exit(1)

    ts_iso = _ns_to_iso(found.ts_ns)
    hmac_full = found.hmac or ""
    hmac_short = (hmac_full[:8] + "...") if hmac_full else "(none)"
    hmac_suffix = ""
    if hmac_secret:
        secret = _parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET")
        # Round 25 MED (F-R25-2): ``found.metadata[KEY_ID_FIELD]`` is
        # attacker-controlled (the operator is reaching for ``signet
        # replay`` precisely to inspect a suspect entry). Every other
        # interpolated value in this function is wrapped in
        # ``_sanitize_for_terminal`` (per R7 / R14 / R23-5 closures);
        # ``entry_key_id`` was the one slot the sanitizer was not
        # applied to. A tampered ``_signing_key_id`` containing ANSI
        # bytes (e.g. ``"\x1b[2J\x1bcEVIL"``) would otherwise leak
        # through to the operator's terminal as the literal escape
        # sequence, matching the class of finding the broader R7 / R14
        # sweeps retired elsewhere. The CLI-supplied ``key_id`` fallback
        # is already validated by ``_validate_key_id_charset`` (R23-9),
        # but routing both branches through the sanitizer keeps the
        # invariant uniform.
        entry_key_id = _sanitize_for_terminal(str(found.metadata.get(KEY_ID_FIELD, key_id)))
        try:
            payload = _serialize_for_signing(found)
            recomputed = _hmac.new(secret, payload, hashlib.sha256).hexdigest()
        except Exception as exc:  # pragma: no cover -- payload integrity issue
            hmac_suffix = f"  (verification error: {type(exc).__name__})"
        else:
            if _hmac.compare_digest(recomputed, hmac_full):
                hmac_suffix = f"  (verified against ring {entry_key_id})"
            else:
                hmac_suffix = f"  (FAILED verification against ring {entry_key_id})"
    else:
        hmac_suffix = "  (unverified -- pass --hmac-secret/SIGNET_HMAC_SECRET to check)"

    # Render aligned label: value rows. Width chosen to line up the
    # documented fields.
    #
    # Round 7 MED: ``reason``, ``check_name``, and ``owner`` are all
    # populated by checks / server code that may carry attacker-
    # influenced fragments (e.g. an exception message that echoes a
    # request body slice). Run every interpolated value through the
    # terminal-escape sanitizer so ``signet replay`` cannot be turned
    # into a title-rewrite / clipboard-hijack primitive.
    rows: list[tuple[str, str]] = [
        ("entry_id", _sanitize_for_terminal(found.entry_id)),
        ("ts", _sanitize_for_terminal(ts_iso)),
        ("owner", _sanitize_for_terminal(found.owner)),
        # ``_stage`` is the convention used elsewhere (audit count, tail) for
        # surfacing the pipeline stage out of metadata. Fall back to "-".
        ("stage", _sanitize_for_terminal(found.metadata.get("_stage", "-"))),
        ("check", _sanitize_for_terminal(found.check_name)),
        ("decision", _sanitize_for_terminal(found.decision.value)),
        ("reason", _sanitize_for_terminal(found.reason)),
    ]
    label_width = max(len(label) for label, _ in rows) + 1  # ":"
    for label, value in rows:
        click.echo(f"{(label + ':').ljust(label_width)}    {value}")

    # Metadata block. Skip the chain-internal fields (key id, anchor
    # receipt) by default -- they're load-bearing for the chain but
    # noisy for an operator paging through one row. Show them under a
    # collapsed "_chain" line so power users still see they exist.
    visible_meta: dict[str, Any] = {}
    chain_meta_keys: list[str] = []
    for k, v in found.metadata.items():
        if k.startswith("_"):
            chain_meta_keys.append(k)
        else:
            visible_meta[k] = v

    click.echo("metadata:".ljust(label_width))
    if not visible_meta and not chain_meta_keys:
        click.echo("    (none)")
    else:
        # Inner alignment for the metadata sub-rows.
        meta_label_w = max((len(k) for k in visible_meta), default=0) + 1
        for k, v in visible_meta.items():
            # Round 7 MED: metadata values come from arbitrary check /
            # server code paths and can carry attacker-influenced bytes
            # (upstream Content-Type, exception messages, tool names).
            # ``json.dumps`` is the cleanest stringifier here -- it
            # matches the on-disk representation that ``audit show``
            # already echoes safely. With ``ensure_ascii=False`` it
            # escapes C0 controls (0x00-0x1F) as ``\\uNNNN`` per JSON
            # spec, but it does NOT escape Unicode bidi controls,
            # paragraph / line separators, BOM, or C1 controls.
            # Round 14 INFO: those gaps are closed by the extended
            # ``_sanitize_for_terminal`` table (Trojan Source +
            # 8-bit-CSI), so the two-step pipeline (json.dumps with
            # ensure_ascii=False, then sanitize) now preserves legitimate
            # non-ASCII display while neutralizing the deception vectors
            # that reach the operator's terminal via ``signet replay``.
            rendered = json.dumps(v, ensure_ascii=False, default=str)
            rendered = _sanitize_for_terminal(rendered)
            click.echo(f"  {(_sanitize_for_terminal(k) + ':').ljust(meta_label_w)}  {rendered}")
        if chain_meta_keys:
            click.echo(
                "  (chain-internal: "
                f"{', '.join(_sanitize_for_terminal(k) for k in sorted(chain_meta_keys))})"
            )

    click.echo(f"{('hmac:').ljust(label_width)}    {hmac_short}{hmac_suffix}")
    sys.exit(0)


@main.command()
@click.argument(
    "target_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("."),
)
def init(target_dir: Path) -> None:
    """Scaffold a starter signet project (config + sample pipeline).

    Writes four files into TARGET_DIR (current directory by default):

    \b
    - pipeline.py: a four-check pipeline (OwnerResolutionCheck,
      ClassificationGateCheck, RateLimitCheck, ScopeDriftCheck) you
      hand to ``signet serve --config``.
    - client_example.py: a minimal OpenAI-Python client that points
      at the local proxy and sends ``X-Commit-Owner`` so the gate
      has an attributable identity to record.
    - .env.example: the environment variables ``signet serve``
      reads (upstream URL, audit-log path, HMAC secret).
    - .gitignore: keeps ``.env`` and ``*.jsonl`` audit logs out of
      version control on first ``git add``.

    Per-file overwrite policy: each file is written only if it does
    not already exist. Pre-existing files are skipped with a
    ``skipped (already exists)`` line so an operator who deleted
    just ``pipeline.py`` (the most common "let me regenerate this
    one" workflow) can re-run ``signet init`` and get exactly that
    file back without losing edits to ``client_example.py`` or
    ``.env.example``. If every file is already present, the command
    refuses with exit code 1 -- this preserves the original "do not
    overwrite an existing project" guard.

    Post-init checklist:

    \b
    1. Review the four scaffolded files and edit them for your env.
    2. ``signet serve --upstream <URL> --dev`` (the ``--dev`` shorthand
       wires up an ephemeral HMAC key, an in-tmp audit log, and
       ``--config pipeline.py`` for local iteration).
    3. In another terminal, ``python client_example.py``.
    """
    # Round 19 LOW (F-R19-3): refuse Windows reserved device names at
    # the CLI boundary so ``signet init CON`` (and friends) produce a
    # clean ``ClickException`` instead of a raw ``NotADirectoryError:
    # [WinError 267]`` traceback from ``Path.mkdir``. Mirrors the R17
    # closures at the audit-log, keys-gen, and audit-compact output
    # surfaces -- the helper's check is on basename shape and is
    # correct for both file and directory targets.
    _reject_windows_reserved_device_name(target_dir, kind="TARGET_DIR")

    target_dir.mkdir(parents=True, exist_ok=True)

    pipeline_path = target_dir / "pipeline.py"
    env_path = target_dir / ".env.example"
    gitignore_path = target_dir / ".gitignore"
    client_path = target_dir / "client_example.py"

    files: list[tuple[Path, str]] = [
        (pipeline_path, _PIPELINE_TEMPLATE),
        (env_path, _ENV_TEMPLATE),
        (client_path, _CLIENT_EXAMPLE_TEMPLATE),
        (gitignore_path, _GITIGNORE_TEMPLATE),
    ]

    def _path_already_present(p: Path) -> bool:
        # Round 7 LOW: ``Path.exists`` returns False on a dangling
        # symlink, which means a local attacker who pre-plants a
        # symlink at e.g. ``pipeline.py -> /etc/somewhere`` would slip
        # past the overwrite guard below. ``is_symlink`` (or
        # ``os.path.lexists`` -- same thing) closes the gap.
        return p.exists() or p.is_symlink()

    # If every scaffolded file already exists, the operator is calling
    # init on an already-initialized directory -- refuse so we don't
    # silently no-op. Mirrors the v0.1.6 contract that an existing
    # ``pipeline.py`` is load-bearing.
    if all(_path_already_present(path) for path, _ in files):
        click.secho(f"refusing to overwrite existing {pipeline_path}", fg="yellow")
        sys.exit(1)

    wrote_any = False
    for path, content in files:
        if _path_already_present(path):
            # Be explicit when a symlink is what's blocking us so the
            # operator knows their tree is in an unexpected shape.
            if path.is_symlink():
                click.secho(
                    f"  skipped (refusing to write through symlink): {path}",
                    fg="yellow",
                )
            else:
                click.secho(f"  skipped (already exists): {path}", fg="yellow")
            continue
        # Use ``O_CREAT | O_EXCL`` so we refuse to follow any final-
        # component symlink that was created between the
        # ``_path_already_present`` check above and this open() call.
        # ``O_EXCL`` makes the open atomic with respect to that race.
        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
            )
        except FileExistsError:
            click.secho(
                f"  skipped (refusing to write through symlink): {path}",
                fg="yellow",
            )
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        click.secho(f"  wrote {path}", fg="green")
        wrote_any = True

    if not wrote_any:
        # Defensive: the all-exist branch above should already have
        # exited. Keeps mypy and humans happy.
        sys.exit(1)

    click.echo("\nnext: review the files, then run:")
    click.echo("  signet serve --upstream http://localhost:11434/v1 --dev")
    click.echo("\nthen, in another terminal:")
    click.echo("  python client_example.py")


@main.command()
@click.option(
    "--upstream",
    "upstream_url",
    default="http://localhost:11434/v1",
    show_default=True,
    envvar="SIGNET_UPSTREAM_URL",
    help="OpenAI-compatible upstream URL used for the baseline measurement.",
)
@click.option(
    "--requests",
    "request_count",
    default=1000,
    # Round 14 INFO: cap the upper bound. ``run_bench`` materializes one
    # asyncio task per request up front (``bench.py:780, 837``) -- the
    # ``Semaphore(concurrency)`` correctly bounds in-flight HTTP /
    # pipeline work but does NOT bound the number of pending task
    # objects. For ``--requests 1_000_000`` memory grows linearly into
    # the gigabyte range while adding no meaningful percentile signal
    # over the 1000-sample baseline. Refuse with a clear click range
    # error rather than letting the bench OOM the operator's machine.
    type=click.IntRange(min=1, max=1_000_000),
    show_default=True,
    help="Total number of synthetic requests to drive through the pipeline. "
    "Must be in [1, 1_000_000]. The bench materializes one task per "
    "request up front, so an upper bound caps memory growth -- meaningful "
    "tail-percentile signal levels off well below the cap.",
)
@click.option(
    "--concurrency",
    default=10,
    type=click.IntRange(min=1),
    show_default=True,
    help="Maximum in-flight requests at once. Must be >= 1.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a pipeline.py defining ``pipeline``. Without this, the "
    "bench runs against a tiny mock pipeline -- useful to measure signet's "
    "orchestration overhead in isolation.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json", "csv"]),
    default="markdown",
    show_default=True,
    help="Report format. ``json`` is suitable for CI gating and dashboards; "
    "``csv`` is for spreadsheet ingestion.",
)
@click.option(
    "--no-baseline",
    "no_baseline",
    is_flag=True,
    help="Skip the direct-to-upstream baseline. Use when the upstream is "
    "mocked or unreachable; only signet's pipeline overhead is reported.",
)
@click.option(
    "--mock-upstream",
    "mock_upstream",
    is_flag=True,
    help="Don't talk to the upstream at all. Use for CI gating where you "
    "want to catch signet code regressions independent of upstream variance.",
)
@click.option(
    "--gate",
    "gate_spec",
    default=None,
    help="Comma-separated percentile=threshold rules. Exit non-zero if any "
    "rule fails. Example: --gate p95=10ms,p99=20ms. Units: ms (default), s, us.",
)
def bench(
    upstream_url: str,
    request_count: int,
    concurrency: int,
    config_path: Path | None,
    output_format: str,
    no_baseline: bool,
    mock_upstream: bool,
    gate_spec: str | None,
) -> None:
    """Measure signet's per-request overhead.

    Drives synthetic requests through the configured (or default mock)
    pipeline, recording per-stage and per-check timings. Optionally runs
    a direct-to-upstream baseline so the report can show the delta.

    Output is suitable for blog posts, Grafana dashboards (JSON), CI
    gating (JSON + ``--gate``), and spreadsheets (CSV).

    \b
    Three modes:
      --mock-upstream    skip upstream entirely (CI gating)
      --no-baseline      pipeline-only, no upstream baseline
      (default)          full report with upstream delta

    \b
    Example:
      signet bench --mock-upstream --requests 1000 --gate p95=10ms

    See docs/bench.md for interpretation.
    """
    import asyncio

    from signet.bench import (
        apply_gate,
        format_gate_outcome,
        load_pipeline_or_default,
        parse_gate_spec,
        run_bench,
    )

    # Parse the gate spec up front so a malformed --gate fails fast,
    # before we spend a minute driving 1000 synthetic requests.
    try:
        gate_rules = parse_gate_spec(gate_spec or "")
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    pipeline = load_pipeline_or_default(config_path)

    # click.IntRange already validates --requests/--concurrency at parse
    # time, but run_bench also enforces its own contract for programmatic
    # callers. Wrap the ValueError it raises so a future internal misuse
    # surfaces as a one-line click error instead of a raw traceback.
    try:
        report = asyncio.run(
            run_bench(
                pipeline,
                upstream_url=upstream_url,
                requests=request_count,
                concurrency=concurrency,
                baseline=not no_baseline,
                mock_upstream=mock_upstream,
            )
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if output_format == "markdown":
        click.echo(report.render_markdown(), nl=False)
    elif output_format == "json":
        click.echo(report.render_json())
    elif output_format == "csv":
        click.echo(report.render_csv(), nl=False)

    if gate_rules:
        outcome = apply_gate(report, gate_rules)
        # Gate output goes to stderr so a JSON consumer piping stdout
        # to ``jq`` doesn't get gate banner text mixed in. The non-zero
        # exit still surfaces "this failed".
        click.echo(format_gate_outcome(outcome), err=True, nl=False)
        if not outcome.passed:
            sys.exit(1)


def _configure_structlog_json() -> None:
    """Configure structlog to emit JSON via the stdlib logging handler.

    All existing ``logging.getLogger(...)`` calls in signet then route
    through structlog's processor chain and emit one JSON object per
    line. The output goes to stderr (the standard signal-handler-safe
    stream for daemon logs).

    Required because all signet code uses stdlib ``logging`` (it predates
    this CLI flag); we don't rewrite every module to import structlog
    directly. Calling this function is enough.
    """
    import logging

    import structlog

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    pre_chain: list[Any] = [  # structlog's processor types vary; loose typing here
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
    ]

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=logging.INFO,
        force=True,
    )

    # Replace the root handler's formatter with structlog's JSON renderer
    handler = logging.getLogger().handlers[0]
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=pre_chain,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
        )
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


@dataclass(frozen=True)
class _LintFinding:
    code: str
    severity: str  # "error" | "warning"
    message: str
    hint: str = ""


def _lint_pipeline(config_path: Path) -> list[_LintFinding]:
    """Static-ish analysis on a configured pipeline.

    Imports the file (arbitrary code execution -- caller already warned)
    and walks the loaded ``pipeline._checks`` list. Returns a list of
    findings in declaration order.
    """
    pipeline = _load_pipeline_from_path(config_path)
    findings: list[_LintFinding] = []

    # Import the check classes lazily to avoid circular imports at
    # module top level. We compare by class identity (not name) where
    # possible so renames or re-exports don't fool us.
    from signet.checks.classification_gate import ClassificationGateCheck
    from signet.checks.owner_resolution import OwnerResolutionCheck
    from signet.checks.rate_limit import RateLimitCheck
    from signet.checks.scope_drift import ScopeDriftCheck
    from signet.checks.tool_call_inspector import ToolCallInspectorCheck
    from signet.core.stage import Stage

    checks_by_index: list[Any] = list(pipeline.checks)
    by_class: dict[type, list[int]] = {}
    for i, c in enumerate(checks_by_index):
        by_class.setdefault(type(c), []).append(i)

    # Rule 2: missing OwnerResolutionCheck (or a subclass).
    has_owner_resolver = any(isinstance(c, OwnerResolutionCheck) for c in checks_by_index)
    if not has_owner_resolver:
        findings.append(
            _LintFinding(
                code="SIG002",
                severity="error",
                message=(
                    "no OwnerResolutionCheck registered; every audit row will "
                    "record Owner.unresolved() and attribution-based incident "
                    "response will not work."
                ),
                hint=(
                    "Add OwnerResolutionCheck(require_owner=True) to your "
                    "ADMISSION-stage checks. See "
                    "docs/checks/owner_resolution.md."
                ),
            )
        )

    # Rule 1 (SIG001 -- v0.1.6 repurpose, v0.1.7 docstring fix):
    # The original v0.1.4 SIG001 fired on declared-position misordering of
    # RateLimitCheck before content checks. v0.1.5 made that moot: the
    # check's class-level ``priority=100`` self-orders it last within
    # ADMISSION regardless of registration order. The remaining footgun
    # is operators who SUBCLASS ``RateLimitCheck`` and override the
    # class-level ``priority`` attribute below 100 (e.g.
    # ``class FastRL(RateLimitCheck): priority = 10``), which re-creates
    # the original drain-on-refused-request behavior.
    #
    # IMPORTANT: ``RateLimitCheck.__init__`` does NOT accept a
    # ``priority=`` keyword argument. v0.1.6 of this file's docstring
    # incorrectly suggested it did. The lint logic itself is correct --
    # it inspects the class-level attribute exposed via ``c.priority`` --
    # but the only way for operators to make it fire is to subclass and
    # override the class attr. Treat the rule as catching subclass
    # overrides, not constructor arguments.
    #
    # CHANGELOG: SIG001 was repurposed in v0.1.6. Its original
    # registration-order check was retired alongside the v0.1.5 priority
    # default. The rule now fires on explicit priority<100 overrides
    # via subclass, surfaced through the resolved ``c.priority``.
    for c in checks_by_index:
        if not isinstance(c, RateLimitCheck):
            continue
        # The class default is 100. ``c.priority`` may be a class attr
        # (subclass override -- the documented trigger) or an instance
        # attr (rare, but possible if an operator monkey-patches one).
        # Compare to 100 directly.
        rl_priority = getattr(c, "priority", 100)
        if isinstance(rl_priority, int) and rl_priority < 100:
            findings.append(
                _LintFinding(
                    code="SIG001",
                    severity="warning",
                    message=(
                        f"RateLimitCheck has priority={rl_priority}; values < 100 "
                        "recreate the v0.1.4 footgun where rate limits drain "
                        "on downstream-blocked requests. The most common "
                        "trigger is a subclass override "
                        "(`class FastRL(RateLimitCheck): priority = 10`); "
                        "RateLimitCheck.__init__ does not accept priority "
                        "as a keyword argument."
                    ),
                    hint=(
                        "Remove the subclass priority override and keep the "
                        "default of 100 unless you specifically need rate "
                        "limiting to run before content checks."
                    ),
                )
            )

    # Rule 3: ToolCallInspectorCheck(allow_unregistered=True).
    for c in checks_by_index:
        if isinstance(c, ToolCallInspectorCheck) and getattr(c, "allow_unregistered", False):
            findings.append(
                _LintFinding(
                    code="SIG003",
                    severity="warning",
                    message=(
                        "ToolCallInspectorCheck(allow_unregistered=True): "
                        "tools outside the registry are silently allowed."
                    ),
                    hint=(
                        "Set allow_unregistered=False (the default) and "
                        "register every tool you intend to permit."
                    ),
                )
            )

    # Rule 4: ClassificationGate without a matching ScopeDriftCheck.
    has_class_gate = any(isinstance(c, ClassificationGateCheck) for c in checks_by_index)
    has_scope_drift_at_inspection = any(
        isinstance(c, ScopeDriftCheck) and c.stage is Stage.INSPECTION for c in checks_by_index
    )
    if has_class_gate and not has_scope_drift_at_inspection:
        findings.append(
            _LintFinding(
                code="SIG004",
                severity="warning",
                message=(
                    "ClassificationGateCheck registered without a matching "
                    "ScopeDriftCheck at INSPECTION. ADMISSION classification "
                    "only validates what was requested; INSPECTION drift is "
                    "what catches the model generating outside its lane "
                    "after the request was admitted."
                ),
                hint="Add ScopeDriftCheck() to your INSPECTION-stage checks.",
            )
        )

    return findings


def _doctor_autodetect(
    upstream_url: str | None, signet_url: str | None
) -> tuple[str | None, str | None]:
    """Fill in ``--upstream`` and ``--self`` when invoked inside a
    ``signet init`` workspace and the user did not pass them.

    Looks for ``pipeline.py`` in the cwd as the marker for "this is
    a scaffold". When found:

    * ``--upstream`` is filled from ``SIGNET_UPSTREAM_URL`` in
      ``.env`` (preferred) or ``.env.example``, parsed with a tiny
      key=value reader to avoid pulling in python-dotenv as a hard
      dep.
    * ``--self`` defaults to ``http://127.0.0.1:8443`` (the
      ``serve`` defaults), so doctor probes the proxy that
      ``signet serve --dev`` would start.

    Both arguments are passed through unchanged when no scaffold is
    detected or when the user supplied a value explicitly.
    """
    if upstream_url and signet_url:
        return upstream_url, signet_url

    pipeline_marker = Path("pipeline.py")
    if not pipeline_marker.exists():
        return upstream_url, signet_url

    if upstream_url is None:
        for candidate in (Path(".env"), Path(".env.example")):
            if not candidate.exists():
                continue
            value = _read_env_var(candidate, "SIGNET_UPSTREAM_URL")
            if value:
                upstream_url = value
                # Round 7 LOW: a hostile .env in the operator's CWD can
                # carry ANSI / OSC escape sequences; sanitize before
                # echoing to stderr so doctor's preflight banner can't
                # rewrite the operator's terminal title.
                click.echo(
                    f"(doctor: auto-detected --upstream="
                    f"{_sanitize_for_terminal(value)} from {candidate})",
                    err=True,
                )
                break

    if signet_url is None:
        signet_url = "http://127.0.0.1:8443"
        click.echo(
            f"(doctor: auto-detected --self={signet_url} from local pipeline.py scaffold)",
            err=True,
        )

    return upstream_url, signet_url


def _read_env_var(path: Path, key: str) -> str | None:
    """Best-effort KEY=value reader for .env-style files.

    Strips matching surrounding quotes and inline ``#`` comments.
    Skips comment lines and lines without ``=``. Does not handle the
    full python-dotenv grammar (no escapes, no multi-line) -- those are
    not what ``signet init`` writes.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        # Allow `export FOO=bar` (sh-compatible env files).
        if line.startswith("export "):
            line = line[len("export ") :]
        k, _, v = line.partition("=")
        if k.strip() != key:
            continue
        v = v.strip()
        # Strip surrounding quotes if matched.
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        # Strip inline comments only when not inside quotes (we already
        # stripped quotes); a literal `#` after whitespace ends the value.
        if " #" in v:
            v = v.split(" #", 1)[0].rstrip()
        return v or None
    return None


# Round 23 LOW (F-R23-9): the R15 F-R15-3 closure tightened the parse-
# time guard on ``signet keys generate-ed25519 --key-id`` to a strict
# ``[A-Za-z0-9_.:\-]+`` allowlist, but the other four ``--key-id`` flag
# sites (``audit verify``, ``audit report``, ``audit compact``, and the
# top-level ``replay`` command) inherit the same ``SIGNET_HMAC_KEY_ID``
# env var WITHOUT the validation. A hostile operator environment
# (compromised CI runner, a malicious .envrc, a copy-pasted env block
# from a phishing message) could set ``SIGNET_HMAC_KEY_ID=$'\x1b[2J'``
# (terminal clear) or a Unicode bidi-override and have it leak into
# the colored error / info banners on the read path. The echo sites
# all sanitize via ``_sanitize_for_terminal`` so the runtime impact
# is bounded -- but promoting the parse-time guard to every ``--key-id``
# option closes the asymmetry between the write surface (key
# generation) and the read surfaces (verify / report / compact /
# replay) uniformly.
def _validate_key_id_charset(key_id: str, *, source: str = "--key-id") -> str:
    """Validate a ``--key-id`` value against the strict charset allowlist.

    The allowlist mirrors the R15 ``keys generate-ed25519`` parse-time
    guard: ``[A-Za-z0-9_.:\\-]+``. Key IDs in practice are short ASCII
    identifiers (``prod-2024-01``, ``kms-rotated-foo``), so the charset
    is more than sufficient; rejecting Unicode at the parser is cleaner
    than depending on the echo-site sanitizer to neutralize bidi /
    control bytes after they have already flowed into log lines.

    Returns the (unchanged) ``key_id`` on success. Raises
    ``click.ClickException`` on empty / non-conforming input.

    Args:
        key_id: The candidate key identifier.
        source: Human-readable name of the flag (e.g. ``"--key-id"``
            or ``"SIGNET_HMAC_KEY_ID"``) for the error message.
    """
    import re as _re

    if not key_id:
        raise click.ClickException(f"{source} must not be empty")
    if not _re.fullmatch(r"[A-Za-z0-9_.:\-]+", key_id):
        # Report the first offending codepoint so the operator can
        # locate the problem (e.g. an invisible trailing space from a
        # copy-paste). Render the value through ``_sanitize_for_terminal``
        # so the error message itself cannot inject ANSI / bidi into
        # the terminal.
        offending: str | None = None
        for ch in key_id:
            if not _re.fullmatch(r"[A-Za-z0-9_.:\-]", ch):
                offending = ch
                break
        offending_repr = f"U+{ord(offending):04X}" if offending is not None else "?"
        raise click.ClickException(
            f"{source} must match [A-Za-z0-9_.:-]+ (got "
            f"{_sanitize_for_terminal(key_id)!r}; first invalid "
            f"codepoint {offending_repr}); key IDs are short ASCII "
            "identifiers like 'prod-2024-01'"
        )
    return key_id


def _parse_hex_secret(value: str, source: str) -> bytes:
    """Decode a hex-encoded HMAC secret with a clear error on failure.

    Strips the optional ``0x`` prefix and any surrounding whitespace --
    real users paste from terminals and copy-managers that add either.
    Re-raises with the source name (env var or flag) so the operator
    knows where to fix the input.
    """
    cleaned = value.strip()
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    try:
        out = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise click.ClickException(
            f"{source} is not valid hex ({exc}). "
            "Generate a fresh secret with `openssl rand -hex 32` "
            "and pass the resulting 64-character string."
        ) from exc
    if len(out) < 16:
        raise click.ClickException(
            f"{source} decoded to {len(out)} bytes; HMAC-SHA256 needs at "
            "least 16 (32 recommended). Use `openssl rand -hex 32`."
        )
    return out


def _load_pipeline_from_path(path: Path) -> Pipeline:
    """Import a Python file and return its ``pipeline`` attribute.

    SECURITY: this calls ``importlib.exec_module`` on the file at
    ``path``, which is arbitrary-code execution by design. Only point
    ``signet serve --config`` at files you control. The CLI prints a
    warning at startup; this function is the actual gun.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("signet_user_config", path)
    if spec is None or spec.loader is None:
        raise click.ClickException(f"could not load config from {path}")
    module = importlib.util.module_from_spec(spec)
    # C5 (v0.1.7): Wrap the exec so the operator sees a one-line
    # ClickException instead of a Python traceback when ``signet lint``
    # / ``signet serve --config`` is pointed at a file with a syntax or
    # import error. The traceback is the wrong UX for a CLI surface --
    # they want to know which file and which line, not the Python call
    # stack. The broad catch is intentional: arbitrary user code may
    # raise anything at import time (NameError, AttributeError, ...).
    try:
        spec.loader.exec_module(module)
    except SyntaxError as exc:
        # Round 9 LOW: user-supplied config files are documented arbitrary
        # code execution, but the error formatter should still scrub
        # control bytes -- a *buggy* (not malicious) config that surfaces
        # an HTTP response in its error message can carry ANSI without
        # either party intending it.
        raise click.ClickException(
            f"syntax error in {path}: {_sanitize_for_terminal(exc.msg)} at line {exc.lineno}"
        ) from exc
    except ImportError as exc:
        raise click.ClickException(
            f"failed to import {path}: {_sanitize_for_terminal(exc)}"
        ) from exc
    except click.ClickException:
        # Don't double-wrap -- _load_pipeline_from_path may be called
        # transitively. Pass through.
        raise
    except Exception as exc:
        raise click.ClickException(
            f"failed to load {path}: {type(exc).__name__}: {_sanitize_for_terminal(exc)}"
        ) from exc
    from signet.core.pipeline import Pipeline as _Pipeline

    pipeline = getattr(module, "pipeline", None)
    if pipeline is None:
        raise click.ClickException(
            f"{path} does not define a `pipeline` variable. "
            "Run `signet init` for a starter template."
        )
    if not isinstance(pipeline, _Pipeline):
        raise click.ClickException(
            f"{path}'s `pipeline` is {type(pipeline).__name__}, "
            "expected signet.core.pipeline.Pipeline"
        )
    return pipeline


_PIPELINE_TEMPLATE = '''"""signet pipeline configuration.

Edit the `pipeline` variable below to register the checks you want.
The CLI will import this file and pass the pipeline to SignetApp.
"""

from signet.checks import (
    ClassificationGateCheck,
    LoopbackTrustCheck,
    OwnerResolutionCheck,
    PromptInjectionCheck,
    RateLimitCheck,
    ScopeDriftCheck,
    ToolCallInspectorCheck,
    ToolSpec,
    RiskTier,
)
from signet.core.pipeline import Pipeline


# A starter pipeline. Adjust to your needs.
pipeline = Pipeline(checks=[
    # ADMISSION
    LoopbackTrustCheck(),  # auto-resolve loopback + Tailscale CGNAT
    OwnerResolutionCheck(require_owner=True),
    RateLimitCheck(capacity=60, refill_per_second=1.0),
    ClassificationGateCheck(),
    # PromptInjectionCheck must be in the default pipeline so
    # ``signet doctor --probe-injection`` reports refusals out of the
    # box on a fresh ``signet init`` scaffold (v0.1.7 F3).
    PromptInjectionCheck(),

    # INSPECTION
    ScopeDriftCheck(),

    # COMMITMENT
    ToolCallInspectorCheck(
        registry={
            # Add your tools here. Example:
            # "list_files": ToolSpec(risk_tier=RiskTier.LOW),
            # "send_email": ToolSpec(
            #     risk_tier=RiskTier.HIGH,
            #     irreversible=True,
            #     dryrun_supported=False,
            # ),
        },
        max_allowed_tier=RiskTier.HIGH,
        allow_critical=False,
    ),
])
'''

_ENV_TEMPLATE = """# signet runtime configuration. Copy to .env, fill in, source before running.

# Upstream LLM (any OpenAI-compatible endpoint)
SIGNET_UPSTREAM_URL=http://localhost:11434/v1

# HMAC key for the audit chain. Generate with:  openssl rand -hex 32
SIGNET_HMAC_SECRET=

# Where to write the audit log (JSONL)
SIGNET_AUDIT_LOG_PATH=./audit.jsonl

# Bind address. 127.0.0.1 = loopback only; 0.0.0.0 = all interfaces.
SIGNET_HOST=127.0.0.1
SIGNET_PORT=8443
"""

# Generated alongside the scaffold so first-time users do not commit
# their HMAC secret or audit-log contents on first push.
_GITIGNORE_TEMPLATE = """# signet -- keep secrets and audit logs out of version control.
.env
.env.*
!.env.example
*.jsonl
__pycache__/
*.pyc
"""

# Minimal-but-real client snippet so users do not have to read the
# README to find out how to call signet from Python.
_CLIENT_EXAMPLE_TEMPLATE = '''"""client_example.py -- call signet from Python.

Two ways shown:
1. Plain httpx -- works with no extras installed.
2. wrap_openai -- drop-in replacement for the openai SDK that points
   at signet and injects the X-Commit-Owner header on every request.
   Requires the `openai` extra: `pip install signet-sign[openai]`.

Run after starting `signet serve --upstream <URL> --dev` in another
terminal.
"""

from __future__ import annotations

import httpx


SIGNET_URL = "http://localhost:8443/v1"


def call_with_httpx() -> None:
    """Plain HTTP -- no SDK needed."""
    resp = httpx.post(
        f"{SIGNET_URL}/chat/completions",
        headers={
            "Content-Type": "application/json",
            # Required: caller-asserted commit owner. Any of these
            # three header forms is accepted:
            #   X-Commit-Owner: human:<principal>
            #   X-Agent-Id:     agent:<id>
            #   X-Policy-Name:  <policy>
            "X-Commit-Owner": "human:alice@example.com",
        },
        json={
            "model": "llama3.2:1b",  # change to a model your upstream actually has
            "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
            "max_tokens": 10,
        },
        timeout=60.0,
    )
    print("status:", resp.status_code)
    print("upstream:", resp.headers.get("X-Signet-Upstream"))
    print("upstream-status:", resp.headers.get("X-Signet-Upstream-Status"))
    print("receipt:", resp.headers.get("X-Signet-Receipt", "(no audit log configured)"))
    print("body:", resp.json())


def call_with_openai_sdk() -> None:
    """Drop-in: existing OpenAI SDK code points at signet."""
    try:
        from openai import OpenAI
    except ImportError:
        print("install with: pip install signet-sign[openai]")
        return

    from signet.adapters.openai import wrap_openai

    client = wrap_openai(
        OpenAI(api_key="not-used-by-local-llm"),
        signet_url=SIGNET_URL,
        owner="human:alice@example.com",
    )
    resp = client.chat.completions.create(
        model="llama3.2:1b",
        messages=[{"role": "user", "content": "Reply with exactly: pong"}],
        max_tokens=10,
    )
    print(resp.choices[0].message.content)


if __name__ == "__main__":
    call_with_httpx()
    print("---")
    call_with_openai_sdk()
'''


if __name__ == "__main__":
    main()
