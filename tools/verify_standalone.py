#!/usr/bin/env python3
"""Standalone, zero-install verifier for signet audit chains and receipts.

This single file lets an auditor who does NOT trust the chain operator --
and who has NOT installed signet -- verify, from the receipt bytes / log
file plus a key alone:

  * that an HMAC audit log is intact (no entry altered, inserted,
    deleted, or reordered), and
  * that the log is complete (no sequence-number gaps), and
  * that an ``X-Signet-Receipt`` header is a genuine signature over the
    entry it claims to cover.

It deliberately has **no ``import signet``**. It depends only on the
Python standard library, plus -- only when actually needed -- two small
optional packages:

  * ``rfc8785``      -- to verify chains/receipts written with JCS
                        canonicalization (``canon='jcs'``).
  * ``cryptography`` -- to verify Ed25519 receipts.
  * ``dilithium-py`` -- to verify ML-DSA-65 (post-quantum) receipts.

If a log uses only the default (legacy) canonicalization and you only
need HMAC + contiguity, this script runs on a bare Python install.

Hand this file to a regulator. They can read every line of it, confirm
it does nothing but hash and compare, and run it against your log with
your public key. No trust in signet -- or in you -- required.

----------------------------------------------------------------------
ANTI-DRIFT: the canonicalization below MUST stay byte-identical to
``signet.audit.chain._serialize_for_signing``. The test
``tests/unit/test_standalone_verifier.py`` imports both and asserts they
produce identical bytes for a battery of entries; if you change the
in-tree serializer, that test fails until you mirror the change here.
----------------------------------------------------------------------

Usage::

    # Verify a chain's integrity + completeness (HMAC mode):
    python verify_standalone.py chain audit.jsonl --secret <hex> --key-id k1

    # Verify a single Ed25519 receipt against the entry it covers:
    python verify_standalone.py receipt \\
        --entry @entry.json --header "$(cat receipt.txt)" \\
        --alg ed25519 --pub-pem signet.pub.pem --key-id signet-prod

Exit codes: 0 = verified, 2 = a problem was found, 1 = usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from typing import Any

# --- canonicalization (mirror of signet.audit.chain) -----------------

_JS_MAX_SAFE_INT = 2**53 - 1
CANON_FIELD = "_canon"
CANON_LEGACY = "legacy"
CANON_JCS_V1 = "jcs/v1"
KEY_ID_FIELD = "_signing_key_id"
SEQ_FIELD = "_seq"


def _ijson_safe(obj: Any) -> Any:
    """Encode out-of-range integers as decimal strings (RFC 7493)."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return str(obj) if abs(obj) > _JS_MAX_SAFE_INT else obj
    if isinstance(obj, dict):
        return {k: _ijson_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_ijson_safe(v) for v in obj]
    return obj


def serialize_for_signing(entry_dict: dict[str, Any]) -> bytes:
    """Canonical bytes a signet entry's HMAC/signature is computed over.

    Operates on the raw on-disk dict (each JSONL line). Drops ``hmac``
    (the value being computed) and selects canonicalization from the
    entry's own ``metadata._canon`` marker -- absent means legacy.
    """
    d = dict(entry_dict)
    d.pop("hmac", None)
    meta = d.get("metadata")
    canon = meta.get(CANON_FIELD, CANON_LEGACY) if isinstance(meta, dict) else CANON_LEGACY
    if canon == CANON_LEGACY:
        return json.dumps(
            d,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=False,
        ).encode("utf-8")
    if canon == CANON_JCS_V1:
        try:
            import rfc8785
        except ModuleNotFoundError:
            raise SystemExit(
                "this log uses JCS canonicalization; install the 'rfc8785' "
                "package to verify it (pip install rfc8785)"
            ) from None
        return rfc8785.dumps(_ijson_safe(d))
    raise SystemExit(f"unknown canonicalization scheme {canon!r} in an entry")


# --- chain verification ----------------------------------------------


def verify_chain(
    log_path: str,
    secret_hex: str,
    key_id: str,
    *,
    expected_start: int | None = None,
    expected_end: int | None = None,
) -> dict[str, Any]:
    """Walk the JSONL log; return a structured result dict.

    ``expected_start`` / ``expected_end`` assert the chain spans a known
    sequence range -- the way an external auditor catches head/tail
    truncation when they know the true endpoints out-of-band.
    """
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        raise SystemExit("--secret must be hex") from None

    breaks: list[str] = []
    prev_hmac = ""
    seqs: list[int] = []
    total = 0
    with open(log_path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh):
            raw = raw.strip()
            if not raw:
                continue
            total += 1
            try:
                d = json.loads(raw)
            except json.JSONDecodeError as exc:
                breaks.append(f"line {lineno + 1}: not valid JSON: {exc}")
                break
            ent_hmac = d.get("hmac", "")
            ent_prev = d.get("prev_hmac", "")
            # Link check.
            if ent_prev != prev_hmac:
                breaks.append(
                    f"line {lineno + 1}: link_mismatch (prev_hmac does not "
                    f"match previous entry's hmac) -- insertion/deletion/reorder"
                )
            # Key + self HMAC check.
            meta = d.get("metadata") or {}
            ent_key = meta.get(KEY_ID_FIELD)
            if ent_key != key_id:
                breaks.append(
                    f"line {lineno + 1}: signed with key_id={ent_key!r}, expected {key_id!r}"
                )
            else:
                expected = hmac.new(secret, serialize_for_signing(d), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, str(ent_hmac)):
                    breaks.append(f"line {lineno + 1}: self_mismatch (entry was modified)")
            # Collect sequence numbers for the contiguity pass.
            s = meta.get(SEQ_FIELD)
            if isinstance(s, int) and not isinstance(s, bool):
                seqs.append(s)
            prev_hmac = str(ent_hmac)

    # Contiguity pass over collected sequence numbers.
    gaps: list[str] = []
    if seqs:
        from itertools import pairwise

        for a, b in pairwise(seqs):
            if b == a + 1:
                continue
            if b <= a:
                gaps.append(f"out-of-order/duplicate sequence: {a} then {b}")
            else:
                gaps.append(f"missing sequence numbers {a + 1}..{b - 1}")

    if expected_start is not None and seqs and seqs[0] != expected_start:
        gaps.append(
            f"expected to start at seq {expected_start} but starts at {seqs[0]} "
            f"({'head truncated' if seqs[0] > expected_start else 'unexpected earlier entries'})"
        )
    if expected_end is not None and seqs and seqs[-1] != expected_end:
        gaps.append(
            f"expected to end at seq {expected_end} but ends at {seqs[-1]} "
            f"({'tail truncated' if seqs[-1] < expected_end else 'unexpected later entries'})"
        )

    return {
        "total_entries": total,
        "numbered_entries": len(seqs),
        "first_seq": seqs[0] if seqs else None,
        "last_seq": seqs[-1] if seqs else None,
        "integrity_breaks": breaks,
        "contiguity_gaps": gaps,
        "ok": not breaks and not gaps,
    }


# --- receipt verification --------------------------------------------


def parse_receipt(header_value: str) -> dict[str, str] | None:
    fields: dict[str, str] = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        fields[k.strip()] = v.strip()
    if fields.get("signet") != "v1":
        return None
    if not all(k in fields for k in ("entry", "key", "sig")):
        return None
    fields.setdefault("alg", "hmac-sha256")
    return fields


def verify_receipt(args: argparse.Namespace) -> bool:
    entry_raw = args.entry
    if entry_raw.startswith("@"):
        with open(entry_raw[1:], encoding="utf-8") as fh:
            entry_raw = fh.read()
    entry = json.loads(entry_raw)
    parsed = parse_receipt(args.header)
    if parsed is None:
        print("receipt header is malformed or not v1", file=sys.stderr)
        return False
    if parsed["entry"] != entry.get("entry_id"):
        print("receipt entry-id does not match the supplied entry", file=sys.stderr)
        return False
    if args.key_id and parsed["key"] != args.key_id:
        print(f"receipt key-id {parsed['key']!r} != expected {args.key_id!r}", file=sys.stderr)
        return False
    payload = serialize_for_signing(entry)
    alg = parsed["alg"]

    if alg == "hmac-sha256":
        if not args.secret:
            raise SystemExit("hmac-sha256 receipts need --secret <hex>")
        expected = hmac.new(bytes.fromhex(args.secret), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, parsed["sig"])

    if alg == "ed25519":
        if not args.pub_pem:
            raise SystemExit("ed25519 receipts need --pub-pem <file>")
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        with open(args.pub_pem, "rb") as fh:
            pub = load_pem_public_key(fh.read())
        try:
            pub.verify(bytes.fromhex(parsed["sig"]), payload)  # type: ignore[call-arg]
            return True
        except InvalidSignature:
            return False

    if alg == "ml-dsa-65":
        if not args.pub_raw:
            raise SystemExit("ml-dsa-65 receipts need --pub-raw <file>")
        from dilithium_py.ml_dsa import ML_DSA_65

        with open(args.pub_raw, "rb") as fh:
            pub_bytes = fh.read()
        try:
            return bool(ML_DSA_65.verify(pub_bytes, payload, bytes.fromhex(parsed["sig"])))
        except Exception:
            return False

    raise SystemExit(f"unknown receipt alg {alg!r}")


# --- CLI -------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("chain", help="verify an HMAC audit log's integrity + completeness")
    pc.add_argument("log_path")
    pc.add_argument("--secret", required=True, help="HMAC secret as hex")
    pc.add_argument("--key-id", default="k1", help="expected signing key id (default: k1)")
    pc.add_argument(
        "--expect-start", type=int, default=None, help="assert the first sequence number"
    )
    pc.add_argument(
        "--expect-end",
        type=int,
        default=None,
        help="assert the last sequence number (catches tail truncation)",
    )
    pc.add_argument("--json", action="store_true", help="emit JSON instead of text")

    pr = sub.add_parser("receipt", help="verify an X-Signet-Receipt header against its entry")
    pr.add_argument("--entry", required=True, help="entry JSON, or @file")
    pr.add_argument("--header", required=True, help="the X-Signet-Receipt header value")
    pr.add_argument("--alg", help="expected alg (informational; the header's alg is used)")
    pr.add_argument("--key-id", help="expected key id (optional cross-check)")
    pr.add_argument("--secret", help="HMAC secret as hex (hmac-sha256 receipts)")
    pr.add_argument("--pub-pem", help="Ed25519 public key PEM file")
    pr.add_argument("--pub-raw", help="ML-DSA-65 raw public key file")

    args = p.parse_args(argv)

    if args.cmd == "chain":
        result = verify_chain(
            args.log_path,
            args.secret,
            args.key_id,
            expected_start=args.expect_start,
            expected_end=args.expect_end,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            if result["ok"]:
                print(
                    f"OK: {result['total_entries']} entries, chain intact and complete"
                    + (
                        f" (seq {result['first_seq']}..{result['last_seq']})"
                        if result["numbered_entries"]
                        else " (no sequence numbers present)"
                    )
                )
            else:
                print(f"BROKEN: {result['total_entries']} entries")
                for b in result["integrity_breaks"]:
                    print(f"  integrity: {b}")
                for g in result["contiguity_gaps"]:
                    print(f"  completeness: {g}")
        return 0 if result["ok"] else 2

    if args.cmd == "receipt":
        ok = verify_receipt(args)
        print("VALID" if ok else "INVALID")
        return 0 if ok else 2

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
