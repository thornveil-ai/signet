"""ReceiptSigner -- emit X-Signet-Receipt headers callers can verify offline.

Every response signet returns carries a *decision receipt* -- a short
signed summary of what the gate did with the request. Callers can:

1. Hand the receipt to an auditor as proof the gate ran.
2. Verify the receipt against the signing key (or the public verify
   key when using asymmetric signers), confirming the response did pass
   through a known signet instance.
3. Reconstruct the receipt later from the audit log to prove
   non-tampering.

Receipt format (HTTP header value):

    signet=v1; alg=<alg>; entry=<entry_id>; key=<key_id>; sig=<hex_sig>

* ``v1`` -- wire version. Bump if the canonicalization or fields change.
* ``alg`` -- signing algorithm. ``hmac-sha256`` (default, no extra
  deps) or ``ed25519`` (asymmetric, requires ``cryptography``).
* ``entry`` -- audit row UUID this receipt covers.
* ``key`` -- opaque signing-key ID; the verifier uses it to look up the
  key on its own keyring.
* ``sig`` -- hex signature over the canonical entry payload.

**Choosing a signer:**

* :class:`HmacReceiptSigner` (default) -- fast, no extra deps, but
  anyone who can verify can also forge. Use when verifier and proxy
  share a trust domain (your own auditor reads your own logs).
* :class:`Ed25519ReceiptSigner` -- asymmetric, requires
  ``pip install signet-sign[ed25519]``. The proxy holds the private
  key; verifiers hold only the public key and **cannot forge**. Use
  when handing receipts to outside parties (customers, regulators).
  Verifiers can be issued the public key out-of-band (DNS TXT, JWKS
  endpoint, manual delivery) and verify entirely offline.

This module is signing-only; verification logic lives on each signer
for symmetry but the canonical chain verifier in
:mod:`signet.audit.verifier` is the recommended path for any audit
walk longer than one entry.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, Any, Protocol

from signet.audit.chain import _serialize_for_signing
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

#: Wire version embedded in every receipt header.
RECEIPT_VERSION = "v1"

#: Algorithm tag for the built-in HMAC-SHA256 signer.
ALG_HMAC_SHA256 = "hmac-sha256"

#: Algorithm tag for the asymmetric Ed25519 signer.
ALG_ED25519 = "ed25519"

#: Algorithm tag for the post-quantum ML-DSA-65 (FIPS 204) signer.
ALG_ML_DSA_65 = "ml-dsa-65"

#: Header value template. Order is fixed so receipts are byte-stable
#: across runs given the same inputs. Parsers must be tolerant to extra
#: ``;``-separated fields a future version might add.
_HEADER_FORMAT = "signet={ver}; alg={alg}; entry={entry}; key={key}; sig={sig}"

#: Canonical header name the proxy sets. Configurable in ServerConfig.
DEFAULT_HEADER_NAME = "X-Signet-Receipt"


class ReceiptSigner(Protocol):
    """Protocol every receipt signer implements.

    Implement this if you want to use an asymmetric primitive (ed25519,
    RSA-PSS) instead of the built-in HMAC. ``alg`` must be a stable,
    distinct identifier -- verifiers reject receipts whose ``alg`` does
    not match what they expect.
    """

    @property
    def alg(self) -> str: ...

    def sign(self, entry: AuditEntry) -> str: ...

    def verify(self, header_value: str, entry: AuditEntry) -> bool: ...


class HmacReceiptSigner:
    """HMAC-SHA256 signer.

    Construct with the same :class:`KeyRing` used by the audit chain.
    The signer always uses the ring's *active* key; verifiers can hold
    a ring with multiple legacy keys to verify older receipts after a
    rotation.

    See module docstring for the symmetric-primitive caveat.
    """

    alg = ALG_HMAC_SHA256

    def __init__(self, keyring: KeyRing) -> None:
        self._keyring = keyring

    def sign(self, entry: AuditEntry) -> str:
        """Return a header value for the given audit entry.

        Pass an entry that has already been written to the audit chain
        so verifiers can correlate the receipt with chain state.
        """
        active = self._keyring.active
        payload = _serialize_for_signing(entry)
        sig = hmac.new(active.secret, payload, hashlib.sha256).hexdigest()
        return _HEADER_FORMAT.format(
            ver=RECEIPT_VERSION,
            alg=self.alg,
            entry=entry.entry_id,
            key=active.key_id,
            sig=sig,
        )

    def verify(self, header_value: str, entry: AuditEntry) -> bool:
        """Return ``True`` iff the receipt matches ``entry`` under
        this signer's algorithm and a key on the ring.

        Rejects (returns False) when:

        * the header is malformed or version != v1
        * the header's ``alg`` is not ``hmac-sha256``
        * the entry-id mismatches
        * the key-id is unknown to the ring
        * the signature does not match (constant-time compare)
        """
        parsed = parse_header(header_value)
        if parsed is None:
            return False
        if parsed.get("alg") != self.alg:
            return False
        if parsed["entry"] != entry.entry_id:
            return False
        key = self._keyring.get(parsed["key"])
        if key is None:
            return False
        payload = _serialize_for_signing(entry)
        expected = hmac.new(key.secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, parsed["sig"])


class Ed25519ReceiptSigner:
    """Asymmetric ed25519 signer.

    Construct with an ed25519 private key (for signing) plus a stable
    ``key_id`` that goes into the receipt's ``key=`` field. Verifiers
    construct with the matching ed25519 public key and the same
    ``key_id``. The verifier holds *only* the public key -- it cannot
    forge new receipts.

    Use this when you want to hand receipts to outside parties as
    cryptographic proof that signet (specifically, the holder of the
    private key) made the audit decision the receipt summarizes.

    Requires ``pip install signet-sign[ed25519]``.

    Key generation: ``signet keys generate-ed25519 --out signet.key``
    writes a private key in PEM format with mode 0600. The matching
    public key is printed; share it with verifiers via DNS TXT, a
    JWKS endpoint, or out-of-band delivery.

    Example::

        from signet.server.app import SignetApp
        from signet.server.receipt import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.from_pem(
            private_pem_path="/etc/signet/signet.key",
            key_id="signet-prod-2026q2",
        )
        app = SignetApp(config=cfg, pipeline=pipeline, receipt_signer=signer)
    """

    alg = ALG_ED25519

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey | None,
        public_key: Ed25519PublicKey,
        key_id: str,
    ) -> None:
        if not key_id:
            raise ValueError("key_id must be a non-empty string")
        self._private = private_key
        self._public = public_key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @classmethod
    def generate(cls, key_id: str) -> Ed25519ReceiptSigner:
        """Generate a fresh ed25519 keypair for testing.

        Production deployments should use :meth:`from_pem` against a key
        generated externally and stored in a secrets manager.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key(), key_id=key_id)

    @classmethod
    def from_pem(
        cls,
        *,
        private_pem_path: str | None = None,
        public_pem_path: str | None = None,
        key_id: str,
        password: bytes | None = None,
    ) -> Ed25519ReceiptSigner:
        """Load a signer from PEM-encoded key file(s).

        - Pass ``private_pem_path`` to construct a *signer* (proxy).
          The corresponding public key is derived automatically.
        - Pass only ``public_pem_path`` to construct a *verifier*
          (auditor). ``sign()`` on a verifier-only instance raises.
        - Pass both to keep them explicit (e.g. when private and
          public live in separate locations).
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        priv: Ed25519PrivateKey | None = None
        pub: Ed25519PublicKey | None = None
        if private_pem_path is not None:
            with open(private_pem_path, "rb") as f:
                loaded_priv = serialization.load_pem_private_key(f.read(), password=password)
            if not isinstance(loaded_priv, Ed25519PrivateKey):
                raise ValueError(
                    f"{private_pem_path}: expected an ed25519 private key, "
                    f"got {type(loaded_priv).__name__}"
                )
            priv = loaded_priv
            pub = priv.public_key()
        if public_pem_path is not None:
            with open(public_pem_path, "rb") as f:
                loaded_pub = serialization.load_pem_public_key(f.read())
            if not isinstance(loaded_pub, Ed25519PublicKey):
                raise ValueError(
                    f"{public_pem_path}: expected an ed25519 public key, "
                    f"got {type(loaded_pub).__name__}"
                )
            if pub is not None and loaded_pub.public_bytes_raw() != pub.public_bytes_raw():
                raise ValueError(
                    "public key from --public-pem-path does not match the public "
                    "key derived from --private-pem-path"
                )
            pub = loaded_pub
        if pub is None:
            raise ValueError("must supply at least one of private_pem_path or public_pem_path")
        return cls(private_key=priv, public_key=pub, key_id=key_id)

    def public_pem(self) -> bytes:
        """Return the public key as PEM bytes for sharing with verifiers."""
        from cryptography.hazmat.primitives import serialization

        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, entry: AuditEntry) -> str:
        """Return a header value for the given audit entry.

        Raises ``RuntimeError`` if this signer was constructed without
        a private key (verify-only instance).
        """
        if self._private is None:
            raise RuntimeError(
                "this Ed25519ReceiptSigner is verify-only -- no private key was loaded; cannot sign"
            )
        payload = _serialize_for_signing(entry)
        sig = self._private.sign(payload).hex()
        return _HEADER_FORMAT.format(
            ver=RECEIPT_VERSION,
            alg=self.alg,
            entry=entry.entry_id,
            key=self._key_id,
            sig=sig,
        )

    def verify(self, header_value: str, entry: AuditEntry) -> bool:
        """Return ``True`` iff the receipt matches ``entry`` under this
        signer's algorithm and key_id.

        Rejects (returns ``False``) when:

        * the header is malformed or version != v1
        * the header's ``alg`` is not ``ed25519``
        * the entry-id mismatches
        * the key-id mismatches this signer's expected key_id
        * the signature does not verify against the public key
        """
        from cryptography.exceptions import InvalidSignature

        parsed = parse_header(header_value)
        if parsed is None:
            return False
        if parsed.get("alg") != self.alg:
            return False
        if parsed["entry"] != entry.entry_id:
            return False
        if parsed["key"] != self._key_id:
            return False
        try:
            sig = bytes.fromhex(parsed["sig"])
        except ValueError:
            return False
        payload = _serialize_for_signing(entry)
        try:
            self._public.verify(sig, payload)
        except InvalidSignature:
            return False
        return True


def _load_mldsa_backend() -> Any:
    """Return the ML-DSA-65 implementation, or raise a helpful error.

    Resolved lazily so the post-quantum dependency is only required by
    deployments that actually emit PQ receipts (``signet-sign[pq]``).
    Today the backend is the pure-Python ``dilithium-py`` reference
    implementation of FIPS 204; when a hardware-backed or OpenSSL 3.5
    ML-DSA lands in ``cryptography`` this loader is the single place to
    add it.
    """
    try:
        from dilithium_py.ml_dsa import ML_DSA_65
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via skip
        raise RuntimeError(
            "ML-DSA-65 receipts require a post-quantum backend; "
            "install it with: pip install signet-sign[pq]"
        ) from exc
    return ML_DSA_65


class MLDSAReceiptSigner:
    """Post-quantum ML-DSA-65 (FIPS 204) receipt signer.

    The lattice-based sibling of :class:`Ed25519ReceiptSigner`: the proxy
    holds the private key and signs; verifiers hold only the public key
    and cannot forge. Use it when receipts must stay verifiable against a
    "harvest-now, decrypt-later" adversary -- the security of an Ed25519
    receipt rests on assumptions a future quantum computer breaks, while
    ML-DSA's rest on module-lattice problems believed quantum-resistant.

    Trade-offs to know before reaching for this:

    * **Header size.** An ML-DSA-65 signature is ~3.3 KB (vs 64 bytes for
      Ed25519), so the hex-encoded ``X-Signet-Receipt`` header is ~6.6 KB.
      Confirm your ingress and any header-size limits tolerate it.
    * **Keys are raw bytes**, not PEM -- there is no universally-deployed
      PEM OID for ML-DSA yet. Public key: 1952 bytes; private key: 4032
      bytes. Share the public key out-of-band as you would a PEM.
    * **Backend.** Requires ``signet-sign[pq]`` (the pure-Python
      ``dilithium-py`` reference implementation of FIPS 204). It is
      functionally correct and fully verifiable but not constant-time;
      treat it as the interoperable default until a hardened/FIPS-
      validated ML-DSA backend is wired through :func:`_load_mldsa_backend`.
      This signer is marked EXPERIMENTAL for that reason.

    Example::

        signer = MLDSAReceiptSigner.generate(key_id="signet-pq-2026q2")
        # Persist signer.private_bytes() (0600) and publish
        # signer.public_bytes() to verifiers.
    """

    alg = ALG_ML_DSA_65

    def __init__(
        self,
        *,
        private_key: bytes | None,
        public_key: bytes,
        key_id: str,
    ) -> None:
        if not key_id:
            raise ValueError("key_id must be a non-empty string")
        if not isinstance(public_key, (bytes, bytearray)) or not public_key:
            raise ValueError("public_key must be non-empty raw bytes")
        if private_key is not None and (
            not isinstance(private_key, (bytes, bytearray)) or not private_key
        ):
            raise ValueError("private_key, when provided, must be non-empty raw bytes")
        self._private = bytes(private_key) if private_key is not None else None
        self._public = bytes(public_key)
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @classmethod
    def generate(cls, key_id: str) -> MLDSAReceiptSigner:
        """Generate a fresh ML-DSA-65 keypair.

        Production deployments should generate the key once, store the
        private half in a secrets manager (0600), and construct via
        :meth:`from_raw` / :meth:`from_files`.
        """
        backend = _load_mldsa_backend()
        public_key, private_key = backend.keygen()
        return cls(private_key=private_key, public_key=public_key, key_id=key_id)

    @classmethod
    def from_raw(
        cls,
        *,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
        key_id: str,
    ) -> MLDSAReceiptSigner:
        """Construct from raw key bytes.

        Pass ``private_key`` to build a signer (proxy); pass only
        ``public_key`` to build a verifier (auditor). When only the
        private key is supplied the public key is NOT derivable from it
        cheaply, so at least one of the two must be present and a
        verifier needs the public key explicitly.
        """
        if public_key is None:
            raise ValueError(
                "public_key is required (it cannot be re-derived from an "
                "ML-DSA private key without the original keygen seed)"
            )
        return cls(private_key=private_key, public_key=public_key, key_id=key_id)

    @classmethod
    def from_files(
        cls,
        *,
        private_key_path: str | None = None,
        public_key_path: str | None = None,
        key_id: str,
    ) -> MLDSAReceiptSigner:
        """Load a signer/verifier from raw key file(s)."""
        priv: bytes | None = None
        pub: bytes | None = None
        if private_key_path is not None:
            with open(private_key_path, "rb") as f:
                priv = f.read()
        if public_key_path is not None:
            with open(public_key_path, "rb") as f:
                pub = f.read()
        return cls.from_raw(private_key=priv, public_key=pub, key_id=key_id)

    def public_bytes(self) -> bytes:
        """Return the raw public key for sharing with verifiers."""
        return self._public

    def private_bytes(self) -> bytes:
        """Return the raw private key for secrets-manager storage.

        Raises ``RuntimeError`` on a verify-only instance.
        """
        if self._private is None:
            raise RuntimeError("this MLDSAReceiptSigner is verify-only -- no private key")
        return self._private

    def sign(self, entry: AuditEntry) -> str:
        """Return a header value for ``entry``.

        Raises ``RuntimeError`` if constructed without a private key.
        """
        if self._private is None:
            raise RuntimeError(
                "this MLDSAReceiptSigner is verify-only -- no private key was loaded; cannot sign"
            )
        backend = _load_mldsa_backend()
        payload = _serialize_for_signing(entry)
        sig = backend.sign(self._private, payload).hex()
        return _HEADER_FORMAT.format(
            ver=RECEIPT_VERSION,
            alg=self.alg,
            entry=entry.entry_id,
            key=self._key_id,
            sig=sig,
        )

    def verify(self, header_value: str, entry: AuditEntry) -> bool:
        """Return ``True`` iff the receipt matches ``entry`` under this
        signer's algorithm, key_id, and public key.

        Rejects (returns ``False``) when the header is malformed, the
        version/alg/entry-id/key-id mismatch, the signature is not valid
        hex, or the lattice verification fails.
        """
        parsed = parse_header(header_value)
        if parsed is None:
            return False
        if parsed.get("alg") != self.alg:
            return False
        if parsed["entry"] != entry.entry_id:
            return False
        if parsed["key"] != self._key_id:
            return False
        try:
            sig = bytes.fromhex(parsed["sig"])
        except ValueError:
            return False
        backend = _load_mldsa_backend()
        payload = _serialize_for_signing(entry)
        try:
            return bool(backend.verify(self._public, payload, sig))
        except Exception:
            # A reference backend may raise on malformed signatures
            # rather than returning False; treat any failure as "does
            # not verify" so a bad receipt never reads as valid.
            return False


def parse_header(value: str) -> dict[str, str] | None:
    """Best-effort parse of an ``X-Signet-Receipt`` header value.

    Accepts the canonical
    ``signet=v1; alg=<alg>; entry=...; key=...; sig=...`` shape and
    tolerates extra ``;``-separated fields the future may add.

    Backward compatibility: receipts emitted before the ``alg`` field
    existed (pre-v0.1.0 dev builds) are accepted and reported as
    ``alg = "hmac-sha256"`` -- that was the only algorithm that ever
    shipped without an explicit tag. Reject if you want strict.

    Returns ``None`` when required fields are absent or the version
    is not v1.
    """
    fields: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        fields[k.strip()] = v.strip()
    if fields.get("signet") != RECEIPT_VERSION:
        return None
    if not all(k in fields for k in ("entry", "key", "sig")):
        return None
    fields.setdefault("alg", ALG_HMAC_SHA256)
    return fields
