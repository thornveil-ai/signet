"""KeyRing -- secret key management for the HMAC audit chain.

A :class:`KeyRing` holds the keys used to sign and verify audit entries.
The simplest deployment uses a single key for the chain's lifetime; richer
deployments rotate keys periodically and need to verify entries signed
under previous keys.

Key rotation produces multiple *eras*. Each era is a contiguous run of
entries signed under the same key. Entries written after a rotation use
the new key but are still chained (via ``prev_hmac``) to the last entry of
the previous era. Verification walks the whole chain, switching keys at
era boundaries.

This module is crypto-free at the interface -- it just stores key bytes.
The actual HMAC computation lives in :mod:`signet.audit.chain`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

#: Algorithm identifier for symmetric HMAC-SHA256 keys (default, zero extra deps).
ALG_HMAC_SHA256 = "hmac-sha256"

#: Algorithm identifier for asymmetric Ed25519 keys (requires ``signet-sign[ed25519]``).
ALG_ED25519 = "ed25519"


def _load_ed25519_primitives() -> tuple[type[Ed25519PrivateKey], type[Ed25519PublicKey]]:
    """Lazy-import cryptography's Ed25519 classes so HMAC-only deployments stay dependency-free."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey as _Priv,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as _Pub,
        )
    except ModuleNotFoundError as exc:  # pragma: no cover - covered via optional-dep guard
        raise RuntimeError(
            "Ed25519 audit keys require the 'cryptography' package; "
            "install it with: pip install signet-sign[ed25519]"
        ) from exc
    return _Priv, _Pub


@dataclass(frozen=True, slots=True)
class Key:
    """A single symmetric HMAC-SHA256 signing key with an opaque identifier.

    Attributes:
        key_id: Stable identifier for this key. Conventionally a short
            string like ``"k1"``, ``"k2"``, or a date stamp like
            ``"2026-05-03"``. Embedded in audit entries so the verifier
            knows which key to use.
        secret: The HMAC secret. Treat as cleartext; this object should
            never be serialized to logs or telemetry.
    """

    key_id: str
    secret: bytes

    def __post_init__(self) -> None:
        # Round 7 LOW-2: reject whitespace-only key_ids. ``"   "`` is
        # truthy in Python so the bare ``if not self.key_id`` check
        # slipped them through, producing unreadable verify reports
        # and a defense-in-depth gap (a config file with a broken
        # escape could silently end up with ``"\n"`` or ``"   "`` as
        # the key_id without anyone noticing).
        if not self.key_id or not self.key_id.strip():
            raise ValueError("Key.key_id must be a non-empty, non-whitespace string")
        if len(self.secret) < 16:
            raise ValueError(
                f"Key.secret must be at least 16 bytes (got {len(self.secret)}); "
                "32 bytes recommended for HMAC-SHA256"
            )

    @property
    def algorithm(self) -> str:
        """Algorithm tag embedded when non-legacy signing is used."""
        return ALG_HMAC_SHA256

    @property
    def can_sign(self) -> bool:
        """Symmetric HMAC keys can always sign and verify."""
        return True

    def sign(self, payload: bytes) -> str:
        """Compute hex-encoded HMAC-SHA256 over ``payload``."""
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature_hex: str) -> bool:
        """Constant-time verification of ``signature_hex`` against ``payload``."""
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature_hex)

    def __repr__(self) -> str:
        # Override the default dataclass repr so the secret never lands in
        # logs, exception tracebacks, or REPL output. The length is exposed
        # because it's useful for diagnosing key-size misconfiguration and
        # does not weaken the secret.
        return f"Key(key_id={self.key_id!r}, secret=<{len(self.secret)} bytes redacted>)"

    @classmethod
    def generate(cls, key_id: str, *, length: int = 32) -> Key:
        """Generate a new key with a cryptographically-random secret.

        ``length`` defaults to 32 bytes (256 bits), matching the HMAC-SHA256
        block-internal state size -- the standard recommendation.
        """
        return cls(key_id=key_id, secret=secrets.token_bytes(length))


@dataclass(frozen=True, slots=True)
class Ed25519Key:
    """Asymmetric Ed25519 key for public-key-verifiable audit chains.

    Holders of the private key can sign new audit entries; external
    auditors holding only :meth:`public_only` can verify every entry
    offline without possessing any forging capability.

    Requires ``pip install signet-sign[ed25519]``.
    """

    key_id: str
    public_bytes: bytes
    private_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if not self.key_id or not self.key_id.strip():
            raise ValueError("Ed25519Key.key_id must be a non-empty, non-whitespace string")
        if len(self.public_bytes) != 32:
            raise ValueError(
                f"Ed25519Key.public_bytes must be exactly 32 raw bytes (got {len(self.public_bytes)})"
            )
        if self.private_bytes is not None and len(self.private_bytes) != 32:
            raise ValueError(
                f"Ed25519Key.private_bytes must be exactly 32 raw bytes (got {len(self.private_bytes)})"
            )

    @property
    def algorithm(self) -> str:
        return ALG_ED25519

    @property
    def can_sign(self) -> bool:
        """True when private key material is loaded; False for verify-only public keys."""
        return self.private_bytes is not None

    def public_only(self) -> Ed25519Key:
        """Return a verify-only copy with private key material stripped."""
        return Ed25519Key(key_id=self.key_id, public_bytes=self.public_bytes, private_bytes=None)

    def sign(self, payload: bytes) -> str:
        """Sign ``payload`` with Ed25519 and return a 128-char lowercase hex signature."""
        if self.private_bytes is None:
            raise ValueError(
                f"Ed25519Key {self.key_id!r} is verify-only (no private_bytes); cannot sign"
            )
        priv_cls, _ = _load_ed25519_primitives()
        priv = priv_cls.from_private_bytes(self.private_bytes)
        return priv.sign(payload).hex()

    def verify(self, payload: bytes, signature_hex: str) -> bool:
        """Verify a hex-encoded Ed25519 signature over ``payload`` using ``public_bytes``."""
        try:
            sig_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        if len(sig_bytes) != 64:
            return False
        _, pub_cls = _load_ed25519_primitives()
        from cryptography.exceptions import InvalidSignature

        pub = pub_cls.from_public_bytes(self.public_bytes)
        try:
            pub.verify(sig_bytes, payload)
        except InvalidSignature:
            return False
        return True

    def __repr__(self) -> str:
        priv_state = "<32 bytes redacted>" if self.private_bytes is not None else "None"
        return (
            f"Ed25519Key(key_id={self.key_id!r}, "
            f"public_bytes={self.public_bytes.hex()[:12]}..., "
            f"private_bytes={priv_state})"
        )

    @classmethod
    def generate(cls, key_id: str) -> Ed25519Key:
        """Generate a fresh Ed25519 keypair."""
        priv_cls, _ = _load_ed25519_primitives()
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        priv = priv_cls.generate()
        raw_priv = priv.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        raw_pub = priv.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return cls(key_id=key_id, public_bytes=raw_pub, private_bytes=raw_priv)

    @classmethod
    def from_private_bytes(cls, key_id: str, private_bytes: bytes) -> Ed25519Key:
        """Construct a signing Ed25519Key from 32 raw private seed bytes."""
        if len(private_bytes) != 32:
            raise ValueError(
                f"Ed25519 private_bytes must be exactly 32 bytes (got {len(private_bytes)})"
            )
        priv_cls, _ = _load_ed25519_primitives()
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        priv = priv_cls.from_private_bytes(private_bytes)
        raw_pub = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        return cls(key_id=key_id, public_bytes=raw_pub, private_bytes=private_bytes)

    @classmethod
    def from_public_bytes(cls, key_id: str, public_bytes: bytes) -> Ed25519Key:
        """Construct a verify-only Ed25519Key from 32 raw public key bytes."""
        if len(public_bytes) != 32:
            raise ValueError(
                f"Ed25519 public_bytes must be exactly 32 bytes (got {len(public_bytes)})"
            )
        # Validate the raw bytes are accepted by cryptography when available.
        _, pub_cls = _load_ed25519_primitives()
        pub_cls.from_public_bytes(public_bytes)
        return cls(key_id=key_id, public_bytes=public_bytes, private_bytes=None)


#: Union of all key types accepted by :class:`KeyRing`.
SigningKey = Key | Ed25519Key


@dataclass
class KeyRing:
    """Ordered set of keys covering one or more eras of an audit chain.

    The *active* key is the one used to sign new entries. All other keys
    in the ring are still trusted for verification of entries that were
    written under them. Supports symmetric :class:`Key` (HMAC-SHA256),
    asymmetric :class:`Ed25519Key`, and seamless mixed-era rotations.

    Construct with the active key. Add older keys via :meth:`add_legacy`
    when bringing an existing chain online. Rotate to a new active key
    via :meth:`rotate`.

    Constructor ergonomics: ``KeyRing(active=Key(...))`` is the
    historical signature. ``KeyRing(keys=[...], active_id="k1")`` and
    ``KeyRing(keys={"k1": Key(...), "k2": Key(...)}, active_id="k1")``
    are accepted shorthands for callers that already have a list / dict
    of keys.
    """

    _active: SigningKey
    _legacy: dict[str, SigningKey] = field(default_factory=dict)
    _lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

    def __init__(
        self,
        active: SigningKey | None = None,
        *,
        keys: list[SigningKey] | dict[str, SigningKey] | dict[str, bytes] | None = None,
        active_id: str | None = None,
    ) -> None:
        self._lock = threading.RLock()
        if active is not None:
            if keys is not None or active_id is not None:
                raise ValueError("pass either active= or (keys=, active_id=), not both")
            self._active = active
            self._legacy = {}
            return

        if keys is None:
            raise TypeError(
                "KeyRing requires active= or (keys=, active_id=) to identify the signing key"
            )
        if active_id is None:
            raise TypeError(
                "KeyRing(keys=...) requires active_id= so the signing key is unambiguous"
            )

        # Normalize list[SigningKey] -> dict[str, SigningKey].
        if isinstance(keys, list):
            keys_by_id: dict[str, SigningKey] = {}
            for k in keys:
                if k.key_id in keys_by_id:
                    raise ValueError(f"duplicate key_id {k.key_id!r} in keys= list")
                keys_by_id[k.key_id] = k
        else:
            # keys is a dict[str, SigningKey | bytes]. If values are bytes, wrap
            # them into Key objects using the dict key as the key_id. This
            # keeps `KeyRing(keys={"k1": b"x" * 32}, active_id="k1")` working
            # the way callers reasonably expect.
            keys_by_id = {}
            for kid, v in keys.items():
                if isinstance(v, bytes):
                    keys_by_id[kid] = Key(key_id=kid, secret=v)
                else:
                    keys_by_id[kid] = v

        if active_id not in keys_by_id:
            raise ValueError(
                f"active_id {active_id!r} not present in keys= (known ids: {sorted(keys_by_id)!r})"
            )
        self._active = keys_by_id.pop(active_id)
        self._legacy = keys_by_id

    @property
    def active(self) -> SigningKey:
        """The current signing key. New entries are signed with this key."""
        with self._lock:
            return self._active

    def get(self, key_id: str) -> SigningKey | None:
        """Look up a key by ID. Returns ``None`` if no such key is known."""
        with self._lock:
            if key_id == self._active.key_id:
                return self._active
            return self._legacy.get(key_id)

    def add_legacy(self, key: SigningKey) -> None:
        """Register a previous-era key for verification only.

        The added key is not used for signing. Raises :class:`ValueError`
        if a key with the same ID is already registered.
        """
        with self._lock:
            if key.key_id == self._active.key_id:
                raise ValueError(
                    f"Cannot add legacy key with same ID as active key: {key.key_id!r}"
                )
            if key.key_id in self._legacy:
                raise ValueError(f"Legacy key {key.key_id!r} already registered")
            self._legacy[key.key_id] = key

    def rotate(self, new_active: SigningKey) -> None:
        """Promote ``new_active`` to the signing role; demote the previous
        active key to legacy verification-only.

        Raises :class:`ValueError` if ``new_active`` already exists in the
        ring under any role.
        """
        with self._lock:
            if new_active.key_id == self._active.key_id:
                raise ValueError(
                    f"New active key has same ID as current active: {new_active.key_id!r}"
                )
            if new_active.key_id in self._legacy:
                raise ValueError(f"New active key {new_active.key_id!r} already exists as legacy")
            self._legacy[self._active.key_id] = self._active
            self._active = new_active

    def public_ring(self) -> KeyRing:
        """Return a verify-only KeyRing with all Ed25519 private keys stripped.

        Safe to distribute to external auditors so they can verify the chain
        offline without gaining signing capability. Raises :class:`ValueError`
        if the ring contains any symmetric HMAC :class:`Key` (which has no
        public-only form).
        """
        with self._lock:
            if not isinstance(self._active, Ed25519Key):
                raise ValueError(
                    f"Active key {self._active.key_id!r} is symmetric ({self._active.algorithm}); "
                    "public_ring() only supports asymmetric Ed25519Key rings"
                )
            pub_keys: list[SigningKey] = [self._active.public_only()]
            for k in self._legacy.values():
                if not isinstance(k, Ed25519Key):
                    raise ValueError(
                        f"Legacy key {k.key_id!r} is symmetric ({k.algorithm}); "
                        "public_ring() refuses to export symmetric secrets"
                    )
                pub_keys.append(k.public_only())
            return KeyRing(keys=pub_keys, active_id=self._active.key_id)

    def all_known_ids(self) -> tuple[str, ...]:
        """All key IDs currently in the ring (active + legacy), in
        insertion order with the active key first."""
        with self._lock:
            return (self._active.key_id, *self._legacy.keys())
