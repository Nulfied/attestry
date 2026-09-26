"""Signing keys: generation, on-disk storage, and the signature string format.

Hash chaining proves nobody edited the log. Signatures prove who wrote it. Both
are needed: without signatures, anyone who can append can also rewrite from any
point and re-hash the tail, and the chain will happily verify.

Signatures are written as ``alg:keyid:hexsignature``, for example::

    ed25519:3f9c1a2b4d5e6f70:1a2b3c...

Carrying the key id inline means a verifier can find the right public key
without guessing, and a ledger stays verifiable when several people append to
it. Public keys themselves travel in ``ledger.key-trusted`` entries, so a ledger
file is self-describing: hand someone the file and one trusted key id and they
can check the whole thing.

Two backends implement the same format. ``cryptography`` is used when it can be
imported, and the bundled pure-Python implementation otherwise. They are
interchangeable -- keys and signatures made by one verify under the other.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from typing import Any, Dict, Optional, Tuple

from ..util.errors import TrustError
from ..util.timeutil import now_rfc3339
from . import ed25519 as _pure

__all__ = [
    "ALG",
    "BACKEND",
    "KeyPair",
    "keyid_for",
    "generate",
    "sign_bytes",
    "verify_bytes",
    "parse_sig",
    "Keyring",
]

#: The only algorithm Attestry signs with. Kept as a named constant, and carried
#: in every signature string, so a future second algorithm is additive rather
#: than a breaking change to the ledger format.
ALG = "ed25519"

_KEYID_DOMAIN = b"attestry-keyid/v1"

try:  # pragma: no cover - which branch runs depends on the environment
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _fast

    BACKEND = "cryptography"
except Exception:  # pragma: no cover
    _fast = None
    _ser = None
    BACKEND = "pure-python"


def _public_from_secret(secret: bytes) -> bytes:
    if _fast is not None:
        key = _fast.Ed25519PrivateKey.from_private_bytes(secret)
        return key.public_key().public_bytes(
            encoding=_ser.Encoding.Raw, format=_ser.PublicFormat.Raw
        )
    return _pure.secret_to_public(secret)


def _raw_sign(secret: bytes, message: bytes) -> bytes:
    if _fast is not None:
        return _fast.Ed25519PrivateKey.from_private_bytes(secret).sign(message)
    return _pure.sign(secret, message)


def _raw_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    if _fast is not None:
        try:
            _fast.Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
            return True
        except Exception:
            return False
    return _pure.verify(public, message, signature)


def keyid_for(public_hex: str) -> str:
    """Stable short identifier for a public key: 16 hex characters.

    Domain-separated so a key id can never collide with some other SHA-256 in
    the system that happens to be computed over the same 32 bytes.
    """
    raw = bytes.fromhex(public_hex)
    return hashlib.sha256(_KEYID_DOMAIN + raw).hexdigest()[:16]


class KeyPair:
    """A signing identity. ``secret`` is present only for keys you own."""

    __slots__ = ("keyid", "alg", "public", "secret", "label", "created")

    def __init__(
        self,
        public: str,
        secret: Optional[str] = None,
        label: str = "",
        created: Optional[str] = None,
        keyid: Optional[str] = None,
        alg: str = ALG,
    ) -> None:
        self.public = public
        self.secret = secret
        self.label = label
        self.created = created or now_rfc3339()
        self.alg = alg
        self.keyid = keyid or keyid_for(public)

    def __repr__(self) -> str:
        return "KeyPair(%s, label=%r, %s)" % (
            self.keyid,
            self.label,
            "private" if self.secret else "public-only",
        )

    @property
    def can_sign(self) -> bool:
        return self.secret is not None

    def public_only(self) -> "KeyPair":
        """A copy with the secret stripped, safe to hand out or print."""
        return KeyPair(self.public, None, self.label, self.created, self.keyid, self.alg)

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        data = {
            "keyid": self.keyid,
            "alg": self.alg,
            "public": self.public,
            "label": self.label,
            "created": self.created,
        }
        if include_secret and self.secret:
            data["secret"] = self.secret
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyPair":
        return cls(
            public=data["public"],
            secret=data.get("secret"),
            label=data.get("label", ""),
            created=data.get("created"),
            keyid=data.get("keyid"),
            alg=data.get("alg", ALG),
        )


def generate(label: str = "") -> KeyPair:
    """Create a new Ed25519 keypair from the OS entropy source."""
    secret = secrets.token_bytes(32)
    public = _public_from_secret(secret)
    return KeyPair(public=public.hex(), secret=secret.hex(), label=label)


def sign_bytes(key: KeyPair, message: bytes) -> str:
    """Sign ``message``, returning an ``alg:keyid:hex`` signature string."""
    if not key.can_sign:
        raise TrustError("key %s has no secret half; cannot sign" % key.keyid)
    signature = _raw_sign(bytes.fromhex(key.secret), message)
    return "%s:%s:%s" % (ALG, key.keyid, signature.hex())


def parse_sig(sig: str) -> Tuple[str, str, bytes]:
    """Split a signature string into ``(alg, keyid, raw_signature)``."""
    parts = sig.split(":")
    if len(parts) != 3:
        raise TrustError("malformed signature %r: expected alg:keyid:hex" % (sig,))
    alg, kid, hexsig = parts
    if alg != ALG:
        raise TrustError("unsupported signature algorithm %r" % (alg,))
    try:
        raw = bytes.fromhex(hexsig)
    except ValueError:
        raise TrustError("signature payload for %s is not hex" % kid)
    return alg, kid, raw


def verify_bytes(sig: str, message: bytes, public_hex: str) -> bool:
    """Check a signature string against a message and a public key.

    The key id embedded in the signature must match the key offered, otherwise
    a valid signature could be replayed while pointing at somebody else's
    identity.
    """
    try:
        _, kid, raw = parse_sig(sig)
    except TrustError:
        return False
    if kid != keyid_for(public_hex):
        return False
    try:
        public = bytes.fromhex(public_hex)
    except ValueError:
        return False
    return _raw_verify(public, message, raw)


class Keyring:
    """Private keys on disk, one JSON file per key.

    Secrets are written with owner-only permissions where the platform supports
    it. This is a developer-grade keyring, not a hardware token: it protects
    against a curious process, not against somebody with your login.
    """

    def __init__(self, directory: str) -> None:
        self.directory = directory

    def _path(self, keyid: str) -> str:
        return os.path.join(self.directory, "%s.json" % keyid)

    def save(self, key: KeyPair) -> str:
        os.makedirs(self.directory, exist_ok=True)
        path = self._path(key.keyid)
        payload = json.dumps(key.to_dict(include_secret=True), indent=2) + "\n"
        # Create with restrictive permissions rather than fixing them after the
        # secret has already been on disk world-readable for a moment.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        handle = os.open(path, flags, 0o600)
        try:
            os.write(handle, payload.encode("utf-8"))
        finally:
            os.close(handle)
        return path

    def load(self, keyid: str) -> KeyPair:
        path = self._path(keyid)
        if not os.path.exists(path):
            raise TrustError("no key %s in %s" % (keyid, self.directory))
        with open(path, "r", encoding="utf-8") as handle:
            return KeyPair.from_dict(json.load(handle))

    def list(self) -> list:
        if not os.path.isdir(self.directory):
            return []
        out = []
        for name in sorted(os.listdir(self.directory)):
            if not name.endswith(".json"):
                continue
            try:
                with open(
                    os.path.join(self.directory, name), "r", encoding="utf-8"
                ) as handle:
                    out.append(KeyPair.from_dict(json.load(handle)))
            except (OSError, ValueError, KeyError):
                # A corrupt key file should not stop you listing the others.
                continue
        return out

    def create(self, label: str = "") -> KeyPair:
        key = generate(label)
        self.save(key)
        return key
