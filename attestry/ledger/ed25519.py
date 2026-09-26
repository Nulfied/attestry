"""Ed25519, pure Python, following the RFC 8032 reference implementation.

Attestry ships this so that a signed ledger works out of the box with nothing
installed but CPython. A registry whose signatures only verify if you first
install a native dependency is not much of a decentralised registry -- the whole
promise is that a stranger can check your work with what they already have.

When ``cryptography`` is importable, :mod:`attestry.ledger.keys` uses it instead
for the ~100x speed-up. This module stays as the reference and the fallback, and
the two agree byte for byte: same key format, same 64-byte signatures. There is
a test that signs with each backend and verifies with the other.

A warning worth taking seriously: this implementation is **not constant-time**.
Point multiplication branches on secret scalar bits, so a local attacker who can
measure timing precisely could in principle recover a signing key. For the job
at hand -- signing your own ledger entries on your own machine -- that is an
acceptable trade against a hard dependency, and verification touches only public
data. If you are signing something valuable on shared hardware, install
``cryptography`` (``pip install attestry[fast]``) and the constant-time backend
takes over automatically.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

__all__ = [
    "secret_to_public",
    "sign",
    "verify",
    "SECRET_SIZE",
    "PUBLIC_SIZE",
    "SIGNATURE_SIZE",
]

SECRET_SIZE = 32
PUBLIC_SIZE = 32
SIGNATURE_SIZE = 64

# Curve25519 field prime and group order.
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493

_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

Point = Tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    """Recover the x coordinate from a compressed y and its sign bit."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _modp_inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
_G: Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)
_IDENTITY: Point = (0, 1, 1, 0)


def _point_add(p: Point, q: Point) -> Point:
    """Unified addition on the twisted Edwards curve with a = -1."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(scalar: int, point: Point) -> Point:
    result = _IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(p: Point, q: Point) -> bool:
    # Projective coordinates are not unique, so cross-multiply instead of
    # comparing componentwise.
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _point_compress(point: Point) -> bytes:
    z_inv = _modp_inv(point[2])
    x = point[0] * z_inv % _P
    y = point[1] * z_inv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decompress(data: bytes) -> Optional[Point]:
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % _Q


def _secret_expand(secret: bytes) -> Tuple[int, bytes]:
    if len(secret) != SECRET_SIZE:
        raise ValueError("ed25519 secret key must be 32 bytes, got %d" % len(secret))
    digest = _sha512(secret)
    scalar = int.from_bytes(digest[:32], "little")
    # Clamping: clear the low 3 bits, clear bit 255, set bit 254.
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def secret_to_public(secret: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed."""
    scalar, _ = _secret_expand(secret)
    return _point_compress(_point_mul(scalar, _G))


def sign(secret: bytes, message: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature over ``message``."""
    scalar, prefix = _secret_expand(secret)
    public = _point_compress(_point_mul(scalar, _G))
    # Deterministic nonce: no entropy source needed at signing time, and no
    # chance of the catastrophic nonce reuse that sinks ECDSA.
    r = _sha512_modq(prefix + message)
    r_point = _point_compress(_point_mul(r, _G))
    k = _sha512_modq(r_point + public + message)
    s = (r + k * scalar) % _Q
    return r_point + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Check a signature. Returns False rather than raising on malformed input."""
    if len(public) != PUBLIC_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    point_a = _point_decompress(public)
    if point_a is None:
        return False
    r_bytes = signature[:32]
    point_r = _point_decompress(r_bytes)
    if point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        # Reject non-canonical s, which would otherwise allow trivial
        # signature malleability: the same message verifying under two
        # different signature encodings.
        return False
    k = _sha512_modq(r_bytes + public + message)
    return _point_equal(_point_mul(s, _G), _point_add(point_r, _point_mul(k, point_a)))
