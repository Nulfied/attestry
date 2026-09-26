"""Canonical JSON: one byte sequence per value, on every machine, forever.

Everything in Attestry that gets hashed or signed goes through here first. If
two runs of the same program could serialise the same dict two different ways,
then hashes stop meaning "same content" and the whole ledger is decoration.

The rules, close to RFC 8785 (JCS) but deliberately stricter in two places:

* object keys are sorted by their UTF-16 code units, exactly as JCS requires;
* no insignificant whitespace, with "," and ":" as the only separators;
* UTF-8 output, non-ASCII left as real characters rather than escape sequences;
* NaN and Infinity are rejected -- they are not JSON, and they would let two
  documents that compare equal in Python hash differently;
* non-string object keys are rejected rather than coerced, because {1: "a"} and
  {"1": "a"} are different documents that would otherwise collide;
* floats are emitted with Python's shortest round-tripping repr, and integral
  floats keep a trailing ".0" so 1.0 never collides with 1.

That last point is the one intentional divergence from JCS, which renders 1.0 as
1. Attestry keeps int and float distinguishable, since a drift score of 1.0 and
a count of 1 mean different things and a person reading the raw ledger should be
able to tell them apart without consulting a schema.

String escaping is delegated to json.dumps, whose output for a single string is
already exactly what JCS asks for.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

__all__ = [
    "canonical_json",
    "canonical_bytes",
    "digest_of",
    "digest_hex",
    "ZERO_DIGEST",
]

#: The "prev" value of a genesis entry: 64 zeros, meaning nothing came before.
ZERO_DIGEST = "0" * 64


def _escape(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def _sort_key(key: str) -> tuple:
    """Sort by UTF-16 code units, which is what JCS specifies.

    Within the Basic Multilingual Plane this matches a code-point sort. It
    differs only for astral characters (emoji, rarer scripts), where a naive
    code-point sort would disagree with a JavaScript implementation of the same
    spec -- and cross-language agreement is the entire reason to have a
    canonical form at all.
    """
    return tuple(key.encode("utf-16-be"))


def _number(value: Any) -> str:
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise ValueError(
            "cannot canonicalise non-finite float %r: NaN and Infinity are not JSON"
            % (value,)
        )
    text = repr(float(value))
    if "." in text or "e" in text or "E" in text:
        return text
    return text + ".0"


def _write(value: Any, out: list, path: str) -> None:
    if value is None:
        out.append("null")
    elif isinstance(value, bool):
        # Checked before int, because bool is an int subclass.
        out.append("true" if value else "false")
    elif isinstance(value, (int, float)):
        out.append(_number(value))
    elif isinstance(value, str):
        out.append(_escape(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out, "%s[%d]" % (path, index))
        out.append("]")
    elif isinstance(value, dict):
        bad = [k for k in value if not isinstance(k, str)]
        if bad:
            raise TypeError(
                "object keys must be strings at %s, got %r" % (path or "$", bad[0])
            )
        out.append("{")
        for index, key in enumerate(sorted(value, key=_sort_key)):
            if index:
                out.append(",")
            out.append(_escape(key))
            out.append(":")
            _write(value[key], out, "%s.%s" % (path, key))
        out.append("}")
    else:
        raise TypeError(
            "%s is not JSON-serialisable at %s; convert it before hashing"
            % (type(value).__name__, path or "$")
        )


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text for ``value``."""
    out: list = []
    _write(value, out, "")
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical JSON text for ``value``, encoded as UTF-8."""
    return canonical_json(value).encode("utf-8")


def digest_of(value: Any) -> str:
    """SHA-256, lowercase hex, of the canonical form of ``value``."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_hex(data: bytes) -> str:
    """SHA-256, lowercase hex, of raw bytes."""
    return hashlib.sha256(data).hexdigest()
