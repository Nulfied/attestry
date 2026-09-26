"""Deciding whether a model's answer is still the answer you signed off on.

Two different questions get asked of every case, and conflating them is the
mistake that makes naive drift tools useless:

**Did it meet the expectation?** A pass/fail check against what you asserted.
This is a test, and it fails loudly.

**Did the behaviour move?** A comparison against the last accepted output for
the same prompt. The case can still pass while the answer changes character
entirely -- longer, differently formatted, suddenly hedged, a different order of
reasoning. That is drift, and it is the early warning that something upstream
changed. By the time expectations start failing you have usually been shipping
different behaviour for weeks.

Comparison is deliberately free of embeddings. Similarity here is lexical:
cheap, deterministic, dependency-free, and reproducible on a machine with no
network. It will not notice that two differently worded answers mean the same
thing -- and that is the correct trade for a regression detector, where the
question is whether the output changed, not whether it is still true.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any, Dict, List, Mapping, Optional

from ..util.canonical import digest_hex

__all__ = [
    "MODES",
    "Verdict",
    "check",
    "similarity",
    "drift_between",
    "normalize",
    "unified_diff",
    "output_digest",
]

#: Expectation modes. Each takes the case's ``expect.value`` and the output.
MODES = (
    "exact",
    "normalized",
    "contains_all",
    "contains_any",
    "never_contains",
    "regex",
    "json_shape",
    "numeric",
    "similarity",
    "none",
)

_WORD = re.compile(r"[A-Za-z0-9_]+")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


class Verdict:
    """The result of one check: did it pass, how well, and why."""

    __slots__ = ("passed", "score", "detail", "mode")

    def __init__(self, passed: bool, score: float, detail: str, mode: str = "") -> None:
        self.passed = passed
        self.score = round(float(score), 4)
        self.detail = detail
        self.mode = mode

    def __repr__(self) -> str:
        return "Verdict(%s, %.3f, %s)" % (self.passed, self.score, self.detail)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "score": self.score,
            "detail": self.detail,
            "mode": self.mode,
        }


def normalize(text: str) -> str:
    """Collapse the differences that never matter: case, spacing, edge padding."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _tokens(text: str) -> List[str]:
    return _WORD.findall((text or "").lower())


def similarity(left: str, right: str) -> float:
    """A 0..1 lexical similarity, blending sequence overlap and token overlap.

    Sequence ratio alone punishes a reordered sentence far more than a reader
    would; token overlap alone ignores structure entirely and calls a shuffled
    bag of the same words identical. Averaging them gives a measure that moves
    when either the wording or the arrangement moves, which is what a drift
    threshold wants to sit on top of.
    """
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    sequence = difflib.SequenceMatcher(None, left, right).ratio()
    left_tokens, right_tokens = set(_tokens(left)), set(_tokens(right))
    if left_tokens or right_tokens:
        union = left_tokens | right_tokens
        jaccard = len(left_tokens & right_tokens) / len(union) if union else 1.0
    else:
        jaccard = 1.0
    return round((sequence + jaccard) / 2.0, 4)


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _check_json_shape(output: str, expected: Any) -> Verdict:
    """Does the output parse as JSON, and does it have the shape asked for?

    The shape is a skeleton: keys that must exist, and optionally a type name as
    the value. Values in the skeleton that are not type names must match
    exactly. Extra keys in the output are fine -- this checks a contract, not
    equality.
    """
    text = output.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fence:
        # Models fence JSON constantly. Unwrapping is a kindness, and it is
        # recorded in the detail so nobody is confused about what was parsed.
        text = fence.group(1)
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        return Verdict(False, 0.0, "output is not valid JSON (%s)" % exc, "json_shape")
    problems: List[str] = []
    _match_shape(parsed, expected, "$", problems)
    if problems:
        return Verdict(False, 0.0, "; ".join(problems[:4]), "json_shape")
    return Verdict(True, 1.0, "JSON matches the required shape", "json_shape")


_TYPE_NAMES = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "any": object,
}


def _match_shape(value: Any, expected: Any, path: str, problems: List[str]) -> None:
    if isinstance(expected, str) and expected in _TYPE_NAMES:
        wanted = _TYPE_NAMES[expected]
        if expected == "integer" and isinstance(value, bool):
            problems.append("%s is a boolean, expected integer" % path)
        elif not isinstance(value, wanted):
            problems.append(
                "%s is %s, expected %s" % (path, type(value).__name__, expected)
            )
        return
    if isinstance(expected, Mapping):
        if not isinstance(value, Mapping):
            problems.append("%s is not an object" % path)
            return
        for key, sub in expected.items():
            if key not in value:
                problems.append("%s.%s is missing" % (path, key))
            else:
                _match_shape(value[key], sub, "%s.%s" % (path, key), problems)
        return
    if isinstance(expected, list):
        if not isinstance(value, list):
            problems.append("%s is not an array" % path)
            return
        if expected and value:
            _match_shape(value[0], expected[0], "%s[0]" % path, problems)
        elif expected and not value:
            problems.append("%s is empty" % path)
        return
    if value != expected:
        problems.append("%s is %r, expected %r" % (path, value, expected))


def _check_numeric(output: str, expected: Any, tolerance: float) -> Verdict:
    numbers = [float(n) for n in _NUMBER.findall(output or "")]
    if not numbers:
        return Verdict(False, 0.0, "no number found in the output", "numeric")
    try:
        target = float(expected)
    except (TypeError, ValueError):
        return Verdict(False, 0.0, "expected value %r is not a number" % (expected,), "numeric")
    best = min(numbers, key=lambda n: abs(n - target))
    delta = abs(best - target)
    allowed = abs(tolerance)
    if delta <= allowed:
        return Verdict(True, 1.0, "found %g (target %g)" % (best, target), "numeric")
    scale = max(abs(target), 1.0)
    score = max(0.0, 1.0 - delta / scale)
    return Verdict(
        False, score, "closest number %g is %g away from %g" % (best, delta, target), "numeric"
    )


def check(output: str, expect: Optional[Mapping[str, Any]]) -> Verdict:
    """Evaluate one expectation against one output."""
    if not expect:
        return Verdict(True, 1.0, "no expectation declared", "none")
    mode = expect.get("mode", "contains_all")
    value = expect.get("value")
    if mode not in MODES:
        return Verdict(False, 0.0, "unknown expectation mode %r" % (mode,), mode)

    if mode == "none":
        return Verdict(True, 1.0, "no expectation declared", mode)

    if mode == "exact":
        ok = output == value
        return Verdict(ok, 1.0 if ok else similarity(output, str(value)),
                       "exact match" if ok else "output differs from the expected text", mode)

    if mode == "normalized":
        ok = normalize(output) == normalize(str(value))
        return Verdict(ok, 1.0 if ok else similarity(normalize(output), normalize(str(value))),
                       "matches ignoring case and spacing" if ok else "differs beyond case and spacing", mode)

    if mode in ("contains_all", "contains_any", "never_contains"):
        needles = [str(v) for v in _as_list(value)]
        haystack = normalize(output)
        hits = [n for n in needles if normalize(n) in haystack]
        misses = [n for n in needles if n not in hits]
        if mode == "contains_all":
            score = len(hits) / len(needles) if needles else 1.0
            return Verdict(
                not misses, score,
                "all %d phrases present" % len(needles) if not misses
                else "missing: %s" % ", ".join(repr(m) for m in misses[:5]),
                mode,
            )
        if mode == "contains_any":
            return Verdict(
                bool(hits), 1.0 if hits else 0.0,
                "found %r" % hits[0] if hits else "none of the phrases appeared",
                mode,
            )
        return Verdict(
            not hits, 0.0 if hits else 1.0,
            "must not contain, but found: %s" % ", ".join(repr(h) for h in hits[:5])
            if hits else "none of the forbidden phrases appeared",
            mode,
        )

    if mode == "regex":
        patterns = [str(v) for v in _as_list(value)]
        misses = []
        for pattern in patterns:
            try:
                if not re.search(pattern, output or "", re.IGNORECASE | re.MULTILINE):
                    misses.append(pattern)
            except re.error as exc:
                return Verdict(False, 0.0, "bad regex %r: %s" % (pattern, exc), mode)
        score = (len(patterns) - len(misses)) / len(patterns) if patterns else 1.0
        return Verdict(
            not misses, score,
            "all patterns matched" if not misses
            else "no match for: %s" % ", ".join(misses[:3]),
            mode,
        )

    if mode == "json_shape":
        return _check_json_shape(output, value)

    if mode == "numeric":
        return _check_numeric(output, value, float(expect.get("tolerance", 0.0)))

    # similarity
    threshold = float(expect.get("threshold", 0.85))
    score = similarity(output or "", str(value))
    return Verdict(
        score >= threshold, score,
        "similarity %.3f against threshold %.2f" % (score, threshold),
        mode,
    )


def drift_between(
    baseline: Optional[str],
    current: str,
    threshold: float = 0.95,
) -> Verdict:
    """Compare an output against the last accepted one for the same case.

    ``stable`` means byte-identical. ``minor`` means it moved but stayed above
    the threshold -- usually a reworded sentence. ``drift`` means it moved
    enough that you should look at it, whatever the expectations say.
    """
    if baseline is None:
        return Verdict(True, 1.0, "no baseline yet; this run becomes the reference", "new")
    if baseline == current:
        return Verdict(True, 1.0, "identical to the baseline", "stable")
    score = similarity(baseline, current)
    if score >= threshold:
        return Verdict(
            True, score,
            "reworded but close (similarity %.3f)" % score, "minor",
        )
    return Verdict(
        False, score,
        "behaviour moved (similarity %.3f, below %.2f)" % (score, threshold), "drift",
    )


def unified_diff(baseline: str, current: str, context: int = 2) -> str:
    """A readable diff of two outputs, for the report."""
    lines = list(
        difflib.unified_diff(
            (baseline or "").splitlines(),
            (current or "").splitlines(),
            fromfile="baseline",
            tofile="current",
            lineterm="",
            n=context,
        )
    )
    return "\n".join(lines)


def output_digest(text: str) -> str:
    """Hash of an output, which is what goes in the ledger instead of the text.

    Model outputs can contain whatever was in the prompt, including things that
    should not be committed to a repository. The digest proves what was seen
    without disclosing it; the text stays in the local, gitignored run file.
    """
    return digest_hex((text or "").encode("utf-8"))
