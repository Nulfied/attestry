"""A suite: the prompts you care about and what you expect back.

Deliberately a plain JSON file you commit alongside your code. It is reviewable
in a pull request, and the diff that changes an expectation sits next to the
diff that changed the prompt, which is where the argument about whether the new
behaviour is acceptable actually belongs.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..util.errors import AttestryError
from .compare import MODES

__all__ = ["Case", "Suite", "SUITE_SUFFIX", "example_suite"]

SUITE_SUFFIX = ".suite.json"


class Case:
    """One prompt, and what counts as a correct answer to it."""

    __slots__ = ("id", "prompt", "system", "expect", "threshold", "tags", "params", "skip")

    def __init__(
        self,
        id: str,
        prompt: str,
        system: str = "",
        expect: Optional[Mapping[str, Any]] = None,
        threshold: Optional[float] = None,
        tags: Optional[Sequence[str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        skip: bool = False,
    ) -> None:
        self.id = id
        self.prompt = prompt
        self.system = system
        self.expect = dict(expect) if expect else None
        self.threshold = threshold
        self.tags = list(tags or [])
        self.params = dict(params or {})
        self.skip = skip

    def __repr__(self) -> str:
        return "Case(%s)" % self.id

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"id": self.id, "prompt": self.prompt}
        if self.system:
            out["system"] = self.system
        if self.expect:
            out["expect"] = self.expect
        if self.threshold is not None:
            out["threshold"] = self.threshold
        if self.tags:
            out["tags"] = self.tags
        if self.params:
            out["params"] = self.params
        if self.skip:
            out["skip"] = True
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Case":
        if "id" not in data:
            raise AttestryError("every case needs an id")
        if "prompt" not in data:
            raise AttestryError("case %r has no prompt" % data["id"])
        return cls(
            id=data["id"],
            prompt=data["prompt"],
            system=data.get("system", ""),
            expect=data.get("expect"),
            threshold=data.get("threshold"),
            tags=data.get("tags"),
            params=data.get("params"),
            skip=bool(data.get("skip", False)),
        )


class Suite:
    """A named set of cases, bound to one provider and model."""

    __slots__ = ("name", "provider", "model", "params", "cases", "drift_threshold", "description")

    def __init__(
        self,
        name: str,
        provider: str = "echo",
        model: str = "demo",
        params: Optional[Mapping[str, Any]] = None,
        cases: Optional[Sequence[Case]] = None,
        drift_threshold: float = 0.95,
        description: str = "",
    ) -> None:
        self.name = name
        self.provider = provider
        self.model = model
        # Temperature zero by default. A suite that samples is measuring its own
        # sampling noise as much as the model, and the whole exercise depends on
        # the only variable being the thing upstream.
        self.params = dict(params) if params is not None else {"temperature": 0}
        self.cases = list(cases or [])
        self.drift_threshold = drift_threshold
        self.description = description

    def __repr__(self) -> str:
        return "Suite(%s, %d cases, %s:%s)" % (
            self.name, len(self.cases), self.provider, self.model
        )

    def case(self, case_id: str) -> Optional[Case]:
        for candidate in self.cases:
            if candidate.id == case_id:
                return candidate
        return None

    def validate(self) -> List[str]:
        problems: List[str] = []
        if not self.name:
            problems.append("the suite has no name")
        if not self.cases:
            problems.append("the suite has no cases")
        seen = set()
        for case in self.cases:
            if case.id in seen:
                problems.append("duplicate case id %r" % case.id)
            seen.add(case.id)
            if case.expect:
                mode = case.expect.get("mode", "contains_all")
                if mode not in MODES:
                    problems.append(
                        "case %r uses unknown mode %r; expected one of %s"
                        % (case.id, mode, ", ".join(MODES))
                    )
                if mode != "none" and "value" not in case.expect:
                    problems.append("case %r declares mode %r but no value" % (case.id, mode))
        if self.params.get("temperature", 0) not in (0, 0.0):
            problems.append(
                "temperature is %r; above zero the suite measures sampling noise "
                "as well as drift" % self.params.get("temperature")
            )
        if not 0 < self.drift_threshold <= 1:
            problems.append("drift_threshold must be between 0 and 1")
        return problems

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "provider": self.provider,
            "model": self.model,
            "params": self.params,
            "drift_threshold": self.drift_threshold,
            "cases": [case.to_dict() for case in self.cases],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Suite":
        return cls(
            name=data.get("name", ""),
            provider=data.get("provider", "echo"),
            model=data.get("model", "demo"),
            params=data.get("params"),
            cases=[Case.from_dict(c) for c in data.get("cases", [])],
            drift_threshold=float(data.get("drift_threshold", 0.95)),
            description=data.get("description", ""),
        )

    @classmethod
    def load(cls, path: str) -> "Suite":
        with open(path, "r", encoding="utf-8") as handle:
            try:
                return cls.from_dict(json.load(handle))
            except ValueError as exc:
                raise AttestryError("%s is not valid JSON: %s" % (path, exc))

    def save(self, path: str) -> str:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
            handle.write("\n")
        return path


def example_suite(name: str = "example") -> Suite:
    """A suite that runs for free, used by ``attestry drift init``.

    The cases are written against the echo provider so a new user gets a real
    passing run, and then a real drift report, without an API key.
    """
    return Suite(
        name=name,
        provider="echo",
        model="demo",
        description=(
            "A starter suite that runs against the free echo provider. Replace "
            "provider/model with ollama, openai or anthropic and rewrite the "
            "cases against prompts your system actually sends."
        ),
        cases=[
            Case(
                id="refund-window",
                prompt="How long does a customer have to request a refund?",
                system="You are a concise support agent.",
                expect={"mode": "contains_all", "value": ["refund"]},
                tags=["policy"],
            ),
            Case(
                id="tone-check",
                prompt="Explain our uptime guarantee to an annoyed customer.",
                expect={"mode": "never_contains", "value": ["sorry for the inconvenience"]},
                tags=["tone"],
            ),
            Case(
                id="length-guard",
                prompt="Summarise the outage in one sentence.",
                expect={"mode": "regex", "value": ["Answer|answer"]},
                tags=["format"],
            ),
        ],
    )
