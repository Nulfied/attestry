"""Running a suite, comparing against the baseline, and recording the result.

The division of storage here is deliberate and is the part most worth copying
if you build something similar:

* **the ledger** gets digests, scores and statuses -- enough to prove what was
  seen and when, signed, committed, tamper-evident;
* **the run file** gets the full model outputs and stays local and gitignored;
* **the baseline** gets the accepted outputs, and is committed, because that is
  the thing a reviewer needs to see changing.

Model outputs echo whatever was in the prompt. Writing them into a signed,
append-only log that you then push to a shared repository would take a privacy
problem and make it permanent. The digest proves the output without disclosing
it, and if you do want the text in the ledger, that has to be a choice somebody
makes on purpose.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..ledger.chain import Ledger
from ..util.timeutil import now_rfc3339
from .compare import Verdict, check, drift_between, output_digest, unified_diff
from .providers import Provider, ProviderError, get_provider
from .suite import Suite

__all__ = [
    "Outcome",
    "Run",
    "run_suite",
    "STATUSES",
    "load_baseline",
    "save_baseline",
    "save_run",
    "record_run",
    "history",
    "EXIT_CODES",
]

#: Ordered worst to best. A run takes the status of its worst case.
STATUSES = ("error", "fail", "drift", "minor", "ok", "skipped")

_RANK = {name: index for index, name in enumerate(STATUSES)}

#: What the CLI exits with, so CI can distinguish "broken" from "moved".
EXIT_CODES = {"error": 3, "fail": 2, "drift": 1, "minor": 0, "ok": 0, "skipped": 0}


class Outcome:
    """What happened to one case in one run."""

    __slots__ = (
        "case_id", "status", "output", "digest", "expectation", "movement",
        "latency_ms", "served_model", "error", "baseline_digest", "tags",
    )

    def __init__(
        self,
        case_id: str,
        status: str,
        output: str = "",
        digest: str = "",
        expectation: Optional[Verdict] = None,
        movement: Optional[Verdict] = None,
        latency_ms: int = 0,
        served_model: str = "",
        error: str = "",
        baseline_digest: str = "",
        tags: Optional[Sequence[str]] = None,
    ) -> None:
        self.case_id = case_id
        self.status = status
        self.output = output
        self.digest = digest
        self.expectation = expectation
        self.movement = movement
        self.latency_ms = latency_ms
        self.served_model = served_model
        self.error = error
        self.baseline_digest = baseline_digest
        self.tags = list(tags or [])

    def __repr__(self) -> str:
        return "Outcome(%s, %s)" % (self.case_id, self.status)

    def to_dict(self, include_output: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "case": self.case_id,
            "status": self.status,
            "digest": self.digest,
            "served_model": self.served_model,
            "latency_ms": self.latency_ms,
        }
        if self.expectation is not None:
            out["expectation"] = self.expectation.to_dict()
        if self.movement is not None:
            out["movement"] = self.movement.to_dict()
        if self.baseline_digest:
            out["baseline_digest"] = self.baseline_digest
        if self.error:
            out["error"] = self.error
        if self.tags:
            out["tags"] = self.tags
        if include_output:
            out["output"] = self.output
        return out


class Run:
    """One execution of a suite."""

    def __init__(
        self,
        suite: str,
        provider: str,
        model: str,
        outcomes: Sequence[Outcome],
        started: str,
        finished: str,
        identity_warnings: Optional[Sequence[str]] = None,
    ) -> None:
        self.suite = suite
        self.provider = provider
        self.model = model
        self.outcomes = list(outcomes)
        self.started = started
        self.finished = finished
        self.identity_warnings = list(identity_warnings or [])

    @property
    def status(self) -> str:
        """The worst case status in the run."""
        if not self.outcomes:
            return "ok"
        return min((o.status for o in self.outcomes), key=lambda s: _RANK[s])

    @property
    def exit_code(self) -> int:
        return EXIT_CODES.get(self.status, 0)

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for outcome in self.outcomes:
            out[outcome.status] = out.get(outcome.status, 0) + 1
        return out

    def by_status(self, status: str) -> List[Outcome]:
        return [o for o in self.outcomes if o.status == status]

    def to_dict(self, include_outputs: bool = False) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "provider": self.provider,
            "model": self.model,
            "started": self.started,
            "finished": self.finished,
            "status": self.status,
            "counts": self.counts(),
            "identity_warnings": self.identity_warnings,
            "cases": [o.to_dict(include_outputs) for o in self.outcomes],
        }

    # -- reporting -------------------------------------------------------

    def format(self, baseline: Optional[Mapping[str, Any]] = None, show_diff: bool = False) -> str:
        lines = [
            "suite    %s" % self.suite,
            "model    %s:%s" % (self.provider, self.model),
            "ran      %s" % self.started,
            "",
        ]
        for warning in self.identity_warnings:
            lines.append("  !! %s" % warning)
        if self.identity_warnings:
            lines.append("")
        lines.append("  %-24s %-8s %-7s %s" % ("case", "status", "score", "detail"))
        lines.append("  " + "-" * 74)
        for outcome in self.outcomes:
            verdict = outcome.expectation if outcome.status == "fail" else outcome.movement
            detail = outcome.error or (verdict.detail if verdict else "")
            score = verdict.score if verdict else 1.0
            lines.append(
                "  %-24s %-8s %-7.3f %s"
                % (outcome.case_id[:24], outcome.status, score, detail[:44])
            )
        counts = self.counts()
        lines.append("")
        lines.append(
            "  %s  (%s)"
            % (
                self.status.upper(),
                ", ".join("%d %s" % (count, name) for name, count in sorted(counts.items())),
            )
        )
        if show_diff and baseline:
            for outcome in self.outcomes:
                if outcome.status not in ("drift", "minor"):
                    continue
                previous = (baseline.get(outcome.case_id) or {}).get("output", "")
                diff_text = unified_diff(previous, outcome.output)
                if diff_text:
                    lines.append("")
                    lines.append("--- %s ---" % outcome.case_id)
                    lines.append(diff_text)
        return "\n".join(lines)

    def markdown(self) -> str:
        """A report suitable for pasting into a pull request or an issue."""
        icons = {"ok": "ok", "minor": "minor", "drift": "DRIFT", "fail": "FAIL",
                 "error": "ERROR", "skipped": "skip"}
        lines = [
            "### Drift report: `%s`" % self.suite,
            "",
            "`%s:%s` at %s -- **%s**" % (self.provider, self.model, self.started, self.status.upper()),
            "",
        ]
        for warning in self.identity_warnings:
            lines.append("> **%s**" % warning)
            lines.append("")
        lines.append("| case | status | score | detail |")
        lines.append("| --- | --- | --- | --- |")
        for outcome in self.outcomes:
            verdict = outcome.expectation if outcome.status == "fail" else outcome.movement
            detail = (outcome.error or (verdict.detail if verdict else "")).replace("|", "-")
            score = verdict.score if verdict else 1.0
            lines.append(
                "| `%s` | %s | %.3f | %s |"
                % (outcome.case_id, icons.get(outcome.status, outcome.status), score, detail)
            )
        return "\n".join(lines)


def run_suite(
    suite: Suite,
    provider: Optional[Provider] = None,
    baseline: Optional[Mapping[str, Any]] = None,
    only: Optional[Sequence[str]] = None,
) -> Run:
    """Execute every case and classify each outcome.

    A case is graded twice: against its expectation, and against the baseline.
    An expectation failure outranks drift, because a broken assertion is a
    definite problem while movement is a signal to go and look.
    """
    engine = provider or get_provider(suite.provider, suite.model)
    baseline = baseline or {}
    wanted = set(only) if only else None
    started = now_rfc3339()
    outcomes: List[Outcome] = []
    identity_warnings: List[str] = []
    # Served-model changes, keyed by (what the baseline saw, what we got now).
    identity_changes: Dict[tuple, int] = {}
    unpinned: Dict[str, int] = {}

    for case in suite.cases:
        if case.skip or (wanted and case.id not in wanted):
            outcomes.append(Outcome(case.id, "skipped", tags=case.tags))
            continue

        params = dict(suite.params)
        params.update(case.params)
        try:
            response = engine.complete(case.prompt, case.system, params)
        except ProviderError as exc:
            outcomes.append(
                Outcome(case.id, "error", error=str(exc), tags=case.tags)
            )
            continue

        digest = output_digest(response.text)
        previous = baseline.get(case.id) or {}
        expectation = check(response.text, case.expect)
        movement = drift_between(
            previous.get("output"),
            response.text,
            case.threshold if case.threshold is not None else suite.drift_threshold,
        )

        if not expectation.passed:
            status = "fail"
        elif movement.mode == "drift":
            status = "drift"
        elif movement.mode == "minor":
            status = "minor"
        else:
            status = "ok"

        # Compare the served model against what the baseline saw for this same
        # case, not against the name that was requested. An alias resolving to a
        # pinned snapshot ("gpt-4o" serving "gpt-4o-2024-08-06") is normal; that
        # snapshot changing between runs is exactly the event worth shouting
        # about, and comparing only against the alias would miss it.
        served = response.model or ""
        was_served = previous.get("served_model") or ""
        if served and was_served and served != was_served:
            pair = (was_served, served)
            identity_changes[pair] = identity_changes.get(pair, 0) + 1
        elif served and not was_served and served != suite.model:
            unpinned[served] = unpinned.get(served, 0) + 1

        outcomes.append(
            Outcome(
                case_id=case.id,
                status=status,
                output=response.text,
                digest=digest,
                expectation=expectation,
                movement=movement,
                latency_ms=response.latency_ms,
                served_model=response.model,
                baseline_digest=previous.get("digest", ""),
                tags=case.tags,
            )
        )

    for (was, now), count in sorted(identity_changes.items()):
        identity_warnings.append(
            "model identity changed: %r was serving %r, now serves %r (%d case(s)). "
            "Any movement below is explained by this." % (suite.model, was, now, count)
        )
    for served, count in sorted(unpinned.items()):
        identity_warnings.append(
            "requested %r, provider served %r (%d case(s)); pinning a baseline "
            "records this so a future change is detectable"
            % (suite.model, served, count)
        )

    return Run(
        suite=suite.name,
        provider=suite.provider,
        model=suite.model,
        outcomes=outcomes,
        started=started,
        finished=now_rfc3339(),
        identity_warnings=identity_warnings,
    )


# -- persistence ---------------------------------------------------------


def _baseline_path(directory: str, suite_name: str) -> str:
    return os.path.join(directory, "%s.json" % suite_name)


def load_baseline(directory: str, suite_name: str) -> Dict[str, Any]:
    path = _baseline_path(directory, suite_name)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data.get("cases", {})


def save_baseline(directory: str, suite_name: str, run: Run) -> str:
    """Pin the current outputs as the reference for future runs.

    Errored and skipped cases are left out rather than recorded as empty, so a
    transient outage cannot quietly become the thing you compare against.
    """
    os.makedirs(directory, exist_ok=True)
    cases = {
        outcome.case_id: {
            "output": outcome.output,
            "digest": outcome.digest,
            "served_model": outcome.served_model,
        }
        for outcome in run.outcomes
        if outcome.status not in ("error", "skipped")
    }
    payload = {
        "suite": suite_name,
        "provider": run.provider,
        "model": run.model,
        "recorded": now_rfc3339(),
        "cases": cases,
    }
    path = _baseline_path(directory, suite_name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return path


def save_run(directory: str, run: Run) -> str:
    """Write the full run, outputs included, to the local (gitignored) run log."""
    os.makedirs(directory, exist_ok=True)
    stamp = run.started.replace(":", "").replace("-", "")
    path = os.path.join(directory, "%s-%s.json" % (run.suite, stamp))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(run.to_dict(include_outputs=True), handle, indent=2)
        handle.write("\n")
    return path


def record_run(ledger: Ledger, run: Run) -> Any:
    """Append the run to the ledger -- digests and scores, never the outputs."""
    return ledger.append(
        "drift.run",
        run.suite,
        {
            "provider": run.provider,
            "model": run.model,
            "started": run.started,
            "finished": run.finished,
            "status": run.status,
            "counts": run.counts(),
            "identity_warnings": run.identity_warnings,
            "cases": [outcome.to_dict(include_output=False) for outcome in run.outcomes],
        },
    )


def record_baseline(ledger: Ledger, run: Run) -> Any:
    """Record that a baseline was accepted, and by which run."""
    return ledger.append(
        "drift.baseline",
        run.suite,
        {
            "provider": run.provider,
            "model": run.model,
            "recorded": now_rfc3339(),
            "cases": {
                outcome.case_id: outcome.digest
                for outcome in run.outcomes
                if outcome.status not in ("error", "skipped")
            },
        },
    )


def history(ledger: Ledger, suite_name: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Past runs of one suite, oldest first."""
    out = []
    for entry in ledger.entries():
        if entry.kind != "drift.run" or entry.subject != suite_name:
            continue
        out.append(
            {
                "seq": entry.seq,
                "ts": entry.ts,
                "model": entry.body.get("model"),
                "status": entry.body.get("status"),
                "counts": entry.body.get("counts", {}),
            }
        )
    return out[-limit:]


def case_timeline(ledger: Ledger, suite_name: str, case_id: str) -> List[Dict[str, Any]]:
    """Every recorded digest for one case, which is where drift becomes visible.

    Watching one case's digest change over weeks answers the question that
    started all this: when exactly did this stop behaving the way it used to?
    """
    out = []
    for entry in ledger.entries():
        if entry.kind != "drift.run" or entry.subject != suite_name:
            continue
        for case in entry.body.get("cases", []):
            if case.get("case") == case_id:
                out.append(
                    {
                        "seq": entry.seq,
                        "ts": entry.ts,
                        "digest": case.get("digest", "")[:12],
                        "status": case.get("status"),
                        "served_model": case.get("served_model"),
                    }
                )
    return out
