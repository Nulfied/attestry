"""Recording accesses as they happen, and optionally refusing them.

The API that matters is the context manager::

    with recorder.access("read", "email:gmail/INBOX",
                         purpose="draft daily priorities",
                         data_classes=["message_content"]) as event:
        messages = mailbox.fetch(limit=50)
        event.items = len(messages)

The consent check runs on entry, before your code touches anything, so with
``enforce=True`` an ungranted access is stopped rather than merely regretted.
The receipt is written on exit either way, with the real item count -- which you
only know afterwards -- and with the outcome set correctly if the body raised.

Recording on failure is not an afterthought. "The agent tried to read your
mailbox and crashed" is precisely the event somebody investigating wants, and it
is the one a naive implementation drops.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from ..ledger.chain import Ledger
from ..schema.neutral import ToolSchema
from ..util.errors import PolicyViolation
from .model import AccessEvent
from .policy import ConsentPolicy, Decision

__all__ = ["Recorder", "RecordedAccess", "event_from_schema"]


class RecordedAccess:
    """One receipt read back out of the ledger."""

    __slots__ = ("seq", "event", "decision", "flags")

    def __init__(
        self,
        seq: int,
        event: AccessEvent,
        decision: Optional[Decision] = None,
        flags: Optional[Sequence[str]] = None,
    ) -> None:
        self.seq = seq
        self.event = event
        self.decision = decision
        self.flags = list(flags or [])

    def __repr__(self) -> str:
        return "RecordedAccess(#%d, %r)" % (self.seq, self.event)


def event_from_schema(
    tool: ToolSchema,
    actor: str,
    action: str,
    resource: str,
    **overrides: Any,
) -> AccessEvent:
    """Build an event pre-filled from a tool's declared consent block.

    This is where pillars two and three meet. The tool already declared which
    data classes it touches, for what purpose, and where data may go; repeating
    that at every call site is how declarations and reality drift apart. Pass
    the schema and the declaration becomes the default, so a discrepancy means
    somebody overrode it on purpose.
    """
    fields = {
        "purpose": tool.consent.purpose,
        "data_classes": list(tool.consent.data_classes),
        "egress": list(tool.consent.egress),
        "tool": tool.name,
    }
    fields.update(overrides)
    return AccessEvent(actor=actor, action=action, resource=resource, **fields)


class Recorder:
    """Writes access receipts into the ledger, checking them against policy."""

    def __init__(
        self,
        ledger: Ledger,
        policy: Optional[ConsentPolicy] = None,
        actor: str = "agent:unnamed",
        enforce: bool = False,
    ) -> None:
        self.ledger = ledger
        self.policy = policy
        self.actor = actor
        self.enforce = enforce

    # -- writing ---------------------------------------------------------

    def record(
        self, event: AccessEvent, flags: Optional[Sequence[str]] = None
    ) -> Tuple[Any, Decision]:
        """Check, then append a receipt. Returns ``(entry, decision)``."""
        decision = self.policy.check(event) if self.policy is not None else Decision(True)
        if not decision.allowed and event.outcome == "ok":
            # A refused access did not happen, and the receipt must not claim it
            # did -- otherwise the log overstates what the agent managed to do.
            event.outcome = "denied"
        if decision.grant and not event.grant:
            event.grant = decision.grant
        computed = list(flags) if flags is not None else self.unusual(event)
        kind = "receipt.access" if decision.allowed else "receipt.denied"
        entry = self.ledger.append(
            kind,
            event.actor,
            {
                "event": event.to_dict(),
                "decision": decision.to_dict(),
                "flags": computed,
            },
        )
        return entry, decision

    @contextmanager
    def access(
        self,
        action: str,
        resource: str,
        purpose: str = "",
        actor: str = "",
        **fields: Any,
    ) -> Iterator[AccessEvent]:
        """Record an access around a block of work.

        Yields the event so the body can fill in what is only known afterwards --
        typically ``items``. With ``enforce=True``, a refusal raises
        :class:`PolicyViolation` before the body runs.
        """
        event = AccessEvent(
            actor=actor or self.actor,
            action=action,
            resource=resource,
            purpose=purpose,
            **fields,
        )
        decision = self.policy.check(event) if self.policy is not None else Decision(True)
        if not decision.allowed and self.enforce:
            event.outcome = "denied"
            self.record(event)
            raise PolicyViolation(
                "%s is not permitted to %s %s: %s"
                % (
                    event.actor,
                    action,
                    resource,
                    "; ".join(v.detail for v in decision.violations) or "no grant",
                )
            )
        try:
            yield event
        except Exception as exc:
            event.outcome = "error"
            if not event.detail:
                event.detail = "%s: %s" % (type(exc).__name__, exc)
            self.record(event)
            raise
        else:
            if not decision.allowed and event.outcome == "ok":
                event.outcome = "denied"
            self.record(event)

    # -- reading ---------------------------------------------------------

    def history(
        self,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: Optional[int] = None,
        include_denied: bool = True,
    ) -> List[RecordedAccess]:
        """Receipts from the ledger, oldest first."""
        out: List[RecordedAccess] = []
        for entry in self.ledger.entries():
            if entry.kind not in ("receipt.access", "receipt.denied"):
                continue
            if entry.kind == "receipt.denied" and not include_denied:
                continue
            if since and entry.ts < since:
                continue
            if until and entry.ts > until:
                continue
            payload = entry.body.get("event")
            if not isinstance(payload, dict):
                continue
            try:
                event = AccessEvent.from_dict(payload)
            except (KeyError, ValueError):
                continue
            if actor and event.actor != actor:
                continue
            if resource and resource not in event.resource:
                continue
            decision_data = entry.body.get("decision")
            decision = None
            if isinstance(decision_data, dict):
                decision = Decision(
                    allowed=bool(decision_data.get("allowed", True)),
                    grant=decision_data.get("grant", ""),
                )
            out.append(
                RecordedAccess(entry.seq, event, decision, entry.body.get("flags", []))
            )
        if limit is not None:
            out = out[-limit:]
        return out

    def events(self, **kwargs: Any) -> List[AccessEvent]:
        """Just the events, for the renderer."""
        return [record.event for record in self.history(**kwargs)]

    # -- anomaly flags ---------------------------------------------------

    def unusual(self, event: AccessEvent) -> List[str]:
        """Note what is new or out of character about this access.

        Not anomaly detection in any statistical sense -- just the handful of
        comparisons against recorded history that catch the cases worth a second
        look. Every one is phrased so it can appear directly on a receipt.
        """
        flags: List[str] = []
        prior = [r.event for r in self.history(actor=event.actor)]
        if not prior:
            flags.append("first recorded access by %s" % event.actor)
            return flags

        if all(p.resource != event.resource for p in prior):
            flags.append("first time %s has touched %s" % (event.actor, event.resource))

        seen_actions = {p.action for p in prior}
        if event.action not in seen_actions:
            if event.is_write and not any(
                p.is_write for p in prior
            ):
                flags.append(
                    "%s has only ever read before; this is its first write-type "
                    "action (%s)" % (event.actor, event.action)
                )
            else:
                flags.append("first %s by %s" % (event.action, event.actor))

        same_resource = [p for p in prior if p.resource == event.resource and p.items]
        if same_resource and event.items:
            busiest = max(p.items for p in same_resource)
            if event.items > busiest * 3:
                flags.append(
                    "touched %d items, more than three times the previous high of %d"
                    % (event.items, busiest)
                )

        seen_classes = {c for p in prior for c in p.data_classes}
        new_classes = [c for c in event.data_classes if c not in seen_classes]
        if new_classes:
            flags.append(
                "first access to %s by this actor" % ", ".join(sorted(new_classes))
            )

        seen_egress = {d for p in prior for d in p.egress}
        new_egress = [d for d in event.egress if d not in seen_egress]
        if new_egress:
            flags.append("data sent to %s for the first time" % ", ".join(sorted(new_egress)))

        return flags

    def summary_counts(self) -> Dict[str, int]:
        records = self.history()
        # Writes and egress count only what actually happened. A refused delete
        # is a denial, not a write, and counting it as both would overstate what
        # the agent managed to do.
        happened = [r for r in records if r.event.outcome != "denied"]
        return {
            "receipts": len(records),
            "denied": len(records) - len(happened),
            "writes": sum(1 for r in happened if r.event.is_write),
            "egress": sum(1 for r in happened if r.event.egress),
            "flagged": sum(1 for r in records if r.flags),
        }
