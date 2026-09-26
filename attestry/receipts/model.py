"""What an access looks like when you write it down.

The unit is one access to one resource by one actor for one stated purpose. The
fields are chosen so that the plain-English renderer has everything it needs to
produce a sentence a person can check -- and, just as importantly, so that the
policy checker can compare a real access against what was actually permitted.

The design rule throughout: record what was touched, never what it said. An
access event says "read 42 messages, subject and sender only", never the
subjects. A log that quotes the data it is auditing is a second copy of the
problem.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..schema.neutral import DATA_CLASSES
from ..util.timeutil import now_rfc3339

__all__ = ["AccessEvent", "ACTIONS", "OUTCOMES", "DATA_CLASSES", "RESOURCE_NOUNS"]

#: What an actor can do to a resource. Read-ish actions are separated from
#: write-ish ones because the consent question is completely different.
ACTIONS = (
    "read",
    "list",
    "search",
    "write",
    "update",
    "send",
    "delete",
    "share",
    "execute",
)

OUTCOMES = ("ok", "partial", "denied", "error")

#: Human nouns per resource scheme, so the renderer can say "42 messages"
#: rather than "42 items". Singular and plural.
RESOURCE_NOUNS = {
    "email": ("message", "messages"),
    "calendar": ("event", "events"),
    "contacts": ("contact", "contacts"),
    "files": ("file", "files"),
    "file": ("file", "files"),
    "db": ("record", "records"),
    "http": ("request", "requests"),
    "browser": ("page", "pages"),
    "chat": ("message", "messages"),
    "repo": ("file", "files"),
}


class AccessEvent:
    """One thing an agent did to one resource."""

    __slots__ = (
        "actor", "action", "resource", "purpose", "items", "fields",
        "data_classes", "egress", "selector", "outcome", "grant", "tool",
        "detail", "ts",
    )

    def __init__(
        self,
        actor: str,
        action: str,
        resource: str,
        purpose: str = "",
        items: int = 0,
        fields: Optional[Sequence[str]] = None,
        data_classes: Optional[Sequence[str]] = None,
        egress: Optional[Sequence[str]] = None,
        selector: str = "",
        outcome: str = "ok",
        grant: str = "",
        tool: str = "",
        detail: str = "",
        ts: Optional[str] = None,
    ) -> None:
        if action not in ACTIONS:
            raise ValueError(
                "unknown action %r; expected one of %s" % (action, ", ".join(ACTIONS))
            )
        if outcome not in OUTCOMES:
            raise ValueError("unknown outcome %r" % (outcome,))
        self.actor = actor
        self.action = action
        self.resource = resource
        self.purpose = purpose
        self.items = int(items)
        self.fields = list(fields or [])
        self.data_classes = list(data_classes or [])
        self.egress = list(egress or [])
        self.selector = selector
        self.outcome = outcome
        self.grant = grant
        self.tool = tool
        self.detail = detail
        self.ts = ts or now_rfc3339()

    def __repr__(self) -> str:
        return "AccessEvent(%s %s %s, %s)" % (
            self.actor, self.action, self.resource, self.outcome
        )

    @property
    def scheme(self) -> str:
        """The resource scheme: ``email`` out of ``email:gmail/INBOX``."""
        return self.resource.split(":", 1)[0] if ":" in self.resource else self.resource

    @property
    def is_write(self) -> bool:
        return self.action in ("write", "update", "send", "delete", "share", "execute")

    @property
    def left_the_machine(self) -> bool:
        return bool(self.egress)

    def unknown_data_classes(self) -> List[str]:
        return [c for c in self.data_classes if c not in DATA_CLASSES]

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "ts": self.ts,
        }
        if self.purpose:
            out["purpose"] = self.purpose
        if self.items:
            out["items"] = self.items
        if self.fields:
            out["fields"] = self.fields
        if self.data_classes:
            out["data_classes"] = self.data_classes
        if self.egress:
            out["egress"] = self.egress
        if self.selector:
            out["selector"] = self.selector
        if self.grant:
            out["grant"] = self.grant
        if self.tool:
            out["tool"] = self.tool
        if self.detail:
            out["detail"] = self.detail
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AccessEvent":
        return cls(
            actor=data["actor"],
            action=data["action"],
            resource=data["resource"],
            purpose=data.get("purpose", ""),
            items=data.get("items", 0),
            fields=data.get("fields"),
            data_classes=data.get("data_classes"),
            egress=data.get("egress"),
            selector=data.get("selector", ""),
            outcome=data.get("outcome", "ok"),
            grant=data.get("grant", ""),
            tool=data.get("tool", ""),
            detail=data.get("detail", ""),
            ts=data.get("ts"),
        )
