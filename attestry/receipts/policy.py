"""What each agent is allowed to touch, and the check that says whether it did.

A receipt on its own tells you what happened. A grant tells you what was
supposed to happen. The gap between them is the only thing anybody actually
wants to know, and it is what turns a log into an audit.

Grants are written by hand in ``.attestry/receipts/consent.json`` and committed.
They are deliberately narrow: an actor, some resource patterns, the actions
allowed, the purposes those actions may serve, the classes of data that may be
touched, and where that data may be sent. Anything not granted is refused, and
the refusal is itself recorded -- a denied access is exactly the event you want
in the log a month later.

Purpose matters as much as scope, which is the part most access-control systems
leave out. "May read your calendar" and "may read your calendar in order to
schedule meetings" are different permissions, and the second one is the one
people think they gave.
"""

from __future__ import annotations

import fnmatch
import json
import os
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..util.timeutil import now_rfc3339, parse_rfc3339
from .model import AccessEvent

__all__ = ["Grant", "ConsentPolicy", "Decision", "Violation", "example_policy"]


class Violation:
    """One reason an access was not permitted."""

    __slots__ = ("code", "detail", "severity")

    def __init__(self, code: str, detail: str, severity: str = "deny") -> None:
        self.code = code
        self.detail = detail
        self.severity = severity

    def __repr__(self) -> str:
        return "Violation(%s: %s)" % (self.code, self.detail)

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "detail": self.detail, "severity": self.severity}


class Decision:
    """The verdict on one access event."""

    __slots__ = ("allowed", "grant", "violations")

    def __init__(
        self,
        allowed: bool,
        grant: str = "",
        violations: Optional[Sequence[Violation]] = None,
    ) -> None:
        self.allowed = allowed
        self.grant = grant
        self.violations = list(violations or [])

    def __repr__(self) -> str:
        return "Decision(%s, grant=%s, %d violations)" % (
            "allowed" if self.allowed else "denied", self.grant, len(self.violations)
        )

    @property
    def warnings(self) -> List[Violation]:
        return [v for v in self.violations if v.severity == "warn"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "grant": self.grant,
            "violations": [v.to_dict() for v in self.violations],
        }

    def explain(self) -> str:
        if self.allowed and not self.violations:
            return "permitted by grant %s" % (self.grant or "(none required)")
        lines = [
            "permitted by grant %s, with notes:" % self.grant
            if self.allowed
            else "refused:"
        ]
        for violation in self.violations:
            lines.append("  - %s" % violation.detail)
        return "\n".join(lines)


class Grant:
    """One permission: who may do what, to what, for which purpose."""

    __slots__ = (
        "id", "actor", "resources", "actions", "purposes", "data_classes",
        "egress", "expires", "max_items", "note",
    )

    def __init__(
        self,
        id: str,
        actor: str,
        resources: Optional[Sequence[str]] = None,
        actions: Optional[Sequence[str]] = None,
        purposes: Optional[Sequence[str]] = None,
        data_classes: Optional[Sequence[str]] = None,
        egress: Optional[Sequence[str]] = None,
        expires: str = "",
        max_items: Optional[int] = None,
        note: str = "",
    ) -> None:
        self.id = id
        self.actor = actor
        self.resources = list(resources or [])
        self.actions = list(actions or [])
        self.purposes = list(purposes or [])
        self.data_classes = list(data_classes or [])
        self.egress = list(egress or [])
        self.expires = expires
        self.max_items = max_items
        self.note = note

    def __repr__(self) -> str:
        return "Grant(%s, %s)" % (self.id, self.actor)

    def covers(self, event: AccessEvent) -> bool:
        """Does this grant address the actor, resource and action at all?

        Scope only. Purpose, data classes, volume and egress are checked
        separately, so that an access can be reported as "the right grant, used
        for the wrong purpose" rather than the far less useful "not permitted".
        """
        if not fnmatch.fnmatch(event.actor, self.actor):
            return False
        if self.actions and event.action not in self.actions:
            return False
        if not self.resources:
            return False
        return any(fnmatch.fnmatch(event.resource, pattern) for pattern in self.resources)

    def expired(self, when: Optional[str] = None) -> bool:
        if not self.expires:
            return False
        try:
            return parse_rfc3339(when or now_rfc3339()) > parse_rfc3339(self.expires)
        except ValueError:
            # An unparseable expiry is treated as expired: a grant nobody can
            # read the end date of should not keep working forever.
            return True

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"id": self.id, "actor": self.actor, "resources": self.resources}
        if self.actions:
            out["actions"] = self.actions
        if self.purposes:
            out["purposes"] = self.purposes
        if self.data_classes:
            out["data_classes"] = self.data_classes
        if self.egress:
            out["egress"] = self.egress
        if self.expires:
            out["expires"] = self.expires
        if self.max_items is not None:
            out["max_items"] = self.max_items
        if self.note:
            out["note"] = self.note
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Grant":
        return cls(
            id=data["id"],
            actor=data.get("actor", "*"),
            resources=data.get("resources"),
            actions=data.get("actions"),
            purposes=data.get("purposes"),
            data_classes=data.get("data_classes"),
            egress=data.get("egress"),
            expires=data.get("expires", ""),
            max_items=data.get("max_items"),
            note=data.get("note", ""),
        )


class ConsentPolicy:
    """The set of grants in force, loaded from and saved to one JSON file."""

    def __init__(
        self,
        grants: Optional[Sequence[Grant]] = None,
        default_deny: bool = True,
        path: str = "",
    ) -> None:
        self.grants = list(grants or [])
        self.default_deny = default_deny
        self.path = path

    def __len__(self) -> int:
        return len(self.grants)

    def grant(self, grant_id: str) -> Optional[Grant]:
        for candidate in self.grants:
            if candidate.id == grant_id:
                return candidate
        return None

    # -- persistence -----------------------------------------------------

    @classmethod
    def load(cls, path: str) -> "ConsentPolicy":
        if not os.path.exists(path):
            return cls(path=path)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(
            grants=[Grant.from_dict(g) for g in data.get("grants", [])],
            default_deny=bool(data.get("default_deny", True)),
            path=path,
        )

    def save(self, path: str = "") -> str:
        target = path or self.path
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "default_deny": self.default_deny,
                    "grants": [g.to_dict() for g in self.grants],
                },
                handle,
                indent=2,
            )
            handle.write("\n")
        return target

    # -- the check -------------------------------------------------------

    def check(self, event: AccessEvent) -> Decision:
        """Decide whether ``event`` was permitted, and say why not."""
        candidates = [g for g in self.grants if g.covers(event)]
        if not candidates:
            if not self.default_deny:
                return Decision(
                    True,
                    "",
                    [
                        Violation(
                            "no-grant",
                            "no grant covers %s %s on %s, but the policy does not "
                            "default to deny" % (event.actor, event.action, event.resource),
                            severity="warn",
                        )
                    ],
                )
            return Decision(
                False,
                "",
                [
                    Violation(
                        "no-grant",
                        "nothing permits %s to %s %s"
                        % (event.actor, event.action, event.resource),
                    )
                ],
            )

        # Try every covering grant and keep the best outcome: one grant being
        # expired should not mask another that legitimately allows the access.
        best: Optional[Decision] = None
        for grant in candidates:
            decision = self._check_against(event, grant)
            if decision.allowed and not decision.violations:
                return decision
            if best is None or (decision.allowed and not best.allowed):
                best = decision
            elif decision.allowed == best.allowed and len(decision.violations) < len(best.violations):
                best = decision
        return best or Decision(False, "", [Violation("no-grant", "no grant applied")])

    def _check_against(self, event: AccessEvent, grant: Grant) -> Decision:
        violations: List[Violation] = []

        if grant.expired(event.ts):
            violations.append(
                Violation(
                    "expired",
                    "grant %s expired on %s" % (grant.id, grant.expires),
                )
            )

        if grant.purposes:
            if not event.purpose:
                violations.append(
                    Violation(
                        "purpose-missing",
                        "grant %s is limited to specific purposes but the access "
                        "declared none" % grant.id,
                    )
                )
            elif not any(
                fnmatch.fnmatch(event.purpose, pattern) for pattern in grant.purposes
            ):
                violations.append(
                    Violation(
                        "purpose-undeclared",
                        "purpose %r is not among those granted (%s)"
                        % (event.purpose, ", ".join(grant.purposes)),
                    )
                )

        if grant.data_classes:
            extra = [c for c in event.data_classes if c not in grant.data_classes]
            if extra:
                violations.append(
                    Violation(
                        "data-class-undeclared",
                        "touched %s, which grant %s does not cover"
                        % (", ".join(extra), grant.id),
                    )
                )

        if event.egress:
            if not grant.egress:
                violations.append(
                    Violation(
                        "egress-forbidden",
                        "data was sent to %s but grant %s allows no egress at all"
                        % (", ".join(event.egress), grant.id),
                    )
                )
            else:
                stray = [
                    destination
                    for destination in event.egress
                    if not any(
                        fnmatch.fnmatch(destination, pattern) for pattern in grant.egress
                    )
                ]
                if stray:
                    violations.append(
                        Violation(
                            "egress-undeclared",
                            "data was sent to %s, which grant %s does not allow"
                            % (", ".join(stray), grant.id),
                        )
                    )

        if grant.max_items is not None and event.items > grant.max_items:
            violations.append(
                Violation(
                    "volume-exceeded",
                    "touched %d items, above the %d permitted by grant %s"
                    % (event.items, grant.max_items, grant.id),
                )
            )

        unknown = event.unknown_data_classes()
        if unknown:
            violations.append(
                Violation(
                    "data-class-unknown",
                    "data class %s is outside the shared vocabulary, so it cannot "
                    "be checked properly" % ", ".join(unknown),
                    severity="warn",
                )
            )

        blocking = [v for v in violations if v.severity == "deny"]
        return Decision(not blocking, grant.id, violations)


def example_policy() -> ConsentPolicy:
    """A starter policy, written by ``attestry receipts init``."""
    return ConsentPolicy(
        grants=[
            Grant(
                id="inbox-triage",
                actor="agent:inbox-triage",
                resources=["email:*/INBOX"],
                actions=["read", "list", "search"],
                purposes=["draft daily priorities", "flag urgent messages"],
                data_classes=["message_content", "contact_info"],
                egress=[],
                max_items=200,
                note=(
                    "Read-only, local only. Sending or deleting mail is not "
                    "granted, and neither is shipping anything off the machine."
                ),
            ),
            Grant(
                id="calendar-scheduler",
                actor="agent:scheduler",
                resources=["calendar:*"],
                actions=["read", "list", "write"],
                purposes=["schedule meetings"],
                data_classes=["calendar", "contact_info"],
                egress=["api.anthropic.com"],
                note="May create events and may call a model to word invitations.",
            ),
        ],
        default_deny=True,
    )
