"""What changed between two versions of a tool, and whether it matters.

Tool schemas drift as quietly as models do. A parameter becomes required, an
enum loses a value, a read-only tool acquires the ability to write -- and the
agent calling it keeps going, failing in ways that look like model problems.

Changes are sorted into four severities, because "breaking" and "alarming" are
different questions:

``escalation``
    The tool now does more to the world than it used to: it writes where it only
    read, it reaches the network, it can destroy data, it wants a new class of
    personal data. Nothing about the call signature broke. This is the severity
    that matters when you are installing somebody else's skill, and it is the
    one no other schema tool reports.

``breaking``
    Existing callers stop working: a parameter vanished, changed type, or became
    required; an accepted enum value was withdrawn; a bound tightened.

``behaviour``
    Calls still succeed but may do something different: a default moved, a bound
    loosened, a new optional parameter appeared.

``cosmetic``
    Prose only. Worth showing in a diff, never worth failing a build over.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .neutral import Param, ToolSchema

__all__ = ["Change", "diff", "worst_severity", "format_changes", "SEVERITIES"]

#: Ordered from most to least serious, which is also the display order.
SEVERITIES = ("escalation", "breaking", "behaviour", "cosmetic")

_RANK = {name: index for index, name in enumerate(SEVERITIES)}


class Change:
    __slots__ = ("severity", "path", "detail")

    def __init__(self, severity: str, path: str, detail: str) -> None:
        if severity not in _RANK:
            raise ValueError("unknown severity %r" % (severity,))
        self.severity = severity
        self.path = path
        self.detail = detail

    def __repr__(self) -> str:
        return "Change(%s, %s: %s)" % (self.severity, self.path, self.detail)

    def to_dict(self) -> Dict[str, str]:
        return {"severity": self.severity, "path": self.path, "detail": self.detail}

    def format(self) -> str:
        return "  %-11s %-24s %s" % (self.severity, self.path, self.detail)


def _describe_default(param: Param) -> str:
    return repr(param.default) if param.has_default else "none"


def _diff_param(old: Param, new: Param, path: str, out: List[Change]) -> None:
    if old.type != new.type:
        out.append(
            Change("breaking", path, "type changed from %s to %s" % (old.type, new.type))
        )
    if not old.required and new.required:
        out.append(Change("breaking", path, "became required"))
    elif old.required and not new.required:
        out.append(Change("behaviour", path, "no longer required"))

    if old.values or new.values:
        removed = [v for v in old.values if v not in new.values]
        added = [v for v in new.values if v not in old.values]
        if removed:
            out.append(
                Change(
                    "breaking",
                    path,
                    "enum values withdrawn: %s" % ", ".join(repr(v) for v in removed),
                )
            )
        if added:
            out.append(
                Change(
                    "behaviour",
                    path,
                    "enum values added: %s" % ", ".join(repr(v) for v in added),
                )
            )

    for attr, label, tighter in (
        ("minimum", "minimum", "raised"),
        ("min_length", "minLength", "raised"),
        ("min_items", "minItems", "raised"),
    ):
        _diff_bound(getattr(old, attr), getattr(new, attr), path, label, out, raising_is_tighter=True)
    for attr, label, _ in (
        ("maximum", "maximum", ""),
        ("max_length", "maxLength", ""),
        ("max_items", "maxItems", ""),
    ):
        _diff_bound(getattr(old, attr), getattr(new, attr), path, label, out, raising_is_tighter=False)

    if old.pattern != new.pattern:
        severity = "breaking" if new.pattern else "behaviour"
        out.append(
            Change(severity, path, "pattern changed from %r to %r" % (old.pattern, new.pattern))
        )
    if _describe_default(old) != _describe_default(new):
        out.append(
            Change(
                "behaviour",
                path,
                "default changed from %s to %s" % (_describe_default(old), _describe_default(new)),
            )
        )
    if old.description != new.description:
        out.append(Change("cosmetic", path, "description reworded"))

    old_props = {p.name: p for p in old.properties}
    new_props = {p.name: p for p in new.properties}
    _diff_param_sets(old_props, new_props, path, out)
    if old.items and new.items:
        _diff_param(old.items, new.items, path + "[]", out)


def _diff_bound(
    old_value: Optional[float],
    new_value: Optional[float],
    path: str,
    label: str,
    out: List[Change],
    raising_is_tighter: bool,
) -> None:
    if old_value == new_value:
        return
    if old_value is None:
        out.append(Change("breaking", path, "%s constraint added (%s)" % (label, new_value)))
    elif new_value is None:
        out.append(Change("behaviour", path, "%s constraint removed" % label))
    else:
        raised = new_value > old_value
        tighter = raised if raising_is_tighter else not raised
        out.append(
            Change(
                "breaking" if tighter else "behaviour",
                path,
                "%s moved from %s to %s" % (label, old_value, new_value),
            )
        )


def _diff_param_sets(
    old: Dict[str, Param], new: Dict[str, Param], prefix: str, out: List[Change]
) -> None:
    for name, param in old.items():
        path = "%s.%s" % (prefix, name) if prefix else name
        if name not in new:
            out.append(Change("breaking", path, "parameter removed"))
        else:
            _diff_param(param, new[name], path, out)
    for name, param in new.items():
        if name in old:
            continue
        path = "%s.%s" % (prefix, name) if prefix else name
        if param.required:
            out.append(Change("breaking", path, "new required parameter"))
        else:
            out.append(Change("behaviour", path, "new optional parameter"))


def _diff_effects(old: ToolSchema, new: ToolSchema, out: List[Change]) -> None:
    gained_writes = [w for w in new.effects.writes if w not in old.effects.writes]
    gained_reads = [r for r in new.effects.reads if r not in old.effects.reads]
    if gained_writes:
        out.append(
            Change("escalation", "effects.writes", "now writes %s" % ", ".join(gained_writes))
        )
    if gained_reads:
        out.append(
            Change("escalation", "effects.reads", "now reads %s" % ", ".join(gained_reads))
        )
    if new.effects.network and not old.effects.network:
        out.append(Change("escalation", "effects.network", "now reaches the network"))
    if new.effects.destructive and not old.effects.destructive:
        out.append(Change("escalation", "effects.destructive", "can now destroy data"))
    if old.effects.idempotent and not new.effects.idempotent:
        out.append(
            Change("behaviour", "effects.idempotent", "repeating a call is no longer safe")
        )

    gained_classes = [
        c for c in new.consent.data_classes if c not in old.consent.data_classes
    ]
    if gained_classes:
        out.append(
            Change(
                "escalation",
                "consent.data_classes",
                "now touches %s" % ", ".join(gained_classes),
            )
        )
    if new.consent.required and not old.consent.required:
        out.append(Change("escalation", "consent.required", "now requires consent"))
    gained_egress = [e for e in new.consent.egress if e not in old.consent.egress]
    if gained_egress:
        out.append(
            Change(
                "escalation",
                "consent.egress",
                "data can now leave to %s" % ", ".join(gained_egress),
            )
        )


def diff(old: ToolSchema, new: ToolSchema) -> List[Change]:
    """Every difference between two versions, most serious first."""
    out: List[Change] = []
    if old.name != new.name:
        out.append(
            Change("breaking", "name", "renamed from %s to %s" % (old.name, new.name))
        )
    if old.description != new.description:
        out.append(Change("cosmetic", "description", "reworded"))
    _diff_param_sets(
        {p.name: p for p in old.params}, {p.name: p for p in new.params}, "", out
    )
    _diff_effects(old, new, out)
    if old.returns and new.returns:
        _diff_param(old.returns, new.returns, "returns", out)
    elif old.returns and not new.returns:
        out.append(Change("breaking", "returns", "return schema removed"))
    elif new.returns and not old.returns:
        out.append(Change("behaviour", "returns", "return schema added"))
    out.sort(key=lambda change: (_RANK[change.severity], change.path))
    return out


def worst_severity(changes: List[Change]) -> Optional[str]:
    """The most serious severity present, or None when nothing changed."""
    if not changes:
        return None
    return min(changes, key=lambda change: _RANK[change.severity]).severity


def format_changes(changes: List[Change]) -> str:
    if not changes:
        return "no changes"
    lines = []
    for severity in SEVERITIES:
        group = [c for c in changes if c.severity == severity]
        if group:
            lines.append("%s (%d):" % (severity, len(group)))
            lines.extend(change.format() for change in group)
    return "\n".join(lines)
