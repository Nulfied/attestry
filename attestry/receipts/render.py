"""Turning an access event into a sentence a person can actually check.

This module is the point of the whole subsystem. Structured audit logs already
exist and nobody reads them, because reading them requires knowing the schema,
the resource naming convention and which fields were elided. A receipt that says

    On 25 Sep 2026 at 14:03 UTC, the inbox-triage agent read 42 messages in your
    Gmail inbox (subject and sender only) in order to draft your daily
    priorities. No data left your machine.

can be checked by the person whose inbox it was, which is the only audience that
matters. If they read that and think "it did *what*?", the system worked.

Two rules the renderer holds to. It never invents specificity -- an unrecognised
resource is described with its raw identifier rather than dressed up in prose
that might be wrong. And it always states the egress position explicitly, in
both directions, because "no data left your machine" is the sentence people most
want and silence does not convey it.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..util.timeutil import pretty_when
from .model import RESOURCE_NOUNS, AccessEvent
from .policy import Decision

__all__ = [
    "describe_event",
    "render_receipt",
    "render_digest",
    "render_html",
    "describe_actor",
    "describe_resource",
    "join_and",
]

_PAST = {
    "read": "read",
    "list": "listed",
    "search": "searched",
    "write": "wrote to",
    "update": "updated",
    "send": "sent",
    "delete": "deleted",
    "share": "shared",
    "execute": "ran",
}

_SCHEME_WORDS = {
    "email": "mailbox",
    "calendar": "calendar",
    "contacts": "contacts",
    "files": "files",
    "file": "files",
    "db": "database",
    "http": "endpoint",
    "browser": "browsing data",
    "chat": "conversation",
    "repo": "repository",
}

_PROVIDER_NAMES = {
    "gmail": "Gmail",
    "google": "Google",
    "outlook": "Outlook",
    "icloud": "iCloud",
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "sqlite": "SQLite",
    "slack": "Slack",
    "notion": "Notion",
    "github": "GitHub",
}


def join_and(items: Sequence[str], conjunction: str = "and") -> str:
    """``['a','b','c']`` becomes ``'a, b and c'``."""
    values = [str(i) for i in items if str(i)]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    return "%s %s %s" % (", ".join(values[:-1]), conjunction, values[-1])


def describe_actor(actor: str) -> str:
    """``agent:inbox-triage`` becomes ``the inbox-triage agent``."""
    if ":" not in actor:
        return actor or "an unidentified actor"
    kind, name = actor.split(":", 1)
    if kind == "agent":
        return "the %s agent" % name
    if kind == "tool":
        return "the %s tool" % name
    if kind == "user":
        return "the user %s" % name
    if kind == "service":
        return "the %s service" % name
    return "%s (%s)" % (name, kind)


def describe_resource(resource: str) -> str:
    """Render a resource identifier as a phrase, without inventing detail."""
    if ":" not in resource:
        return resource or "an unnamed resource"
    scheme, path = resource.split(":", 1)
    parts = [p for p in path.split("/") if p]
    provider = _PROVIDER_NAMES.get(parts[0].lower(), parts[0]) if parts else ""
    leaf = parts[-1] if len(parts) > 1 else ""

    if scheme == "email":
        if leaf.upper() == "INBOX":
            return "your %s inbox" % provider if provider else "your inbox"
        if leaf:
            return "your %s %s folder" % (provider, leaf) if provider else "your %s folder" % leaf
        return "your %s mailbox" % provider if provider else "your mailbox"
    if scheme == "calendar":
        if leaf in ("primary", "default"):
            return "your primary %s calendar" % provider if provider else "your main calendar"
        if leaf:
            return "your %s calendar %r" % (provider, leaf) if provider else "your %r calendar" % leaf
        return "your %s calendar" % provider if provider else "your calendar"
    if scheme == "contacts":
        return "your %s contacts" % provider if provider else "your contacts"
    if scheme in ("files", "file", "repo"):
        return "files under %s" % path
    if scheme == "db":
        if leaf:
            return "the %s table in %s" % (leaf, provider)
        return "the %s database" % provider
    if scheme == "http":
        return path

    word = _SCHEME_WORDS.get(scheme, scheme)
    return "%s (%s)" % (path, word)


def _items_phrase(event: AccessEvent) -> str:
    if not event.items:
        return ""
    singular, plural = RESOURCE_NOUNS.get(event.scheme, ("item", "items"))
    noun = singular if event.items == 1 else plural
    return "%d %s in" % (event.items, noun)


def _fields_phrase(event: AccessEvent) -> str:
    if not event.fields:
        return ""
    return " (%s only)" % join_and(event.fields)


def _outcome_clause(event: AccessEvent) -> str:
    if event.outcome == "denied":
        return " The attempt was refused, so nothing was accessed."
    if event.outcome == "partial":
        return " The operation only partly completed."
    if event.outcome == "error":
        return " The operation failed part-way through."
    return ""


def _egress_clause(event: AccessEvent) -> str:
    if event.egress:
        return " This data was sent to %s." % join_and(event.egress)
    return " No data left your machine."


def describe_event(event: AccessEvent) -> str:
    """One sentence (occasionally two) describing one access."""
    verb = _PAST.get(event.action, event.action)
    items = _items_phrase(event)
    target = describe_resource(event.resource)
    subject = describe_actor(event.actor)

    if items:
        middle = "%s %s %s" % (verb, items, target)
    else:
        middle = "%s %s" % (verb, target)

    sentence = "On %s, %s %s%s" % (
        pretty_when(event.ts),
        subject,
        middle,
        _fields_phrase(event),
    )
    if event.selector:
        sentence += ", covering %s" % event.selector
    if event.purpose:
        sentence += ", in order to %s" % event.purpose
    sentence += "."
    sentence += _outcome_clause(event)
    if event.outcome != "denied":
        sentence += _egress_clause(event)
    return sentence


def render_receipt(
    event: AccessEvent,
    decision: Optional[Decision] = None,
    flags: Optional[Sequence[str]] = None,
    seq: Optional[int] = None,
) -> str:
    """A full receipt: the sentence, then the checkable detail beneath it."""
    lines = [describe_event(event)]
    lines.append("")
    if seq is not None:
        lines.append("  ledger entry   #%d" % seq)
    lines.append("  actor          %s" % event.actor)
    lines.append("  action         %s on %s" % (event.action, event.resource))
    if event.tool:
        lines.append("  via tool       %s" % event.tool)
    if event.data_classes:
        lines.append("  data touched   %s" % join_and(event.data_classes))
    if event.detail:
        lines.append("  detail         %s" % event.detail)
    if decision is not None:
        lines.append(
            "  consent        %s"
            % ("permitted by grant %s" % decision.grant if decision.allowed
               else "NOT PERMITTED")
        )
        for violation in decision.violations:
            marker = "warning" if violation.severity == "warn" else "violation"
            lines.append("    %-10s %s" % (marker, violation.detail))
    for flag in flags or []:
        lines.append("  unusual        %s" % flag)
    return "\n".join(lines)


def render_digest(
    events: Sequence[AccessEvent],
    title: str = "Access summary",
    period: str = "",
) -> str:
    """A grouped summary, which is the form anybody reads more than once.

    Per-event receipts are the right thing when something looks wrong. For the
    routine case -- the weekly "what have these agents been doing" question --
    what helps is the shape of the activity: who, how much, and whether anything
    left the machine.
    """
    if not events:
        return "%s: nothing recorded%s." % (title, " for %s" % period if period else "")

    by_actor: Dict[str, List[AccessEvent]] = {}
    for event in events:
        by_actor.setdefault(event.actor, []).append(event)

    lines = [title]
    if period:
        lines.append(period)
    lines.append("=" * max(len(title), len(period) if period else 0))
    lines.append("")

    # Denied attempts are counted, never credited. A refused read touched
    # nothing, so its item count and its intended egress must stay out of every
    # total -- otherwise the summary claims more happened than did, which is the
    # one mistake that would make these receipts worse than no receipts.
    denied = [e for e in events if e.outcome == "denied"]
    happened = [e for e in events if e.outcome != "denied"]
    total_items = sum(e.items for e in happened)
    writes = [e for e in happened if e.is_write]
    egressed = [e for e in happened if e.egress]

    lines.append(
        "%d access%s by %d agent%s, touching %s in total."
        % (
            len(events),
            "" if len(events) == 1 else "es",
            len(by_actor),
            "" if len(by_actor) == 1 else "s",
            _count_noun(total_items, "item"),
        )
    )
    if writes:
        lines.append(
            "%d of them changed or sent something: %s."
            % (len(writes), join_and(sorted({e.action for e in writes})))
        )
    else:
        lines.append("Nothing was changed, sent or deleted.")
    if egressed:
        destinations = sorted({d for e in egressed for d in e.egress})
        lines.append(
            "Data left your machine %s, to %s."
            % (_count_noun(len(egressed), "time"), join_and(destinations))
        )
    else:
        lines.append("No data left your machine.")
    if denied:
        blocked_egress = sorted({d for e in denied for d in e.egress})
        lines.append(
            "%s refused by policy%s."
            % (
                _count_noun(len(denied), "attempt").capitalize(),
                " (one of which would have sent data to %s)" % join_and(blocked_egress)
                if blocked_egress
                else "",
            )
        )

    for actor in sorted(by_actor):
        group = by_actor[actor]
        lines.append("")
        lines.append("%s" % describe_actor(actor))
        resources: Dict[str, int] = {}
        purposes: List[str] = []
        for event in group:
            if event.outcome == "denied":
                continue
            resources[event.resource] = resources.get(event.resource, 0) + event.items
            if event.purpose and event.purpose not in purposes:
                purposes.append(event.purpose)
        for resource, count in sorted(resources.items()):
            lines.append(
                "  %s%s"
                % (
                    describe_resource(resource),
                    " -- %s" % _count_noun(count, "item") if count else "",
                )
            )
        refused = [e for e in group if e.outcome == "denied"]
        for event in refused:
            lines.append(
                "  refused: %s on %s (%s)"
                % (event.action, describe_resource(event.resource),
                   event.purpose or "no purpose stated")
            )
        if purposes:
            lines.append("  stated purposes: %s" % join_and(purposes))
    return "\n".join(lines)


def _count_noun(count: int, noun: str) -> str:
    """``1`` becomes ``1 item``; ``3`` becomes ``3 items``."""
    return "%d %s%s" % (count, noun, "" if count == 1 else "s")


def render_html(
    receipts: Sequence[Mapping[str, Any]],
    title: str = "Access receipts",
) -> str:
    """A self-contained HTML page of receipts, for handing to somebody.

    No external assets and no scripts, so it survives being emailed, archived or
    opened years later. Each item takes ``{"event": AccessEvent, "decision":
    Decision or None, "flags": [...], "seq": int or None}``.
    """
    rows: List[str] = []
    for item in receipts:
        event: AccessEvent = item["event"]
        decision: Optional[Decision] = item.get("decision")
        flags: Sequence[str] = item.get("flags") or []
        classes = ["receipt"]
        if event.outcome == "denied" or (decision is not None and not decision.allowed):
            classes.append("denied")
        elif flags or (decision is not None and decision.warnings):
            classes.append("flagged")
        detail_rows = [
            ("Actor", event.actor),
            ("Action", "%s on %s" % (event.action, event.resource)),
        ]
        if event.tool:
            detail_rows.append(("Tool", event.tool))
        if event.data_classes:
            detail_rows.append(("Data touched", join_and(event.data_classes)))
        if event.egress:
            detail_rows.append(("Sent to", join_and(event.egress)))
        if decision is not None:
            detail_rows.append(
                (
                    "Consent",
                    "permitted by grant %s" % decision.grant
                    if decision.allowed
                    else "NOT PERMITTED",
                )
            )
            for violation in decision.violations:
                detail_rows.append((violation.severity.title(), violation.detail))
        for flag in flags:
            detail_rows.append(("Unusual", flag))
        if item.get("seq") is not None:
            detail_rows.append(("Ledger entry", "#%s" % item["seq"]))

        detail_html = "".join(
            "<tr><th>%s</th><td>%s</td></tr>" % (html.escape(str(k)), html.escape(str(v)))
            for k, v in detail_rows
        )
        rows.append(
            '<article class="%s"><p class="plain">%s</p><table>%s</table></article>'
            % (" ".join(classes), html.escape(describe_event(event)), detail_html)
        )

    return _HTML_SHELL % {
        "title": html.escape(title),
        "count": len(receipts),
        "body": "\n".join(rows) or "<p>Nothing recorded.</p>",
    }


_HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<style>
  :root {
    --bg: #ffffff; --fg: #1a1a1a; --muted: #5c5c5c; --line: #e2e2e2;
    --card: #fafafa; --warn-bg: #fff8e6; --warn-line: #e0b23c;
    --deny-bg: #fdeeee; --deny-line: #c94a4a;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #16181c; --fg: #ececec; --muted: #a0a4ab; --line: #2d3138;
      --card: #1d2026; --warn-bg: #2a2313; --warn-line: #b28b2a;
      --deny-bg: #2c1a1a; --deny-line: #c05a5a;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem 1rem; background: var(--bg); color: var(--fg);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  main { max-width: 46rem; margin: 0 auto; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
  .sub { color: var(--muted); margin: 0 0 2rem; font-size: .9rem; }
  article {
    border: 1px solid var(--line); border-left: 3px solid var(--muted);
    background: var(--card); border-radius: 6px;
    padding: 1rem 1.25rem; margin-bottom: 1rem;
  }
  article.flagged { background: var(--warn-bg); border-left-color: var(--warn-line); }
  article.denied { background: var(--deny-bg); border-left-color: var(--deny-line); }
  .plain { margin: 0 0 .75rem; font-size: 1.02rem; }
  table { width: 100%%; border-collapse: collapse; font-size: .84rem; }
  th, td { text-align: left; vertical-align: top; padding: .2rem .5rem .2rem 0; }
  th { color: var(--muted); font-weight: 500; width: 9rem; white-space: nowrap; }
  footer { color: var(--muted); font-size: .8rem; margin-top: 2rem;
           border-top: 1px solid var(--line); padding-top: 1rem; }
</style>
</head>
<body>
<main>
  <h1>%(title)s</h1>
  <p class="sub">%(count)d recorded access(es). Every line here corresponds to a
  signed entry in an append-only ledger and can be verified with
  <code>attestry ledger verify</code>.</p>
  %(body)s
  <footer>Generated by Attestry. Receipts record what was touched, never the
  contents.</footer>
</main>
</body>
</html>
"""
