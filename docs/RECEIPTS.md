# Consent receipts

## The problem with audit logs

They exist and nobody reads them. Reading one requires knowing the schema, the
resource naming convention, and which fields were elided. So the person whose
mailbox the agent read — the only audience that matters — cannot check it.

The test for this subsystem: if they read a receipt and think *"it did **what**?"*,
it worked.

## Access event

One access, by one actor, to one resource, for one stated purpose.

```json
{
  "actor": "agent:inbox-triage",
  "action": "read",
  "resource": "email:gmail/INBOX",
  "purpose": "draft daily priorities",
  "items": 42,
  "fields": ["subject", "from"],
  "data_classes": ["message_content"],
  "egress": [],
  "selector": "1-25 Sep",
  "outcome": "ok",
  "grant": "inbox-triage",
  "tool": "read_inbox",
  "detail": "",
  "ts": "2026-09-25T23:54:03Z"
}
```

Actions: `read`, `list`, `search`, `write`, `update`, `send`, `delete`, `share`,
`execute`. The first three are read-ish; the rest count as writes, because the
consent question is completely different.

Outcomes: `ok`, `partial`, `denied`, `error`.

**Record what was touched, never what it said.** An event says "read 42 messages,
subject and sender only" — never the subjects. A log that quotes the data it is
auditing is a second copy of the problem.

### Conventions

Actors are `kind:name` — `agent:inbox-triage`, `tool:web-fetch`, `user:sam`,
`service:cron`.

Resources are `scheme:path`:

| Scheme | Example | Renders as |
|---|---|---|
| `email` | `email:gmail/INBOX` | your Gmail inbox |
| `calendar` | `calendar:google/primary` | your primary Google calendar |
| `contacts` | `contacts:google` | your Google contacts |
| `files` | `files:/home/sam/docs` | files under /home/sam/docs |
| `db` | `db:postgres/users` | the users table in PostgreSQL |
| `http` | `http:api.example.com` | api.example.com |
| `chat`, `browser`, `repo` | | |

An unrecognised scheme renders as `path (scheme)`. The renderer does not invent
specificity it does not have.

Data classes, shared with [NTS](NTS.md) so a declaration and an actual access are
comparable without a mapping table: `contact_info`, `message_content`, `calendar`,
`files`, `location`, `credentials`, `financial`, `health`, `browsing`,
`identifiers`, `other`.

## Grants

`.attestry/receipts/consent.json`, committed:

```json
{
  "default_deny": true,
  "grants": [
    {
      "id": "inbox-triage",
      "actor": "agent:inbox-triage",
      "resources": ["email:*/INBOX"],
      "actions": ["read", "list", "search"],
      "purposes": ["draft daily priorities", "flag urgent messages"],
      "data_classes": ["message_content", "contact_info"],
      "egress": [],
      "max_items": 200,
      "expires": "2027-01-01T00:00:00Z",
      "note": "Read-only, local only."
    }
  ]
}
```

`actor`, `resources`, `purposes` and `egress` are glob patterns (`fnmatch`).
Omitting `actions` means any action. Omitting `purposes` means any purpose.
Empty `egress` means **no** egress is permitted.

### Purpose is part of the permission

"May read your calendar" and "may read your calendar **in order to schedule
meetings**" are different permissions, and the second one is what people think
they granted. Most access-control systems drop this, which is why a scope grant
feels broader than the consent the user believed they gave.

### Violation codes

| Code | Severity | Meaning |
|---|---|---|
| `no-grant` | deny | nothing covers this actor, action and resource |
| `expired` | deny | the covering grant has passed its `expires` |
| `purpose-missing` | deny | the grant lists purposes; the access declared none |
| `purpose-undeclared` | deny | the purpose is not among those granted |
| `data-class-undeclared` | deny | touched a class the grant does not cover |
| `egress-forbidden` | deny | data was sent but the grant allows no egress |
| `egress-undeclared` | deny | sent to a destination the grant does not list |
| `volume-exceeded` | deny | more items than `max_items` |
| `data-class-unknown` | warn | outside the shared vocabulary, so uncheckable |

Scope and conditions are separated on purpose, so an access can be reported as
*"the right grant, used for the wrong purpose"* rather than the far less useful
*"not permitted"*.

When several grants cover an access, each is evaluated and the best outcome wins.
One expired grant must not mask another that legitimately allows it.

An unparseable `expires` is treated as expired — a grant nobody can read the end
date of should not keep working forever.

## Recording

```python
from attestry.receipts import Recorder, ConsentPolicy

recorder = Recorder(ledger, ConsentPolicy.load(ws.consent_path),
                    actor="agent:inbox-triage", enforce=True)

with recorder.access("read", "email:gmail/INBOX",
                     purpose="draft daily priorities",
                     fields=["subject", "from"],
                     data_classes=["message_content"]) as event:
    messages = mailbox.fetch(limit=50)
    event.items = len(messages)
```

The consent check runs **on entry**, before your code touches anything, so
`enforce=True` stops an ungranted access rather than merely regretting it. The
receipt is written on exit either way, with the real item count — which you only
know afterwards.

If the body raises, the outcome becomes `error`, the exception is recorded in
`detail`, and the exception propagates. *"The agent tried to read your mailbox and
crashed"* is exactly the event an investigator wants and the one a naive
implementation drops.

A refused access is recorded as `receipt.denied` with `outcome: "denied"`. The
receipt must not claim it happened.

### From a tool schema

```python
from attestry.receipts import event_from_schema

event = event_from_schema(tool, "agent:triage", "read", "email:gmail/INBOX")
```

Purpose, data classes, egress and tool name default to the tool's declared
`consent` block. Repeating the declaration at every call site is how declarations
and reality drift apart; this way a discrepancy means somebody overrode it
deliberately.

## Unusual-access flags

Comparisons against recorded history, not statistics. Each is phrased to appear
directly on a receipt:

- first recorded access by this actor
- first time this actor has touched this resource
- this actor has only ever read before; first write-type action
- more than three times the previous high item count for this resource
- first access to a given data class by this actor
- data sent to a destination for the first time

## Rendering

### The sentence

```
On 25 Sep 2026 at 23:54 UTC, the inbox-triage agent read 42 messages in your
Gmail inbox (subject and from only), covering 1-25 Sep, in order to draft daily
priorities. No data left your machine.
```

Two rules the renderer holds to:

1. **Never invent specificity.** An unrecognised resource keeps its raw
   identifier rather than being dressed up in prose that might be wrong.
2. **Always state the egress position, in both directions.** "No data left your
   machine" is the sentence people most want, and silence does not convey it.

A denied access says *"The attempt was refused, so nothing was accessed."* and
omits the egress clause entirely, because nothing was sent.

### Digest

```bash
attestry receipts digest --period "18-25 September 2026"
```

Denied attempts are **counted, never credited**: their item counts and their
intended egress stay out of every total, and they are listed separately per actor.
A summary that overstates what happened is worse than no summary.

### HTML

```bash
attestry receipts html --out receipts.html
```

Self-contained: no scripts, no external assets, light and dark via
`prefers-color-scheme`. It survives being emailed, archived, or opened years
later. Denied receipts and flagged ones are colour-coded. All interpolated values
are HTML-escaped.

### Re-checking history

```bash
attestry receipts check
```

Re-evaluates every recorded access against the policy **as it stands now**. An
access appears here because a grant was later narrowed or expired, which is not
the same as it having been unauthorised at the time — and the output says so.
Exit 2 when anything is flagged.

## What this is not

A sandbox. Attestry records what your code tells it, and can refuse accesses that
go through the recorder. It cannot see an access that never called it.

That makes it a transparency and consent layer: valuable for showing a user what
their agents did, for catching a tool that quietly started reading more than it
declared, and for producing an audit trail somebody can verify. It is not an
enforcement boundary, and a document that implied otherwise would be doing the
same thing this subsystem exists to prevent.
