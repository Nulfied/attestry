"""Pillar three: receipts an agent's user can actually read.

When an agent touches mail, calendars, files or contacts, something should be
able to answer "what did it look at, and why?" in a sentence. Structured audit
logs technically answer it and practically do not, because reading one requires
knowing the schema.

::

    from attestry.receipts import Recorder, ConsentPolicy, describe_event

    recorder = Recorder(ledger, ConsentPolicy.load(ws.consent_path),
                        actor="agent:inbox-triage", enforce=True)

    with recorder.access("read", "email:gmail/INBOX",
                         purpose="draft daily priorities",
                         fields=["subject", "from"],
                         data_classes=["message_content"]) as event:
        event.items = len(fetch_inbox())

Which produces, on ``attestry receipts list``:

    On 25 Sep 2026 at 14:03 UTC, the inbox-triage agent read 42 messages in your
    Gmail inbox (subject and from only) in order to draft daily priorities. No
    data left your machine.
"""

from .model import ACTIONS, DATA_CLASSES, OUTCOMES, AccessEvent
from .policy import ConsentPolicy, Decision, Grant, Violation, example_policy
from .recorder import Recorder, RecordedAccess, event_from_schema
from .render import (
    describe_actor,
    describe_event,
    describe_resource,
    join_and,
    render_digest,
    render_html,
    render_receipt,
)

__all__ = [
    "AccessEvent",
    "ACTIONS",
    "OUTCOMES",
    "DATA_CLASSES",
    "ConsentPolicy",
    "Grant",
    "Decision",
    "Violation",
    "example_policy",
    "Recorder",
    "RecordedAccess",
    "event_from_schema",
    "describe_event",
    "describe_actor",
    "describe_resource",
    "render_receipt",
    "render_digest",
    "render_html",
    "join_and",
]
