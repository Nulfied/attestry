"""Consent receipts: the policy check, the recorder, and the English."""

from __future__ import annotations

import unittest

from attestry.receipts import (
    AccessEvent,
    ConsentPolicy,
    Grant,
    Recorder,
    describe_actor,
    describe_event,
    describe_resource,
    event_from_schema,
    example_policy,
    join_and,
    render_digest,
    render_html,
    render_receipt,
)
from attestry.schema import Consent, ToolSchema
from attestry.util.errors import PolicyViolation

from .support import WorkspaceCase


def read_event(**overrides) -> AccessEvent:
    fields = dict(
        actor="agent:inbox-triage",
        action="read",
        resource="email:gmail/INBOX",
        purpose="draft daily priorities",
        items=42,
        fields=["subject", "from"],
        data_classes=["message_content"],
    )
    fields.update(overrides)
    return AccessEvent(**fields)


class EventTests(unittest.TestCase):
    def test_unknown_action_and_outcome_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_event(action="telepathise")
        with self.assertRaises(ValueError):
            read_event(outcome="maybe")

    def test_scheme_and_write_classification(self) -> None:
        self.assertEqual(read_event().scheme, "email")
        self.assertFalse(read_event().is_write)
        for action in ("write", "update", "send", "delete", "share", "execute"):
            self.assertTrue(read_event(action=action).is_write, action)

    def test_round_trip(self) -> None:
        event = read_event(egress=["api.example.com"], selector="1-25 Sep")
        self.assertEqual(AccessEvent.from_dict(event.to_dict()).to_dict(), event.to_dict())

    def test_unknown_data_classes_are_detectable(self) -> None:
        self.assertEqual(read_event(data_classes=["telepathy"]).unknown_data_classes(),
                         ["telepathy"])

    def test_from_schema_inherits_the_declaration(self) -> None:
        tool = ToolSchema(
            "read_inbox", "d",
            consent=Consent(required=True, data_classes=["message_content"],
                            purpose="triage", egress=["api.example.com"]),
        )
        event = event_from_schema(tool, "agent:a", "read", "email:gmail/INBOX")
        self.assertEqual(event.purpose, "triage")
        self.assertEqual(event.data_classes, ["message_content"])
        self.assertEqual(event.egress, ["api.example.com"])
        self.assertEqual(event.tool, "read_inbox")

    def test_from_schema_overrides_win(self) -> None:
        tool = ToolSchema("t", "d", consent=Consent(purpose="declared"))
        event = event_from_schema(tool, "agent:a", "read", "x:y", purpose="actual")
        self.assertEqual(event.purpose, "actual")


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = example_policy()

    def test_a_granted_access_is_permitted(self) -> None:
        decision = self.policy.check(read_event())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.grant, "inbox-triage")

    def test_an_ungranted_action_is_refused(self) -> None:
        decision = self.policy.check(read_event(action="delete", purpose="cleanup"))
        self.assertFalse(decision.allowed)
        self.assertEqual([v.code for v in decision.violations], ["no-grant"])

    def test_an_ungranted_actor_is_refused(self) -> None:
        self.assertFalse(self.policy.check(read_event(actor="agent:rogue")).allowed)

    def test_a_resource_outside_the_pattern_is_refused(self) -> None:
        self.assertFalse(self.policy.check(read_event(resource="email:gmail/Sent")).allowed)

    def test_an_undeclared_purpose_is_refused(self) -> None:
        decision = self.policy.check(read_event(purpose="train a model"))
        self.assertFalse(decision.allowed)
        self.assertIn("purpose-undeclared", [v.code for v in decision.violations])

    def test_a_missing_purpose_is_refused_when_purposes_are_listed(self) -> None:
        decision = self.policy.check(read_event(purpose=""))
        self.assertIn("purpose-missing", [v.code for v in decision.violations])

    def test_an_undeclared_data_class_is_refused(self) -> None:
        decision = self.policy.check(read_event(data_classes=["message_content", "financial"]))
        self.assertIn("data-class-undeclared", [v.code for v in decision.violations])

    def test_egress_is_refused_when_none_is_granted(self) -> None:
        decision = self.policy.check(read_event(egress=["api.example.com"]))
        self.assertIn("egress-forbidden", [v.code for v in decision.violations])

    def test_egress_outside_the_allowed_list_is_refused(self) -> None:
        policy = ConsentPolicy([
            Grant("g", "agent:a", ["x:*"], ["read"], egress=["*.trusted.com"]),
        ])
        allowed = policy.check(AccessEvent("agent:a", "read", "x:y", egress=["api.trusted.com"]))
        self.assertTrue(allowed.allowed)
        blocked = policy.check(AccessEvent("agent:a", "read", "x:y", egress=["evil.com"]))
        self.assertIn("egress-undeclared", [v.code for v in blocked.violations])

    def test_volume_limit(self) -> None:
        decision = self.policy.check(read_event(items=5000))
        self.assertIn("volume-exceeded", [v.code for v in decision.violations])

    def test_expired_grant_is_refused(self) -> None:
        policy = ConsentPolicy([
            Grant("g", "agent:a", ["x:*"], ["read"], expires="2020-01-01T00:00:00Z"),
        ])
        decision = policy.check(AccessEvent("agent:a", "read", "x:y"))
        self.assertIn("expired", [v.code for v in decision.violations])

    def test_unparseable_expiry_is_treated_as_expired(self) -> None:
        policy = ConsentPolicy([Grant("g", "agent:a", ["x:*"], ["read"], expires="soon")])
        self.assertFalse(policy.check(AccessEvent("agent:a", "read", "x:y")).allowed)

    def test_default_allow_only_warns(self) -> None:
        policy = ConsentPolicy([], default_deny=False)
        decision = policy.check(read_event())
        self.assertTrue(decision.allowed)
        self.assertEqual([v.severity for v in decision.violations], ["warn"])

    def test_a_second_grant_can_still_permit_the_access(self) -> None:
        """One expired grant must not mask another that legitimately allows it."""
        policy = ConsentPolicy([
            Grant("old", "agent:a", ["x:*"], ["read"], expires="2020-01-01T00:00:00Z"),
            Grant("new", "agent:a", ["x:*"], ["read"]),
        ])
        decision = policy.check(AccessEvent("agent:a", "read", "x:y"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.grant, "new")

    def test_unknown_data_class_is_a_warning_not_a_refusal(self) -> None:
        policy = ConsentPolicy([Grant("g", "agent:a", ["x:*"], ["read"])])
        decision = policy.check(AccessEvent("agent:a", "read", "x:y", data_classes=["telepathy"]))
        self.assertTrue(decision.allowed)
        self.assertEqual([v.code for v in decision.warnings], ["data-class-unknown"])

    def test_policy_round_trip_through_a_file(self) -> None:
        import tempfile, os

        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "consent.json")
        example_policy().save(path)
        loaded = ConsentPolicy.load(path)
        self.assertEqual(len(loaded), len(example_policy()))
        self.assertTrue(loaded.check(read_event()).allowed)

    def test_missing_policy_file_loads_empty_and_denies(self) -> None:
        policy = ConsentPolicy.load("/nonexistent/consent.json")
        self.assertEqual(len(policy), 0)
        self.assertFalse(policy.check(read_event()).allowed)


class RenderTests(unittest.TestCase):
    def test_the_sentence_names_who_what_how_many_and_why(self) -> None:
        sentence = describe_event(read_event())
        for fragment in ("inbox-triage agent", "read", "42 messages",
                         "your Gmail inbox", "subject and from only",
                         "draft daily priorities"):
            self.assertIn(fragment, sentence)

    def test_egress_position_is_always_stated(self) -> None:
        self.assertIn("No data left your machine", describe_event(read_event()))
        self.assertIn("sent to api.example.com",
                      describe_event(read_event(egress=["api.example.com"])))

    def test_a_denied_access_never_claims_to_have_happened(self) -> None:
        sentence = describe_event(read_event(outcome="denied"))
        self.assertIn("refused", sentence)
        self.assertNotIn("No data left your machine", sentence)

    def test_singular_and_plural(self) -> None:
        self.assertIn("1 message", describe_event(read_event(items=1)))
        self.assertIn("2 messages", describe_event(read_event(items=2)))

    def test_unknown_resources_are_described_without_invention(self) -> None:
        self.assertEqual(describe_resource("widget:foo/bar"), "foo/bar (widget)")
        self.assertEqual(describe_resource("bare"), "bare")

    def test_known_resources_read_naturally(self) -> None:
        self.assertEqual(describe_resource("email:gmail/INBOX"), "your Gmail inbox")
        self.assertEqual(describe_resource("calendar:google/primary"),
                         "your primary Google calendar")
        self.assertEqual(describe_resource("db:postgres/users"),
                         "the users table in PostgreSQL")

    def test_actor_descriptions(self) -> None:
        self.assertEqual(describe_actor("agent:x"), "the x agent")
        self.assertEqual(describe_actor("tool:y"), "the y tool")
        self.assertEqual(describe_actor("plain"), "plain")

    def test_join_and(self) -> None:
        self.assertEqual(join_and([]), "")
        self.assertEqual(join_and(["a"]), "a")
        self.assertEqual(join_and(["a", "b"]), "a and b")
        self.assertEqual(join_and(["a", "b", "c"]), "a, b and c")

    def test_digest_never_credits_a_denied_attempt(self) -> None:
        events = [
            read_event(items=10),
            read_event(items=900, outcome="denied", egress=["api.example.com"]),
        ]
        text = render_digest(events, "Summary")
        self.assertIn("10 items in total", text)
        self.assertIn("No data left your machine", text)
        self.assertIn("1 attempt refused", text)

    def test_digest_handles_no_events(self) -> None:
        self.assertIn("nothing recorded", render_digest([], "Summary"))

    def test_html_is_self_contained_and_escapes_input(self) -> None:
        event = read_event(purpose="<script>alert(1)</script>")
        html = render_html([{"event": event, "decision": None, "flags": [], "seq": 1}])
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("http://", html.split("<style>")[0])
        self.assertIn("prefers-color-scheme", html)

    def test_receipt_block_includes_the_ledger_reference(self) -> None:
        self.assertIn("#7", render_receipt(read_event(), None, [], 7))


class RecorderTests(WorkspaceCase):
    def setUp(self) -> None:
        super().setUp()
        self.policy = example_policy()
        self.policy.save(self.workspace.consent_path)
        self.recorder = Recorder(self.ledger, self.policy, actor="agent:inbox-triage")

    def test_a_permitted_access_is_recorded_as_such(self) -> None:
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities") as event:
            event.items = 12
        record = self.recorder.history()[-1]
        self.assertEqual(record.event.outcome, "ok")
        self.assertEqual(record.event.items, 12)
        self.assertEqual(self.ledger.select(kind="receipt.access")[-1].seq, record.seq)

    def test_a_refused_access_is_recorded_as_denied(self) -> None:
        with self.recorder.access("delete", "email:gmail/INBOX", purpose="cleanup"):
            pass
        record = self.recorder.history()[-1]
        self.assertEqual(record.event.outcome, "denied")
        self.assertEqual(self.ledger.select(kind="receipt.denied")[-1].seq, record.seq)

    def test_enforcement_stops_the_body_from_running(self) -> None:
        recorder = Recorder(self.ledger, self.policy, actor="agent:rogue", enforce=True)
        ran = []
        with self.assertRaises(PolicyViolation):
            with recorder.access("delete", "email:gmail/INBOX", purpose="cleanup"):
                ran.append(True)
        self.assertEqual(ran, [])
        self.assertEqual(self.recorder.history()[-1].event.outcome, "denied")

    def test_an_exception_is_recorded_and_re_raised(self) -> None:
        with self.assertRaises(RuntimeError):
            with self.recorder.access("read", "email:gmail/INBOX",
                                      purpose="draft daily priorities"):
                raise RuntimeError("mailbox timed out")
        record = self.recorder.history()[-1]
        self.assertEqual(record.event.outcome, "error")
        self.assertIn("timed out", record.event.detail)

    def test_first_access_is_flagged(self) -> None:
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities"):
            pass
        self.assertTrue(any("first recorded access" in f
                            for f in self.recorder.history()[-1].flags))

    def test_a_first_write_after_only_reads_is_flagged(self) -> None:
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities"):
            pass
        with self.recorder.access("send", "email:gmail/Sent", purpose="reply"):
            pass
        self.assertTrue(any("only ever read before" in f
                            for f in self.recorder.history()[-1].flags))

    def test_a_volume_spike_is_flagged(self) -> None:
        for count in (10, 12):
            with self.recorder.access("read", "email:gmail/INBOX",
                                      purpose="draft daily priorities") as event:
                event.items = count
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities") as event:
            event.items = 500
        self.assertTrue(any("three times" in f for f in self.recorder.history()[-1].flags))

    def test_a_new_egress_destination_is_flagged(self) -> None:
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities"):
            pass
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities",
                                  egress=["api.example.com"]):
            pass
        self.assertTrue(any("first time" in f for f in self.recorder.history()[-1].flags))

    def test_history_filters(self) -> None:
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities"):
            pass
        other = Recorder(self.ledger, self.policy, actor="agent:scheduler")
        with other.access("read", "calendar:google/primary", purpose="schedule meetings"):
            pass
        self.assertEqual(len(self.recorder.history(actor="agent:scheduler")), 1)
        self.assertEqual(len(self.recorder.history(resource="calendar")), 1)
        self.assertEqual(len(self.recorder.history(include_denied=False)), 2)

    def test_receipts_survive_a_ledger_verification(self) -> None:
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities") as event:
            event.items = 3
        self.assertTrue(self.ledger.verify().ok)

    def test_summary_counts(self) -> None:
        with self.recorder.access("read", "email:gmail/INBOX",
                                  purpose="draft daily priorities"):
            pass
        with self.recorder.access("delete", "email:gmail/INBOX", purpose="cleanup"):
            pass
        counts = self.recorder.summary_counts()
        self.assertEqual(counts["receipts"], 2)
        self.assertEqual(counts["denied"], 1)


if __name__ == "__main__":
    unittest.main()
