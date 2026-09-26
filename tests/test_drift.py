"""Drift detection: expectation checks, movement against a baseline, recording."""

from __future__ import annotations

import unittest

from attestry.drift import (
    Case,
    Suite,
    case_timeline,
    check,
    drift_between,
    example_suite,
    get_provider,
    history,
    load_baseline,
    record_baseline,
    record_run,
    run_suite,
    save_baseline,
    save_run,
    similarity,
)
from attestry.drift.providers import ProviderError, Provider, Response

from .support import WorkspaceCase


class ExpectationTests(unittest.TestCase):
    def test_exact(self) -> None:
        self.assertTrue(check("abc", {"mode": "exact", "value": "abc"}).passed)
        self.assertFalse(check("abcd", {"mode": "exact", "value": "abc"}).passed)

    def test_normalized_ignores_case_and_spacing(self) -> None:
        expect = {"mode": "normalized", "value": "Hello  World"}
        self.assertTrue(check("hello world", expect).passed)
        self.assertFalse(check("hello there", expect).passed)

    def test_contains_all_reports_what_is_missing(self) -> None:
        verdict = check("refunds take 14 days", {"mode": "contains_all",
                                                 "value": ["refund", "30 days"]})
        self.assertFalse(verdict.passed)
        self.assertIn("30 days", verdict.detail)
        self.assertAlmostEqual(verdict.score, 0.5)

    def test_contains_any(self) -> None:
        expect = {"mode": "contains_any", "value": ["alpha", "beta"]}
        self.assertTrue(check("this mentions beta", expect).passed)
        self.assertFalse(check("nothing here", expect).passed)

    def test_never_contains_catches_a_banned_phrase(self) -> None:
        expect = {"mode": "never_contains", "value": ["sorry for the inconvenience"]}
        self.assertTrue(check("we fixed it", expect).passed)
        self.assertFalse(check("Sorry for the inconvenience!", expect).passed)

    def test_regex_and_bad_regex(self) -> None:
        self.assertTrue(check("order 12345", {"mode": "regex", "value": [r"order \d+"]}).passed)
        verdict = check("x", {"mode": "regex", "value": ["("]})
        self.assertFalse(verdict.passed)
        self.assertIn("bad regex", verdict.detail)

    def test_json_shape_checks_keys_and_types(self) -> None:
        expect = {"mode": "json_shape",
                  "value": {"id": "string", "count": "integer", "tags": ["string"]}}
        self.assertTrue(check('{"id":"a","count":2,"tags":["x"],"extra":1}', expect).passed)
        self.assertFalse(check('{"id":"a","count":"two","tags":[]}', expect).passed)

    def test_json_shape_unwraps_a_fenced_block(self) -> None:
        expect = {"mode": "json_shape", "value": {"ok": "boolean"}}
        self.assertTrue(check('```json\n{"ok": true}\n```', expect).passed)

    def test_json_shape_rejects_non_json(self) -> None:
        verdict = check("not json at all", {"mode": "json_shape", "value": {"a": "string"}})
        self.assertFalse(verdict.passed)
        self.assertIn("not valid JSON", verdict.detail)

    def test_json_shape_rejects_boolean_as_integer(self) -> None:
        self.assertFalse(check('{"n": true}', {"mode": "json_shape",
                                               "value": {"n": "integer"}}).passed)

    def test_numeric_with_tolerance(self) -> None:
        expect = {"mode": "numeric", "value": 42, "tolerance": 1}
        self.assertTrue(check("the answer is 42.5", expect).passed)
        self.assertFalse(check("the answer is 50", expect).passed)
        self.assertFalse(check("no numbers", expect).passed)

    def test_similarity_threshold(self) -> None:
        expect = {"mode": "similarity", "value": "the quick brown fox", "threshold": 0.9}
        self.assertTrue(check("the quick brown fox", expect).passed)
        self.assertFalse(check("a totally different sentence", expect).passed)

    def test_no_expectation_passes(self) -> None:
        self.assertTrue(check("anything", None).passed)
        self.assertTrue(check("anything", {"mode": "none"}).passed)

    def test_unknown_mode_is_reported(self) -> None:
        verdict = check("x", {"mode": "vibes", "value": "y"})
        self.assertFalse(verdict.passed)
        self.assertIn("unknown expectation mode", verdict.detail)


class SimilarityTests(unittest.TestCase):
    def test_identical_is_one_and_disjoint_is_low(self) -> None:
        self.assertEqual(similarity("abc", "abc"), 1.0)
        self.assertLess(similarity("alpha beta", "zulu yankee"), 0.4)

    def test_empty_inputs(self) -> None:
        self.assertEqual(similarity("", ""), 1.0)
        self.assertEqual(similarity("a", ""), 0.0)

    def test_reordering_costs_less_than_replacing(self) -> None:
        original = "the cat sat on the mat"
        reordered = "on the mat sat the cat"
        replaced = "a dog barked in the yard"
        self.assertGreater(similarity(original, reordered), similarity(original, replaced))


class MovementTests(unittest.TestCase):
    def test_no_baseline_is_new(self) -> None:
        self.assertEqual(drift_between(None, "anything").mode, "new")

    def test_identical_is_stable(self) -> None:
        self.assertEqual(drift_between("same", "same").mode, "stable")

    def test_small_change_is_minor(self) -> None:
        verdict = drift_between("the answer is 42.", "The answer is 42.", threshold=0.8)
        self.assertEqual(verdict.mode, "minor")
        self.assertTrue(verdict.passed)

    def test_large_change_is_drift(self) -> None:
        verdict = drift_between("the answer is 42", "I am unable to help with that")
        self.assertEqual(verdict.mode, "drift")
        self.assertFalse(verdict.passed)


class SuiteTests(unittest.TestCase):
    def test_example_suite_is_valid(self) -> None:
        self.assertEqual(example_suite("x").validate(), [])

    def test_duplicate_case_ids_are_reported(self) -> None:
        suite = Suite("s", cases=[Case("a", "p"), Case("a", "q")])
        self.assertTrue(any("duplicate" in p for p in suite.validate()))

    def test_nonzero_temperature_is_reported(self) -> None:
        suite = Suite("s", params={"temperature": 0.7}, cases=[Case("a", "p")])
        self.assertTrue(any("temperature" in p for p in suite.validate()))

    def test_unknown_mode_is_reported(self) -> None:
        suite = Suite("s", cases=[Case("a", "p", expect={"mode": "vibes", "value": 1})])
        self.assertTrue(any("unknown mode" in p for p in suite.validate()))

    def test_mode_without_a_value_is_reported(self) -> None:
        suite = Suite("s", cases=[Case("a", "p", expect={"mode": "exact"})])
        self.assertTrue(any("no value" in p for p in suite.validate()))

    def test_round_trip_through_json(self) -> None:
        suite = example_suite("x")
        self.assertEqual(Suite.from_dict(suite.to_dict()).to_dict(), suite.to_dict())

    def test_case_requires_an_id_and_prompt(self) -> None:
        from attestry.util.errors import AttestryError

        with self.assertRaises(AttestryError):
            Case.from_dict({"prompt": "p"})
        with self.assertRaises(AttestryError):
            Case.from_dict({"id": "a"})


class BrokenProvider(Provider):
    name = "broken"

    def complete(self, prompt, system="", params=None):
        raise ProviderError("the model is on fire")


class ChangingProvider(Provider):
    """Serves one answer, then a different one, reporting a changed model name."""

    name = "changing"

    def __init__(self, model, texts, served):
        super().__init__(model)
        self.texts = list(texts)
        self.served = served

    def complete(self, prompt, system="", params=None):
        return Response(text=self.texts.pop(0), model=self.served)


class RunnerTests(WorkspaceCase):
    def suite(self) -> Suite:
        return Suite(
            name="s",
            provider="echo",
            model="demo",
            cases=[Case("one", "first prompt", expect={"mode": "contains_all",
                                                       "value": ["Answer"]})],
        )

    def test_first_run_is_ok_and_has_no_baseline(self) -> None:
        run = run_suite(self.suite(), get_provider("echo", "demo", variant="a"))
        self.assertEqual(run.status, "ok")
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(run.outcomes[0].movement.mode, "new")

    def test_stable_when_nothing_changes(self) -> None:
        suite = self.suite()
        first = run_suite(suite, get_provider("echo", "demo", variant="a"))
        save_baseline(self.workspace.baselines_dir, suite.name, first)
        baseline = load_baseline(self.workspace.baselines_dir, suite.name)
        again = run_suite(suite, get_provider("echo", "demo", variant="a"), baseline=baseline)
        self.assertEqual(again.status, "ok")
        self.assertEqual(again.outcomes[0].movement.mode, "stable")

    def test_drift_when_behaviour_moves(self) -> None:
        suite = self.suite()
        first = run_suite(suite, get_provider("echo", "demo", variant="a"))
        save_baseline(self.workspace.baselines_dir, suite.name, first)
        baseline = load_baseline(self.workspace.baselines_dir, suite.name)
        moved = run_suite(suite, get_provider("echo", "demo", variant="b"), baseline=baseline)
        self.assertEqual(moved.status, "drift")
        self.assertEqual(moved.exit_code, 1)

    def test_expectation_failure_outranks_drift(self) -> None:
        suite = Suite(
            name="s", cases=[Case("one", "p", expect={"mode": "contains_all",
                                                      "value": ["impossible phrase"]})],
        )
        run = run_suite(suite, get_provider("echo", "demo", variant="a"))
        self.assertEqual(run.status, "fail")
        self.assertEqual(run.exit_code, 2)

    def test_provider_error_becomes_an_error_outcome(self) -> None:
        run = run_suite(self.suite(), BrokenProvider("x"))
        self.assertEqual(run.status, "error")
        self.assertEqual(run.exit_code, 3)
        self.assertIn("on fire", run.outcomes[0].error)

    def test_skipped_cases_are_not_run(self) -> None:
        suite = Suite("s", cases=[Case("a", "p", skip=True), Case("b", "p")])
        run = run_suite(suite, get_provider("echo", "demo"))
        self.assertEqual(run.outcomes[0].status, "skipped")
        self.assertEqual(run.outcomes[1].status, "ok")

    def test_only_filters_cases(self) -> None:
        suite = Suite("s", cases=[Case("a", "p"), Case("b", "p")])
        run = run_suite(suite, get_provider("echo", "demo"), only=["b"])
        self.assertEqual(run.outcomes[0].status, "skipped")
        self.assertEqual(run.outcomes[1].status, "ok")

    def test_errors_are_never_written_into_a_baseline(self) -> None:
        """An outage must not silently become the reference behaviour."""
        run = run_suite(self.suite(), BrokenProvider("x"))
        save_baseline(self.workspace.baselines_dir, "s", run)
        self.assertEqual(load_baseline(self.workspace.baselines_dir, "s"), {})

    def test_served_model_change_is_reported_against_the_baseline(self) -> None:
        suite = Suite("s", model="alias", cases=[Case("one", "p")])
        first = run_suite(suite, ChangingProvider("alias", ["answer one"], "alias-2026-01-01"))
        save_baseline(self.workspace.baselines_dir, "s", first)
        baseline = load_baseline(self.workspace.baselines_dir, "s")
        second = run_suite(
            suite,
            ChangingProvider("alias", ["answer two"], "alias-2026-06-01"),
            baseline=baseline,
        )
        self.assertTrue(second.identity_warnings)
        self.assertIn("alias-2026-01-01", second.identity_warnings[0])
        self.assertIn("alias-2026-06-01", second.identity_warnings[0])

    def test_a_pinned_snapshot_name_is_not_reported_as_a_change(self) -> None:
        suite = Suite("s", model="alias", cases=[Case("one", "p")])
        first = run_suite(suite, ChangingProvider("alias", ["same"], "alias-2026-01-01"))
        save_baseline(self.workspace.baselines_dir, "s", first)
        baseline = load_baseline(self.workspace.baselines_dir, "s")
        second = run_suite(
            suite, ChangingProvider("alias", ["same"], "alias-2026-01-01"), baseline=baseline
        )
        self.assertEqual(second.identity_warnings, [])

    def test_ledger_records_digests_but_never_the_output(self) -> None:
        run = run_suite(self.suite(), get_provider("echo", "demo", variant="a"))
        record_run(self.ledger, run)
        entry = self.ledger.select(kind="drift.run")[0]
        blob = str(entry.body)
        self.assertIn("digest", blob)
        self.assertNotIn(run.outcomes[0].output, blob)

    def test_history_and_case_timeline(self) -> None:
        suite = self.suite()
        first = run_suite(suite, get_provider("echo", "demo", variant="a"))
        record_run(self.ledger, first)
        record_baseline(self.ledger, first)
        save_baseline(self.workspace.baselines_dir, suite.name, first)
        baseline = load_baseline(self.workspace.baselines_dir, suite.name)
        second = run_suite(suite, get_provider("echo", "demo", variant="b"), baseline=baseline)
        record_run(self.ledger, second)

        rows = history(self.ledger, "s")
        self.assertEqual([r["status"] for r in rows], ["ok", "drift"])
        timeline = case_timeline(self.ledger, "s", "one")
        self.assertEqual(len(timeline), 2)
        self.assertNotEqual(timeline[0]["digest"], timeline[1]["digest"])

    def test_run_file_keeps_the_outputs_locally(self) -> None:
        run = run_suite(self.suite(), get_provider("echo", "demo", variant="a"))
        path = save_run(self.workspace.runs_dir, run)
        with open(path, "r", encoding="utf-8") as handle:
            self.assertIn("Answer", handle.read())

    def test_markdown_report_renders(self) -> None:
        run = run_suite(self.suite(), get_provider("echo", "demo", variant="a"))
        self.assertIn("| case |", run.markdown())

    def test_unknown_provider_is_rejected(self) -> None:
        with self.assertRaises(ProviderError):
            get_provider("telepathy", "x")


if __name__ == "__main__":
    unittest.main()
