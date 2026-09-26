"""The neutral tool schema: emitters, parsers, round trips and diffs."""

from __future__ import annotations

import ast
import json
import unittest
from typing import List, Literal, Optional

from attestry.schema import (
    CODE_TARGETS,
    TARGETS,
    Consent,
    Effects,
    Param,
    SchemaStore,
    ToolSchema,
    detect_format,
    diff,
    emit,
    from_any,
    from_callable,
    render,
    sniff,
    worst_severity,
)
from attestry.util.errors import SchemaError

from .support import WorkspaceCase


def sample_tool() -> ToolSchema:
    return ToolSchema(
        name="search_docs",
        title="Search documentation",
        description="Search the product documentation and return matching passages.",
        params=[
            Param("query", "string", "What to search for.", required=True, min_length=1),
            Param("limit", "integer", "How many results.", default=10, minimum=1, maximum=50),
            Param("mode", "enum", "Ranking strategy.",
                  values=["semantic", "lexical"], default="semantic"),
            Param("tags", "array", "Restrict to these tags.",
                  items=Param("item", "string", "a tag")),
        ],
        effects=Effects(reads=["docs"], network=True),
    )


class ValidationTests(unittest.TestCase):
    def test_a_good_tool_validates_clean(self) -> None:
        self.assertEqual(sample_tool().validate(), [])

    def test_bad_name_is_reported(self) -> None:
        problems = ToolSchema(name="has spaces", description="x").validate()
        self.assertTrue(any("name" in p for p in problems))

    def test_missing_description_is_reported(self) -> None:
        self.assertTrue(any("description" in p for p in ToolSchema(name="ok").validate()))

    def test_enum_without_values_is_reported(self) -> None:
        tool = ToolSchema("t", "d", [Param("m", "enum", "Mode.")])
        self.assertTrue(any("lists no values" in p for p in tool.validate()))

    def test_array_without_items_is_reported(self) -> None:
        tool = ToolSchema("t", "d", [Param("a", "array", "Things.")])
        self.assertTrue(any("does not say what it contains" in p for p in tool.validate()))

    def test_required_with_default_is_contradictory(self) -> None:
        tool = ToolSchema("t", "d", [Param("a", "string", "A.", required=True, default="x")])
        self.assertTrue(any("required but also has a default" in p for p in tool.validate()))

    def test_destructive_and_idempotent_is_flagged(self) -> None:
        tool = ToolSchema("t", "d", effects=Effects(destructive=True, idempotent=True))
        self.assertTrue(any("destructive and idempotent" in p for p in tool.validate()))

    def test_unknown_consent_data_class_is_flagged(self) -> None:
        tool = ToolSchema("t", "d", consent=Consent(data_classes=["telepathy"]))
        self.assertTrue(any("vocabulary" in p for p in tool.validate()))

    def test_require_valid_raises(self) -> None:
        with self.assertRaises(SchemaError):
            ToolSchema(name="bad name").require_valid()

    def test_unknown_type_is_rejected_at_construction(self) -> None:
        with self.assertRaises(SchemaError):
            Param("a", "stringy", "A.")

    def test_digest_ignores_prose_but_not_shape(self) -> None:
        one, two = sample_tool(), sample_tool()
        two.description = "Completely different wording."
        two.params[0].description = "Also reworded."
        self.assertEqual(one.digest(), two.digest())
        two.params[0].required = False
        self.assertNotEqual(one.digest(), two.digest())

    def test_unsupported_nts_version_is_refused(self) -> None:
        data = sample_tool().to_dict()
        data["nts"] = "99"
        with self.assertRaises(SchemaError):
            ToolSchema.from_dict(data)


class EmitTests(unittest.TestCase):
    def test_every_target_produces_something_usable(self) -> None:
        tool = sample_tool()
        for target in TARGETS:
            text, _notes = render(tool, target)
            self.assertTrue(text.strip(), target)
            if target in CODE_TARGETS:
                ast.parse(text)  # raises SyntaxError if the generated code is broken
            else:
                json.loads(text)

    def test_unknown_target_is_rejected(self) -> None:
        with self.assertRaises(KeyError):
            emit(sample_tool(), "nonesuch")

    def test_mcp_carries_effects_as_hints(self) -> None:
        payload, _ = emit(sample_tool(), "mcp")
        self.assertTrue(payload["annotations"]["readOnlyHint"])
        self.assertTrue(payload["annotations"]["openWorldHint"])

    def test_openai_strict_makes_everything_required_and_nullable(self) -> None:
        payload, notes = emit(sample_tool(), "openai", strict=True)
        schema = payload["function"]["parameters"]
        self.assertEqual(set(schema["required"]), {"query", "limit", "mode", "tags"})
        self.assertIn("null", schema["properties"]["limit"]["type"])
        self.assertNotIn("null", str(schema["properties"]["query"]["type"]))
        self.assertTrue(notes)

    def test_openai_responses_style_is_flat(self) -> None:
        payload, _ = emit(sample_tool(), "openai", style="responses")
        self.assertIn("name", payload)
        self.assertNotIn("function", payload)

    def test_gemini_strips_keys_it_rejects(self) -> None:
        payload, _ = emit(sample_tool(), "gemini")
        self.assertNotIn("additionalProperties", json.dumps(payload))

    def test_generated_code_mentions_declared_effects(self) -> None:
        tool = sample_tool()
        tool.effects.destructive = True
        tool.effects.idempotent = False
        for target in ("langchain", "crewai", "autogen"):
            source, _ = render(tool, target)
            self.assertIn("destroy data", source)

    def test_autogen_puts_required_parameters_first(self) -> None:
        tool = ToolSchema(
            "t", "d",
            [Param("opt", "string", "Optional.", default="x"),
             Param("req", "string", "Required.", required=True)],
        )
        source, notes = render(tool, "autogen")
        self.assertLess(source.index("req:"), source.index("opt:"))
        self.assertTrue(any("reordered" in note for note in notes))
        ast.parse(source)

    def test_parameter_names_that_are_not_identifiers_are_reported(self) -> None:
        tool = ToolSchema("t", "d", [Param("has-dash", "string", "A.", required=True)])
        source, notes = render(tool, "langchain")
        ast.parse(source)
        self.assertTrue(any("identifier" in note for note in notes))


class IngestTests(unittest.TestCase):
    def test_detect_format_distinguishes_the_shapes(self) -> None:
        cases = {
            "mcp": {"name": "t", "inputSchema": {"type": "object", "properties": {}}},
            "anthropic": {"name": "t", "input_schema": {"type": "object", "properties": {}}},
            "openai": {"type": "function", "function": {"name": "t", "parameters": {}}},
            "json-schema": {"type": "object", "properties": {"a": {"type": "string"}}},
            "nts": {"nts": "1", "name": "t"},
        }
        for expected, payload in cases.items():
            self.assertEqual(detect_format(payload), expected)

    def test_unrecognised_payload_is_refused(self) -> None:
        with self.assertRaises(SchemaError):
            sniff({"something": "else"})

    def test_round_trip_preserves_the_interface(self) -> None:
        tool = sample_tool()
        for target in ("mcp", "openai", "anthropic"):
            payload, _ = emit(tool, target)
            recovered, detected = sniff(payload)
            self.assertEqual(detected, target)
            self.assertEqual(
                [(p.name, p.type, p.required) for p in recovered.params],
                [(p.name, p.type, p.required) for p in tool.params],
                target,
            )

    def test_strict_round_trip_recovers_optionality(self) -> None:
        payload, _ = emit(sample_tool(), "openai", strict=True)
        recovered, _ = sniff(payload)
        self.assertEqual([p.required for p in recovered.params], [True, False, False, False])

    def test_mcp_hints_become_effects(self) -> None:
        payload = {
            "name": "wipe", "description": "d",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": False, "destructiveHint": True,
                            "openWorldHint": True, "idempotentHint": False},
        }
        tool, _ = sniff(payload)
        self.assertTrue(tool.effects.destructive)
        self.assertTrue(tool.effects.network)
        self.assertFalse(tool.effects.idempotent)
        self.assertEqual(tool.effects.writes, ["unspecified"])

    def test_from_any_unwraps_containers_and_lists(self) -> None:
        one = {"name": "a", "input_schema": {"type": "object", "properties": {}}}
        two = {"name": "b", "input_schema": {"type": "object", "properties": {}}}
        self.assertEqual(len(from_any({"tools": [one, two]})), 2)
        self.assertEqual(len(from_any([one, two])), 2)
        self.assertEqual(len(from_any(one)), 1)

    def test_nested_objects_survive_a_json_round_trip(self) -> None:
        tool = ToolSchema(
            "t", "d",
            [Param("filters", "object", "Filters.", required=True,
                   properties=[Param("since", "string", "From when.", required=True),
                               Param("kind", "string", "Kind.")])],
        )
        payload, _ = emit(tool, "mcp")
        recovered, _ = sniff(payload)
        nested = recovered.param("filters")
        self.assertEqual([p.name for p in nested.properties], ["since", "kind"])
        self.assertEqual([p.required for p in nested.properties], [True, False])


class IntrospectTests(unittest.TestCase):
    def test_signature_and_google_docstring(self) -> None:
        def fetch(user_id: str, fields: Optional[List[str]] = None, loud: bool = False) -> dict:
            """Load one user.

            Args:
                user_id: The account id.
                fields: Which fields to include.
                loud: Log what happened.
            """

        tool = from_callable(fetch)
        self.assertEqual(tool.name, "fetch")
        self.assertEqual(tool.description, "Load one user.")
        self.assertEqual(
            [(p.name, p.type, p.required) for p in tool.params],
            [("user_id", "string", True), ("fields", "array", False), ("loud", "boolean", False)],
        )
        self.assertEqual(tool.param("user_id").description, "The account id.")
        self.assertEqual(tool.returns.type, "object")

    def test_rest_style_docstring(self) -> None:
        def go(target: str) -> None:
            """Do a thing.

            :param target: Where to go.
            """

        self.assertEqual(from_callable(go).param("target").description, "Where to go.")

    def test_literal_becomes_an_enum(self) -> None:
        def pick(mode: Literal["fast", "slow"] = "fast") -> str:
            """Pick a mode.

            Args:
                mode: Which mode.
            """

        param = from_callable(pick).param("mode")
        self.assertEqual(param.type, "enum")
        self.assertEqual(param.values, ["fast", "slow"])

    def test_varargs_are_skipped(self) -> None:
        def go(a: str, *rest: str, **kwargs: str) -> None:
            """Go."""

        self.assertEqual([p.name for p in from_callable(go).params], ["a"])


class DiffTests(unittest.TestCase):
    def test_no_changes(self) -> None:
        self.assertEqual(diff(sample_tool(), sample_tool()), [])

    def test_removing_a_parameter_is_breaking(self) -> None:
        new = sample_tool()
        new.params = [p for p in new.params if p.name != "limit"]
        changes = diff(sample_tool(), new)
        self.assertEqual(worst_severity(changes), "breaking")

    def test_new_required_parameter_is_breaking(self) -> None:
        new = sample_tool()
        new.params.append(Param("locale", "string", "Language.", required=True))
        self.assertEqual(worst_severity(diff(sample_tool(), new)), "breaking")

    def test_new_optional_parameter_is_only_behavioural(self) -> None:
        new = sample_tool()
        new.params.append(Param("locale", "string", "Language.", default="en"))
        self.assertEqual(worst_severity(diff(sample_tool(), new)), "behaviour")

    def test_withdrawing_an_enum_value_is_breaking_adding_is_not(self) -> None:
        narrower = sample_tool()
        narrower.param("mode").values = ["semantic"]
        self.assertEqual(worst_severity(diff(sample_tool(), narrower)), "breaking")
        wider = sample_tool()
        wider.param("mode").values = ["semantic", "lexical", "hybrid"]
        self.assertEqual(worst_severity(diff(sample_tool(), wider)), "behaviour")

    def test_tightening_a_bound_is_breaking_loosening_is_not(self) -> None:
        tighter = sample_tool()
        tighter.param("limit").maximum = 20
        self.assertEqual(worst_severity(diff(sample_tool(), tighter)), "breaking")
        looser = sample_tool()
        looser.param("limit").maximum = 100
        self.assertEqual(worst_severity(diff(sample_tool(), looser)), "behaviour")

    def test_gaining_side_effects_is_an_escalation(self) -> None:
        for mutate in (
            lambda t: t.effects.writes.append("billing"),
            lambda t: setattr(t.effects, "destructive", True),
            lambda t: t.consent.data_classes.append("financial"),
            lambda t: t.consent.egress.append("api.example.com"),
            lambda t: setattr(t.consent, "required", True),
        ):
            new = sample_tool()
            mutate(new)
            self.assertEqual(worst_severity(diff(sample_tool(), new)), "escalation")

    def test_escalation_outranks_breaking_in_the_ordering(self) -> None:
        new = sample_tool()
        new.effects.destructive = True
        new.params = [p for p in new.params if p.name != "limit"]
        changes = diff(sample_tool(), new)
        self.assertEqual(changes[0].severity, "escalation")

    def test_rewording_is_only_cosmetic(self) -> None:
        new = sample_tool()
        new.description = "Different words, same interface."
        self.assertEqual(worst_severity(diff(sample_tool(), new)), "cosmetic")


class StoreTests(WorkspaceCase):
    def test_save_load_and_list(self) -> None:
        store = SchemaStore(self.workspace.schemas_dir, self.ledger)
        store.save(sample_tool())
        self.assertEqual(store.names(), ["search_docs"])
        self.assertEqual(store.load("search_docs").name, "search_docs")

    def test_missing_schema_raises_a_helpful_error(self) -> None:
        store = SchemaStore(self.workspace.schemas_dir, self.ledger)
        with self.assertRaises(SchemaError):
            store.load("nope")

    def test_first_register_records_no_changes(self) -> None:
        store = SchemaStore(self.workspace.schemas_dir, self.ledger)
        changes, severity = store.register(sample_tool())
        self.assertEqual(changes, [])
        self.assertIsNone(severity)
        self.assertEqual(len(self.ledger.select(kind="schema.registered")), 1)

    def test_rewording_does_not_create_a_change_entry(self) -> None:
        store = SchemaStore(self.workspace.schemas_dir, self.ledger)
        store.register(sample_tool())
        reworded = sample_tool()
        reworded.description = "Totally new prose."
        changes, _ = store.register(reworded)
        self.assertEqual(changes, [])
        self.assertEqual(len(self.ledger.select(kind="schema.changed")), 0)

    def test_escalation_is_recorded_with_the_diff(self) -> None:
        store = SchemaStore(self.workspace.schemas_dir, self.ledger)
        store.register(sample_tool())
        escalated = sample_tool()
        escalated.effects.writes.append("billing")
        changes, severity = store.register(escalated)
        self.assertEqual(severity, "escalation")
        entries = self.ledger.select(kind="schema.changed")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].body["severity"], "escalation")
        self.assertTrue(entries[0].body["changes"])

    def test_history_lists_every_recorded_state(self) -> None:
        store = SchemaStore(self.workspace.schemas_dir, self.ledger)
        store.register(sample_tool())
        changed = sample_tool()
        changed.param("limit").maximum = 20
        store.register(changed)
        history = store.history("search_docs")
        self.assertEqual([row["kind"] for row in history],
                         ["schema.registered", "schema.changed"])


if __name__ == "__main__":
    unittest.main()
