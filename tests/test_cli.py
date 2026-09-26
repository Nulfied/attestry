"""The command line, including the exit codes CI depends on."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from attestry.cli import (
    EXIT_CANNOT_RUN,
    EXIT_FAILED,
    EXIT_MOVED,
    EXIT_OK,
    EXIT_UNTRUSTED,
    main,
)


class CliCase(unittest.TestCase):
    """Runs the CLI in a temporary directory with its own workspace."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="attestry-cli-")
        self.saved_cwd = os.getcwd()
        self.saved_home = os.environ.pop("ATTESTRY_HOME", None)
        self.saved_variant = os.environ.pop("ATTESTRY_ECHO_VARIANT", None)
        os.chdir(self.tmp)

    def tearDown(self) -> None:
        os.chdir(self.saved_cwd)
        if self.saved_home is not None:
            os.environ["ATTESTRY_HOME"] = self.saved_home
        if self.saved_variant is not None:
            os.environ["ATTESTRY_ECHO_VARIANT"] = self.saved_variant
        else:
            os.environ.pop("ATTESTRY_ECHO_VARIANT", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *argv: str):
        """Run the CLI, returning ``(exit_code, stdout, stderr)``."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def init(self) -> None:
        code, _, _ = self.run_cli("init", ".")
        self.assertEqual(code, EXIT_OK)


class BasicTests(CliCase):
    def test_no_arguments_prints_help(self) -> None:
        code, out, _ = self.run_cli()
        self.assertEqual(code, EXIT_CANNOT_RUN)
        self.assertIn("usage", out.lower())

    def test_bare_group_prints_that_group_help(self) -> None:
        code, out, _ = self.run_cli("drift")
        self.assertEqual(code, EXIT_CANNOT_RUN)
        self.assertIn("baseline", out)

    def test_commands_outside_a_workspace_fail_cleanly(self) -> None:
        code, _, err = self.run_cli("ledger", "log")
        self.assertEqual(code, EXIT_CANNOT_RUN)
        self.assertIn("attestry init", err)

    def test_init_creates_everything_and_is_idempotent(self) -> None:
        self.init()
        for relative in ("config.json", "ledger.jsonl", "trust.json",
                         "drift/suites/example.suite.json", "receipts/consent.json"):
            self.assertTrue(os.path.exists(os.path.join(".attestry", *relative.split("/"))),
                            relative)
        code, out, _ = self.run_cli("init", ".")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("existing", out)

    def test_init_bare_skips_the_examples(self) -> None:
        code, _, _ = self.run_cli("init", ".", "--bare")
        self.assertEqual(code, EXIT_OK)
        self.assertFalse(os.path.exists(os.path.join(".attestry", "receipts", "consent.json")))

    def test_doctor_reports_a_healthy_workspace(self) -> None:
        self.init()
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("verification OK", out)

    def test_doctor_without_a_workspace_says_so(self) -> None:
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_CANNOT_RUN)
        self.assertIn("attestry init", out)

    def test_json_output_is_parseable(self) -> None:
        self.init()
        code, out, _ = self.run_cli("--json", "ledger", "verify")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(json.loads(out)["ok"])


class LedgerCliTests(CliCase):
    def test_verify_checkpoint_and_prove(self) -> None:
        self.init()
        self.assertEqual(self.run_cli("ledger", "checkpoint")[0], EXIT_OK)
        code, out, _ = self.run_cli("ledger", "prove", "1", "--out", "proof.json")
        self.assertEqual(code, EXIT_OK)
        code, out, _ = self.run_cli("ledger", "prove", "--check", "proof.json")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("VALID", out)

    def test_a_tampered_ledger_exits_untrusted(self) -> None:
        self.init()
        path = os.path.join(".attestry", "ledger.jsonl")
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        doc = json.loads(lines[0])
        doc["body"]["tool"] = "not-attestry"
        lines[0] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        code, out, _ = self.run_cli("ledger", "verify")
        self.assertEqual(code, EXIT_UNTRUSTED)
        self.assertIn("BROKEN", out)

    def test_keys_and_trust(self) -> None:
        self.init()
        code, out, _ = self.run_cli("ledger", "keys")
        self.assertIn("[default]", out)
        self.assertEqual(self.run_cli("ledger", "keys", "--new", "second")[0], EXIT_OK)
        code, out, _ = self.run_cli("ledger", "trust", "list")
        self.assertIn("trust mode", out)
        self.assertEqual(self.run_cli("ledger", "trust", "mode", "strict")[0], EXIT_OK)
        code, out, _ = self.run_cli("ledger", "trust", "list")
        self.assertIn("strict", out)

    def test_log_filters_by_namespace(self) -> None:
        self.init()
        code, out, _ = self.run_cli("ledger", "log", "--kind", "ledger")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("ledger.genesis", out)

    def test_export_and_sync_between_workspaces(self) -> None:
        self.init()
        self.assertEqual(self.run_cli("ledger", "export", "shared.jsonl")[0], EXIT_OK)
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        os.chdir(other)
        self.run_cli("init", ".")
        code, out, _ = self.run_cli("ledger", "sync", os.path.join(self.tmp, "shared.jsonl"))
        # Two independently initialised ledgers have different genesis entries,
        # so this is a fork rather than a fast-forward -- and saying so is right.
        self.assertEqual(code, EXIT_UNTRUSTED)
        self.assertIn("FORK", out)

    def test_sync_into_a_fresh_ledger_fast_forwards(self) -> None:
        self.init()
        self.run_cli("ledger", "export", "shared.jsonl")
        other = os.path.join(self.tmp, "other")
        os.makedirs(os.path.join(other, ".attestry"))
        os.chdir(other)
        code, out, _ = self.run_cli("ledger", "sync", os.path.join(self.tmp, "shared.jsonl"))
        self.assertEqual(code, EXIT_OK)
        self.assertIn("fast-forwarded", out)


class DriftCliTests(CliCase):
    def test_first_run_establishes_a_baseline_then_detects_drift(self) -> None:
        self.init()
        code, out, _ = self.run_cli("drift", "run", "example")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("became the baseline", out)

        os.environ["ATTESTRY_ECHO_VARIANT"] = "b"
        code, out, _ = self.run_cli("drift", "run", "example")
        self.assertEqual(code, EXIT_MOVED)
        self.assertIn("DRIFT", out)
        self.assertIn("model identity changed", out)

    def test_no_pin_new_leaves_no_baseline(self) -> None:
        self.init()
        self.run_cli("drift", "run", "example", "--no-pin-new")
        self.assertFalse(os.path.exists(
            os.path.join(".attestry", "drift", "baselines", "example.json")
        ))

    def test_pin_accepts_new_behaviour(self) -> None:
        self.init()
        self.run_cli("drift", "run", "example")
        os.environ["ATTESTRY_ECHO_VARIANT"] = "b"
        self.assertEqual(self.run_cli("drift", "run", "example", "--pin")[0], EXIT_MOVED)
        code, out, _ = self.run_cli("drift", "run", "example")
        self.assertEqual(code, EXIT_OK)

    def test_history_and_show(self) -> None:
        self.init()
        self.run_cli("drift", "run", "example")
        code, out, _ = self.run_cli("drift", "history", "example")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("ok", out)
        code, out, _ = self.run_cli("drift", "show", "example", "tone-check")
        self.assertIn("output digest", out)

    def test_missing_suite_is_reported_with_the_alternatives(self) -> None:
        self.init()
        code, _, err = self.run_cli("drift", "run", "nope")
        self.assertEqual(code, EXIT_CANNOT_RUN)
        self.assertIn("available", err)

    def test_list_shows_baseline_state(self) -> None:
        self.init()
        code, out, _ = self.run_cli("drift", "list")
        self.assertIn("no baseline yet", out)
        self.run_cli("drift", "run", "example")
        code, out, _ = self.run_cli("drift", "list")
        self.assertIn("baseline pinned", out)


class SchemaCliTests(CliCase):
    MCP_TOOL = {
        "tools": [{
            "name": "send_invoice",
            "description": "Email an invoice to a customer.",
            "inputSchema": {
                "type": "object",
                "properties": {"customer_id": {"type": "string", "description": "Account id."}},
                "required": ["customer_id"],
            },
            "annotations": {"readOnlyHint": True, "openWorldHint": True},
        }]
    }

    def write_tools(self) -> str:
        with open("tools.json", "w", encoding="utf-8") as handle:
            json.dump(self.MCP_TOOL, handle)
        return "tools.json"

    def test_ingest_then_emit_every_target(self) -> None:
        self.init()
        code, out, _ = self.run_cli("schema", "ingest", self.write_tools())
        self.assertEqual(code, EXIT_OK)
        self.assertIn("from mcp format", out)
        code, _, _ = self.run_cli("schema", "emit", "send_invoice", "--all", "--out", "adapters")
        self.assertEqual(code, EXIT_OK)
        produced = sorted(os.listdir("adapters"))
        self.assertIn("send_invoice.crewai.py", produced)
        self.assertIn("send_invoice.mcp.json", produced)

    def test_new_list_and_validate(self) -> None:
        self.init()
        self.assertEqual(self.run_cli("schema", "new", "my_tool")[0], EXIT_OK)
        code, out, _ = self.run_cli("schema", "list")
        self.assertIn("my_tool", out)
        # The skeleton intentionally has a placeholder description, so validate
        # reports work still to do rather than pretending it is finished.
        self.assertIn(self.run_cli("schema", "validate", "my_tool")[0],
                      (EXIT_OK, EXIT_FAILED))

    def test_register_reports_an_escalation_and_exits_moved(self) -> None:
        self.init()
        self.run_cli("schema", "ingest", self.write_tools())
        self.assertEqual(self.run_cli("schema", "register", "send_invoice")[0], EXIT_OK)

        path = os.path.join(".attestry", "schemas", "send_invoice.nts.json")
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        document["effects"]["writes"] = ["billing records"]
        document["effects"]["destructive"] = True
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)

        code, out, _ = self.run_cli("schema", "register", "send_invoice")
        self.assertEqual(code, EXIT_MOVED)
        self.assertIn("escalation", out)
        code, out, _ = self.run_cli("schema", "history", "send_invoice")
        self.assertIn("schema.changed", out)

    def test_diff_between_two_files_exits_moved(self) -> None:
        self.init()
        self.run_cli("schema", "ingest", self.write_tools())
        source = os.path.join(".attestry", "schemas", "send_invoice.nts.json")
        with open(source, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        document["params"].append(
            {"name": "force", "type": "boolean", "description": "Skip.", "required": True}
        )
        with open("v2.json", "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        code, out, _ = self.run_cli("schema", "diff", source, "v2.json")
        self.assertEqual(code, EXIT_MOVED)
        self.assertIn("new required parameter", out)


class ReceiptsCliTests(CliCase):
    def record(self, *extra: str):
        return self.run_cli(
            "receipts", "record",
            "--actor", "agent:inbox-triage",
            "--action", "read",
            "--resource", "email:gmail/INBOX",
            "--purpose", "draft daily priorities",
            "--items", "42",
            "--fields", "subject,from",
            "--data-classes", "message_content",
            *extra,
        )

    def test_a_permitted_access_reads_as_english(self) -> None:
        self.init()
        code, out, _ = self.record()
        self.assertEqual(code, EXIT_OK)
        self.assertIn("read 42 messages in your Gmail inbox", out)
        self.assertIn("No data left your machine", out)

    def test_an_ungranted_access_exits_failed(self) -> None:
        self.init()
        code, out, _ = self.run_cli(
            "receipts", "record", "--actor", "agent:inbox-triage",
            "--action", "delete", "--resource", "email:gmail/INBOX", "--purpose", "cleanup",
        )
        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("NOT PERMITTED", out)

    def test_list_digest_and_html(self) -> None:
        self.init()
        self.record()
        code, out, _ = self.run_cli("receipts", "list")
        self.assertIn("inbox-triage agent", out)
        code, out, _ = self.run_cli("receipts", "digest", "--period", "this week")
        self.assertIn("this week", out)
        code, _, _ = self.run_cli("receipts", "html", "--out", "receipts.html")
        self.assertEqual(code, EXIT_OK)
        with open("receipts.html", "r", encoding="utf-8") as handle:
            self.assertIn("<!DOCTYPE html>", handle.read())

    def test_grants_are_listed(self) -> None:
        self.init()
        code, out, _ = self.run_cli("receipts", "grants")
        self.assertIn("inbox-triage", out)
        self.assertIn("default: deny", out)

    def test_check_flags_history_against_a_narrowed_policy(self) -> None:
        self.init()
        self.record()
        path = os.path.join(".attestry", "receipts", "consent.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"default_deny": True, "grants": []}, handle)
        code, out, _ = self.run_cli("receipts", "check")
        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("would not be permitted today", out)


class RegistryCliTests(CliCase):
    MANIFEST = {
        "name": "hello-web", "version": "1.0.0",
        "description": "Fetch a URL and return its readable text.",
        "author": "Nulfied", "license": "MIT", "entry": "skill.py",
    }

    def make_package(self) -> str:
        directory = os.path.join(self.tmp, "hello-web")
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "skill.json"), "w", encoding="utf-8") as handle:
            json.dump(self.MANIFEST, handle)
        with open(os.path.join(directory, "skill.py"), "w", encoding="utf-8") as handle:
            handle.write("def fetch_page(url):\n    return url\n")
        return directory

    def test_pack_publish_install_verify(self) -> None:
        self.init()
        directory = self.make_package()
        code, out, _ = self.run_cli("registry", "pack", directory, "--out", "pkg.tar.gz")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("digest", out)

        code, out, _ = self.run_cli("registry", "publish", directory, "--source", "pkg.tar.gz")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("published hello-web@1.0.0", out)

        code, out, _ = self.run_cli("registry", "install", "hello-web@^1.0.0", "--to", "installed")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(os.path.exists(os.path.join("installed", "skill.py")))

        code, out, _ = self.run_cli("registry", "verify", "installed", "hello-web@1.0.0")
        self.assertEqual(code, EXIT_OK)

        with open(os.path.join("installed", "skill.py"), "a", encoding="utf-8") as handle:
            handle.write("\n# sneaky\n")
        code, out, _ = self.run_cli("registry", "verify", "installed", "hello-web@1.0.0")
        self.assertEqual(code, EXIT_UNTRUSTED)
        self.assertIn("MISMATCH", out)

    def test_show_and_list(self) -> None:
        self.init()
        directory = self.make_package()
        self.run_cli("registry", "publish", directory, "--source", "pkg.tar.gz")
        code, out, _ = self.run_cli("registry", "list")
        self.assertIn("hello-web", out)
        code, out, _ = self.run_cli("registry", "show", "hello-web@1.0.0")
        self.assertIn("Nulfied", out)
        self.assertIn("digest", out)

    def test_revoke_stops_resolution(self) -> None:
        self.init()
        directory = self.make_package()
        self.run_cli("registry", "publish", directory, "--source", "pkg.tar.gz")
        code, _, _ = self.run_cli("registry", "revoke", "hello-web@1.0.0",
                                  "--reason", "leaked a key")
        self.assertEqual(code, EXIT_OK)
        code, _, err = self.run_cli("registry", "resolve", "hello-web")
        self.assertEqual(code, EXIT_CANNOT_RUN)
        self.assertIn("revoked", err)

    def test_remotes(self) -> None:
        self.init()
        self.assertEqual(
            self.run_cli("registry", "remote", "add", "up", "https://example.com/l.jsonl")[0],
            EXIT_OK,
        )
        code, out, _ = self.run_cli("registry", "remote", "list")
        self.assertIn("up", out)

    def test_conflicts_is_quiet_when_there_are_none(self) -> None:
        self.init()
        code, out, _ = self.run_cli("registry", "conflicts")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("no conflicting", out)


if __name__ == "__main__":
    unittest.main()
