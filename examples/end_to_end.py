"""All four subsystems, then one verification that covers every claim.

Runs entirely offline and for free: the drift suite uses the bundled ``echo``
provider, and everything else is local. Nothing outside a temporary directory is
touched.

    python examples/end_to_end.py
"""

from __future__ import annotations

import os
import shutil
import tempfile

from attestry.drift import (
    example_suite,
    get_provider,
    load_baseline,
    record_run,
    run_suite,
    save_baseline,
)
from attestry.ledger import Keyring, Ledger, TrustStore
from attestry.receipts import (
    ConsentPolicy,
    Recorder,
    example_policy,
    render_digest,
    render_receipt,
)
from attestry.registry import Package, Registry
from attestry.schema import Effects, Param, SchemaStore, ToolSchema, emit, format_changes
from attestry.workspace import Workspace

HERE = os.path.dirname(os.path.abspath(__file__))


def banner(text: str) -> None:
    print("\n" + text)
    print("=" * len(text))


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="attestry-example-")
    try:
        workspace = Workspace.init(workdir)
        key = Keyring(workspace.keys_dir).create("example")
        trust = TrustStore(workspace.trust_path, mode="tofu")
        trust.add(key.public, "example")
        ledger = Ledger(workspace.ledger_path, key=key, trust=trust)
        ledger.announce_key(key)
        print("workspace ready, signing key %s" % key.keyid)

        # -- 1. drift ----------------------------------------------------
        banner("1. Model drift")
        suite = example_suite("demo")
        first = run_suite(suite, get_provider("echo", "demo", variant="a"))
        save_baseline(workspace.baselines_dir, suite.name, first)
        record_run(ledger, first)
        print("baseline pinned from a run that was %s" % first.status)

        # The same suite against a model that now answers differently -- which is
        # what a provider updating a model behind a stable name looks like.
        baseline = load_baseline(workspace.baselines_dir, suite.name)
        second = run_suite(
            suite, get_provider("echo", "demo", variant="b"), baseline=baseline
        )
        record_run(ledger, second)
        print("second run: %s (exit code %d)" % (second.status, second.exit_code))
        for warning in second.identity_warnings:
            print("  !! %s" % warning)

        # -- 2. schema ---------------------------------------------------
        banner("2. One tool definition, every framework")
        tool = ToolSchema(
            name="send_invoice",
            description="Email an invoice to a customer.",
            params=[
                Param("customer_id", "string", "Account id.", required=True),
                Param("amount", "number", "Amount in USD.", required=True, minimum=0),
            ],
            effects=Effects(reads=["billing"], network=True),
        )
        store = SchemaStore(workspace.schemas_dir, ledger)
        store.save(tool)
        store.register(tool)
        for target in ("mcp", "openai", "anthropic", "crewai"):
            payload, notes = emit(tool, target)
            kind = "source" if isinstance(payload, str) else "json"
            print("  %-10s %-7s %d note(s)" % (target, kind, len(notes)))

        # The same tool, six months later, quietly able to write and delete.
        escalated = ToolSchema.from_dict(tool.to_dict())
        escalated.effects.writes = ["customer billing records"]
        escalated.effects.destructive = True
        escalated.effects.idempotent = False
        changes, severity = store.register(escalated)
        print("\nre-registered after a dependency update -- %s:" % severity)
        print(format_changes(changes))

        # -- 3. receipts -------------------------------------------------
        banner("3. Consent receipts")
        policy = example_policy()
        policy.save(workspace.consent_path)
        recorder = Recorder(
            ledger, ConsentPolicy.load(workspace.consent_path),
            actor="agent:inbox-triage",
        )

        with recorder.access(
            "read", "email:gmail/INBOX",
            purpose="draft daily priorities",
            fields=["subject", "from"],
            data_classes=["message_content"],
            selector="1-25 Sep",
        ) as event:
            event.items = 42

        record = recorder.history()[-1]
        print(render_receipt(record.event, record.decision, record.flags, record.seq))

        # An access nobody granted. It is recorded as denied, and never credited.
        with recorder.access("send", "email:gmail/Sent", purpose="reply to customers"):
            pass
        print("\n" + render_digest(recorder.events(), "What the agents did"))

        # -- 4. registry -------------------------------------------------
        banner("4. Serverless skill registry")
        source = os.path.join(workdir, "hello-web")
        shutil.copytree(os.path.join(HERE, "skills", "hello-web"), source)
        package = Package.from_dir(source)
        archive = os.path.join(workdir, "hello-web-1.0.0.tar.gz")
        package.write_archive(archive)

        registry = Registry(ledger, trust, workspace.cache_dir)
        registry.publish(package, sources=[archive])
        print("published %s" % package.manifest.spec)
        print("  digest %s" % package.digest())

        publication, installed = registry.install("hello-web@^1.0.0")
        print("installed and verified against the ledger")
        print("  %s" % registry.verify_installed(installed, publication)[1])

        # Somebody edits the installed copy.
        with open(os.path.join(installed, "skill.py"), "a", encoding="utf-8") as handle:
            handle.write("\n# added later\n")
        print("  after an edit: %s" % registry.verify_installed(installed, publication)[1])

        # -- one verification covering all four --------------------------
        banner("One verification, every claim")
        result = ledger.verify()
        print(result.format())
        print("\nentries by subsystem:")
        for namespace, count in sorted(ledger.stats().items()):
            print("  %-10s %d" % (namespace, count))

        # And a proof that one specific entry was recorded, without disclosing
        # anything about the others.
        ledger.checkpoint()
        proof = ledger.inclusion_proof(record.seq)
        print(
            "\ninclusion proof for receipt #%d: %s (%d sibling hashes)"
            % (record.seq, Ledger.verify_inclusion(proof), len(proof["path"]))
        )
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
