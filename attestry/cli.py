"""The ``attestry`` command line.

Four subsystems under one command, over one ledger. The grouping is not
cosmetic: ``attestry ledger verify`` checks drift runs, receipts, schema history
and package provenance in a single pass, because they are all entries in the
same chain.

Exit codes are part of the interface, since most of this is meant to run
unattended:

====  ===========================================================
0     everything fine
1     something moved -- drift detected, or a schema changed
2     something failed -- an expectation broke, or a check did not pass
3     something could not run -- provider unreachable, bad arguments
4     something is untrustworthy -- broken chain, bad signature, untrusted key
====  ===========================================================

Code 4 is deliberately distinct. A failing test and a ledger that does not
verify are different emergencies, and a CI job should be able to treat them
differently.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .drift import (
    Suite,
    case_timeline,
    example_suite,
    get_provider,
    history as drift_history,
    load_baseline,
    record_baseline,
    record_run,
    run_suite,
    save_baseline,
    save_run,
)
from .ledger import BACKEND, Keyring, Ledger, TrustStore
from .receipts import (
    AccessEvent,
    ConsentPolicy,
    Recorder,
    example_policy,
    render_digest,
    render_html,
    render_receipt,
)
from .registry import (
    Package,
    Registry,
    Remotes,
    export_ledger,
    sync as sync_ledger,
)
from .schema import (
    TARGETS,
    Consent,
    Effects,
    Param,
    SchemaStore,
    ToolSchema,
    diff as schema_diff,
    extension_for,
    format_changes,
    from_any,
    from_callable,
    load_schema_file,
    render as render_schema,
)
from .util.errors import AttestryError, ForkDetected, IntegrityError, TrustError
from .workspace import Workspace, find_workspace

EXIT_OK = 0
EXIT_MOVED = 1
EXIT_FAILED = 2
EXIT_CANNOT_RUN = 3
EXIT_UNTRUSTED = 4


class Context:
    """Resolved workspace, key, trust store and ledger for one invocation."""

    def __init__(self, args: argparse.Namespace, required: bool = True) -> None:
        self.args = args
        self.json = bool(getattr(args, "json", False))
        self.workspace: Optional[Workspace] = find_workspace(
            getattr(args, "directory", None), required=required
        )
        self._ledger: Optional[Ledger] = None
        self._trust: Optional[TrustStore] = None
        self._key = None

    @property
    def trust(self) -> TrustStore:
        if self._trust is None:
            mode = self.workspace.get_config("trust_mode", "tofu")
            self._trust = TrustStore(self.workspace.trust_path, mode=mode)
        return self._trust

    @property
    def keyring(self) -> Keyring:
        return Keyring(self.workspace.keys_dir)

    @property
    def key(self):
        if self._key is None:
            wanted = getattr(self.args, "key", None) or self.workspace.get_config("default_key")
            keys = self.keyring.list()
            if wanted:
                self._key = self.keyring.load(wanted)
            elif keys:
                self._key = self.keyring.load(keys[0].keyid)
            else:
                raise AttestryError(
                    "no signing key in this workspace; run 'attestry ledger keys --new <label>'"
                )
        return self._key

    @property
    def ledger(self) -> Ledger:
        if self._ledger is None:
            try:
                key = self.key
            except AttestryError:
                key = None
            self._ledger = Ledger(self.workspace.ledger_path, key=key, trust=self.trust)
        return self._ledger

    def emit(self, payload: Any, text: str = "") -> None:
        """Print JSON or human text, depending on ``--json``."""
        if self.json:
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(text if text else json.dumps(payload, indent=2, default=str))


def _split(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [piece.strip() for piece in value.split(",") if piece.strip()]


# -- init and doctor -----------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    target = os.path.abspath(args.directory or os.getcwd())
    workspace = Workspace.init(target)
    workspace.set_config("trust_mode", args.trust_mode)

    keyring = Keyring(workspace.keys_dir)
    existing = keyring.list()
    if existing:
        key = keyring.load(existing[0].keyid)
        created = False
    else:
        key = keyring.create(args.label)
        workspace.set_config("default_key", key.keyid)
        created = True

    trust = TrustStore(workspace.trust_path, mode=args.trust_mode)
    trust.add(key.public, key.label, note="this workspace's own key")
    ledger = Ledger(workspace.ledger_path, key=key, trust=trust)
    if not len(ledger):
        ledger.append("ledger.genesis", key.label or key.keyid,
                      {"tool": "attestry", "version": __version__})
        ledger.announce_key(key)

    made: List[str] = []
    if not args.bare:
        suite_path = os.path.join(workspace.suites_dir, "example.suite.json")
        if not os.path.exists(suite_path):
            example_suite("example").save(suite_path)
            made.append(os.path.relpath(suite_path, target))
        if not os.path.exists(workspace.consent_path):
            example_policy().save(workspace.consent_path)
            made.append(os.path.relpath(workspace.consent_path, target))

    print("Initialised an Attestry workspace in %s" % os.path.relpath(workspace.root, target))
    print("  signing key   %s  (%s)" % (key.keyid, "new" if created else "existing"))
    print("  trust mode    %s" % args.trust_mode)
    print("  crypto        %s" % BACKEND)
    for path in made:
        print("  wrote         %s" % path)
    print("")
    print("Next: 'attestry drift run example' for a free drift run, or")
    print("      'attestry doctor' to see how everything is wired up.")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    context = Context(args, required=False)
    lines: List[str] = ["attestry %s" % __version__, ""]
    report: Dict[str, Any] = {"version": __version__, "crypto_backend": BACKEND}

    if context.workspace is None or not context.workspace.exists:
        lines.append("workspace    none found -- run 'attestry init'")
        report["workspace"] = None
        context.emit(report, "\n".join(lines))
        return EXIT_CANNOT_RUN

    workspace = context.workspace
    lines.append("workspace    %s" % workspace.root)
    lines.append("crypto       %s%s" % (
        BACKEND,
        "" if BACKEND == "cryptography" else "  (pip install attestry[fast] for a "
                                            "constant-time, much faster backend)",
    ))
    report["workspace"] = workspace.root

    keys = context.keyring.list()
    lines.append("keys         %d  %s" % (
        len(keys), ", ".join(k.keyid for k in keys) or "none -- nothing can be signed"
    ))
    trust = context.trust
    lines.append("trust mode   %s%s" % (
        trust.mode,
        "  (signatures are verified but trust is not enforced)" if trust.mode == "open" else "",
    ))
    lines.append("trusted keys %d" % len(trust.keys))
    report["keys"] = [k.keyid for k in keys]
    report["trust_mode"] = trust.mode

    ledger = context.ledger
    result = ledger.verify()
    lines.append("")
    lines.append("ledger       %d entries, %d signed" % (result.entries, result.signed))
    for namespace, count in sorted(ledger.stats().items()):
        lines.append("  %-10s %d" % (namespace, count))
    lines.append("verification %s" % ("OK" if result.ok else "BROKEN"))
    for problem in result.problems[:8]:
        lines.append(problem.format())
    report["ledger"] = result.to_dict()

    lines.append("")
    lines.append("providers")
    for name, variable in (
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
    ):
        lines.append("  %-10s %s" % (
            name, "key present" if os.environ.get(variable) else "%s not set" % variable
        ))
    lines.append("  %-10s %s" % ("ollama", os.environ.get("OLLAMA_HOST", "http://localhost:11434")))
    lines.append("  %-10s always available, costs nothing" % "echo")

    suites = _suite_names(workspace)
    lines.append("")
    lines.append("suites       %s" % (", ".join(suites) or "none"))
    policy = ConsentPolicy.load(workspace.consent_path)
    lines.append("consent      %d grant(s), default %s" % (
        len(policy), "deny" if policy.default_deny else "allow"
    ))
    registry = Registry(ledger, trust, workspace.cache_dir)
    lines.append("packages     %d published" % len(registry.publications(include_revoked=True)))
    conflicts = registry.conflicts()
    if conflicts:
        lines.append("  !! %d conflicting publication(s); run 'attestry registry conflicts'"
                     % len(conflicts))

    context.emit(report, "\n".join(lines))
    return EXIT_OK if result.ok else EXIT_UNTRUSTED


# -- ledger --------------------------------------------------------------


def cmd_ledger_log(args: argparse.Namespace) -> int:
    context = Context(args)
    entries = context.ledger.select(
        kind=args.kind, subject=args.subject, since=args.since, limit=args.limit
    )
    if context.json:
        context.emit([e.to_dict() for e in entries])
    else:
        if not entries:
            print("no matching entries")
        for entry in entries:
            print(entry.describe())
    return EXIT_OK


def cmd_ledger_verify(args: argparse.Namespace) -> int:
    context = Context(args)
    result = context.ledger.verify(require_signatures=args.require_signatures)
    context.emit(result.to_dict(), result.format())
    return EXIT_OK if result.ok else EXIT_UNTRUSTED


def cmd_ledger_checkpoint(args: argparse.Namespace) -> int:
    context = Context(args)
    entry = context.ledger.checkpoint()
    context.emit(
        entry.to_dict(),
        "checkpoint #%d over %d entries\n  root %s"
        % (entry.seq, entry.body["size"], entry.body["root"]),
    )
    return EXIT_OK


def cmd_ledger_prove(args: argparse.Namespace) -> int:
    context = Context(args)
    if args.check:
        with open(args.check, "r", encoding="utf-8") as handle:
            proof = json.load(handle)
        ok = Ledger.verify_inclusion(proof)
        print("proof for entry #%s: %s" % (proof.get("seq"), "VALID" if ok else "INVALID"))
        return EXIT_OK if ok else EXIT_UNTRUSTED
    proof = context.ledger.inclusion_proof(args.seq)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(proof, handle, indent=2)
            handle.write("\n")
        print("wrote %s" % args.out)
        print("Anyone can check it with: attestry ledger prove --check %s" % args.out)
    else:
        print(json.dumps(proof, indent=2))
    return EXIT_OK


def cmd_ledger_export(args: argparse.Namespace) -> int:
    context = Context(args)
    path = export_ledger(context.ledger, args.out)
    print("exported %d entries to %s" % (len(context.ledger), path))
    return EXIT_OK


def cmd_ledger_sync(args: argparse.Namespace) -> int:
    context = Context(args)
    remotes = Remotes.load(context.workspace.remotes_path)
    source = remotes.url(args.source)
    try:
        result, problems = sync_ledger(context.ledger, source, context.trust)
    except ForkDetected as exc:
        print("FORK: %s" % exc)
        print("\nHistories diverge, so no automatic merge is possible. Compare the two")
        print("ledgers and decide which history is the real one.")
        return EXIT_UNTRUSTED
    except IntegrityError as exc:
        print("REFUSED: %s" % exc)
        return EXIT_UNTRUSTED
    print("%s: %s" % (source, result.format()))
    for problem in problems:
        print("  note: %s" % problem)
    return EXIT_OK


def cmd_ledger_keys(args: argparse.Namespace) -> int:
    context = Context(args)
    if args.new is not None:
        key = context.keyring.create(args.new)
        context.trust.add(key.public, key.label, note="created locally")
        if not context.workspace.get_config("default_key"):
            context.workspace.set_config("default_key", key.keyid)
        ledger = Ledger(context.workspace.ledger_path, key=key, trust=context.trust)
        ledger.announce_key(key)
        print("created key %s (%s)" % (key.keyid, key.label or "unlabelled"))
        print("  public %s" % key.public)
        return EXIT_OK
    keys = context.keyring.list()
    default = context.workspace.get_config("default_key")
    if not keys:
        print("no keys; create one with 'attestry ledger keys --new <label>'")
    for key in keys:
        print("%s  %-20s %s%s" % (
            key.keyid, key.label or "(unlabelled)", key.created,
            "  [default]" if key.keyid == default else "",
        ))
    return EXIT_OK


def cmd_ledger_trust(args: argparse.Namespace) -> int:
    context = Context(args)
    trust = context.trust
    if args.action == "list":
        print(trust.describe())
    elif args.action == "add":
        if not args.value:
            raise AttestryError("give the public key hex to trust")
        keyid = trust.add(args.value, args.label or "")
        print("trusting %s" % keyid)
    elif args.action == "remove":
        print("removed %s" % args.value if trust.remove(args.value) else "no such key")
    elif args.action == "mode":
        if args.value not in ("strict", "tofu", "open"):
            raise AttestryError("mode must be strict, tofu or open")
        trust.mode = args.value
        trust.save()
        context.workspace.set_config("trust_mode", args.value)
        print("trust mode is now %s" % args.value)
    return EXIT_OK


def cmd_ledger_revoke(args: argparse.Namespace) -> int:
    context = Context(args)
    context.trust.revoke(args.keyid, args.reason, args.invalidates)
    context.ledger.append(
        "ledger.key-revoked",
        args.keyid,
        {"keyid": args.keyid, "reason": args.reason, "invalidates": args.invalidates},
    )
    print("revoked %s (%s); invalidates %s" % (args.keyid, args.reason, args.invalidates))
    if args.invalidates == "all":
        print("Every signature from this key is now rejected, including older ones.")
    else:
        print("Signatures made before now remain valid.")
    return EXIT_OK


def cmd_ledger_stats(args: argparse.Namespace) -> int:
    context = Context(args)
    ledger = context.ledger
    stats = ledger.stats()
    head = ledger.head()
    context.emit(
        {"entries": len(ledger), "by_namespace": stats,
         "head": head.hash if head else None},
        "\n".join(
            ["%d entries" % len(ledger)]
            + ["  %-10s %d" % (name, count) for name, count in sorted(stats.items())]
            + ["head %s" % (head.hash if head else "(empty)")]
        ),
    )
    return EXIT_OK


# -- drift ---------------------------------------------------------------


def _suite_names(workspace: Workspace) -> List[str]:
    directory = workspace.suites_dir
    if not os.path.isdir(directory):
        return []
    return sorted(
        name[: -len(".suite.json")]
        for name in os.listdir(directory)
        if name.endswith(".suite.json")
    )


def _load_suite(workspace: Workspace, name: str) -> Suite:
    path = name if os.path.exists(name) else os.path.join(
        workspace.suites_dir, "%s.suite.json" % name
    )
    if not os.path.exists(path):
        available = ", ".join(_suite_names(workspace)) or "none"
        raise AttestryError("no suite %r; available: %s" % (name, available))
    return Suite.load(path)


def cmd_drift_init(args: argparse.Namespace) -> int:
    context = Context(args)
    suite = example_suite(args.name)
    path = os.path.join(context.workspace.suites_dir, "%s.suite.json" % args.name)
    if os.path.exists(path) and not args.force:
        raise AttestryError("%s already exists; pass --force to overwrite" % path)
    suite.save(path)
    print("wrote %s" % path)
    print("Run it with: attestry drift run %s" % args.name)
    return EXIT_OK


def cmd_drift_list(args: argparse.Namespace) -> int:
    context = Context(args)
    names = _suite_names(context.workspace)
    if not names:
        print("no suites; create one with 'attestry drift init'")
    for name in names:
        suite = _load_suite(context.workspace, name)
        baseline = load_baseline(context.workspace.baselines_dir, name)
        print("%-24s %-22s %2d cases  %s" % (
            name,
            "%s:%s" % (suite.provider, suite.model),
            len(suite.cases),
            "baseline pinned" if baseline else "no baseline yet",
        ))
    return EXIT_OK


def cmd_drift_run(args: argparse.Namespace) -> int:
    context = Context(args)
    suite = _load_suite(context.workspace, args.name)
    problems = suite.validate()
    if problems and not args.force:
        print("This suite has problems:")
        for problem in problems:
            print("  - %s" % problem)
        print("Fix them, or pass --force to run anyway.")
        return EXIT_CANNOT_RUN

    provider_name = args.provider or suite.provider
    model = args.model or suite.model
    if args.provider or args.model:
        suite.provider, suite.model = provider_name, model
    engine = get_provider(provider_name, model)
    baseline = load_baseline(context.workspace.baselines_dir, suite.name)

    run = run_suite(suite, engine, baseline=baseline, only=_split(args.case) or None)
    save_run(context.workspace.runs_dir, run)
    if not args.no_record:
        record_run(context.ledger, run)

    # With no baseline there is nothing to detect drift against, so the first
    # run establishes one -- the same convention snapshot-testing tools follow.
    # Without this the tool silently does nothing useful until somebody happens
    # to read the docs and run 'drift baseline'.
    auto_pinned = False
    if args.pin or (not baseline and not args.no_pin_new and run.status != "error"):
        save_baseline(context.workspace.baselines_dir, suite.name, run)
        if not args.no_record:
            record_baseline(context.ledger, run)
        auto_pinned = not args.pin

    if args.markdown:
        print(run.markdown())
    else:
        context.emit(run.to_dict(), run.format(baseline=baseline, show_diff=args.diff))

    if context.json:
        return run.exit_code
    if auto_pinned:
        print("")
        print("No baseline existed, so this run became the baseline. Review it, commit")
        print("%s, and future runs will be compared against it."
              % os.path.relpath(
                  os.path.join(context.workspace.baselines_dir, "%s.json" % suite.name),
                  os.getcwd(),
              ))
    elif run.status in ("drift", "minor") and not args.pin:
        print("")
        print("If this is the new correct behaviour, accept it with:")
        print("  attestry drift baseline %s" % suite.name)
    return run.exit_code


def cmd_drift_baseline(args: argparse.Namespace) -> int:
    context = Context(args)
    suite = _load_suite(context.workspace, args.name)
    engine = get_provider(args.provider or suite.provider, args.model or suite.model)
    run = run_suite(suite, engine)
    if run.status in ("error",) and not args.force:
        print("Some cases errored; pinning now would record an outage as the")
        print("reference behaviour. Fix the provider, or pass --force.")
        print(run.format())
        return EXIT_CANNOT_RUN
    path = save_baseline(context.workspace.baselines_dir, suite.name, run)
    record_baseline(context.ledger, run)
    print("pinned %d case(s) as the baseline for %s" % (
        len([o for o in run.outcomes if o.status not in ("error", "skipped")]), suite.name
    ))
    print("  %s" % path)
    return EXIT_OK


def cmd_drift_history(args: argparse.Namespace) -> int:
    context = Context(args)
    rows = drift_history(context.ledger, args.name, limit=args.limit)
    if context.json:
        context.emit(rows)
        return EXIT_OK
    if not rows:
        print("no recorded runs for %s" % args.name)
    for row in rows:
        counts = ", ".join("%d %s" % (v, k) for k, v in sorted(row["counts"].items()))
        print("#%-5d %s  %-8s %-24s %s" % (
            row["seq"], row["ts"], row["status"], row["model"] or "", counts
        ))
    return EXIT_OK


def cmd_drift_show(args: argparse.Namespace) -> int:
    context = Context(args)
    rows = case_timeline(context.ledger, args.name, args.case)
    if context.json:
        context.emit(rows)
        return EXIT_OK
    if not rows:
        print("nothing recorded for case %r in suite %r" % (args.case, args.name))
        return EXIT_OK
    print("%-6s %-22s %-14s %-8s %s" % ("entry", "when", "output digest", "status", "served model"))
    previous = None
    for row in rows:
        marker = "  <- changed here" if previous and row["digest"] != previous else ""
        print("#%-5d %-22s %-14s %-8s %s%s" % (
            row["seq"], row["ts"], row["digest"], row["status"],
            row["served_model"] or "", marker,
        ))
        previous = row["digest"]
    return EXIT_OK


# -- schema --------------------------------------------------------------


def _store(context: Context) -> SchemaStore:
    return SchemaStore(context.workspace.schemas_dir, context.ledger)


def cmd_schema_new(args: argparse.Namespace) -> int:
    context = Context(args)
    tool = ToolSchema(
        name=args.name,
        title=args.name.replace("_", " ").title(),
        description=args.description or "Describe what this tool does, for the model.",
        params=[
            Param("query", "string", "What to act on.", required=True),
        ],
        effects=Effects(reads=[], writes=[], network=False, idempotent=True),
        consent=Consent(),
    )
    store = _store(context)
    path = store.save(tool)
    print("wrote %s" % path)
    print("Edit it, then: attestry schema emit %s --target mcp" % args.name)
    return EXIT_OK


def cmd_schema_list(args: argparse.Namespace) -> int:
    context = Context(args)
    store = _store(context)
    names = store.names()
    if not names:
        print("no schemas; create one with 'attestry schema new <name>'")
    for name in names:
        tool = store.load(name)
        problems = tool.validate()
        print("%-24s %-16s %2d params  %s" % (
            name, tool.digest()[:12], len(tool.params),
            "ok" if not problems else "%d problem(s)" % len(problems),
        ))
    return EXIT_OK


def cmd_schema_validate(args: argparse.Namespace) -> int:
    context = Context(args)
    store = _store(context)
    names = [args.name] if args.name else store.names()
    worst = EXIT_OK
    for name in names:
        tool = load_schema_file(name) if os.path.exists(name) else store.load(name)
        problems = tool.validate()
        if problems:
            worst = EXIT_FAILED
            print("%s: %d problem(s)" % (tool.name, len(problems)))
            for problem in problems:
                print("  - %s" % problem)
        else:
            print("%s: ok" % tool.name)
    return worst


def cmd_schema_emit(args: argparse.Namespace) -> int:
    context = Context(args)
    store = _store(context)
    tool = load_schema_file(args.name) if os.path.exists(args.name) else store.load(args.name)
    targets = sorted(TARGETS) if args.all else [args.target]
    for target in targets:
        text, notes = render_schema(tool, target, strict=args.strict, style=args.style)
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            path = os.path.join(args.out, "%s.%s%s" % (tool.name, target, extension_for(target)))
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            print("wrote %s" % path)
        else:
            if len(targets) > 1:
                print("# ---- %s ----" % target)
            sys.stdout.write(text)
        for note in notes:
            print("  note (%s): %s" % (target, note), file=sys.stderr)
    return EXIT_OK


def cmd_schema_ingest(args: argparse.Namespace) -> int:
    context = Context(args)
    with open(args.file, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    results = from_any(payload, args.name or "")
    store = _store(context)
    for tool, detected in results:
        if args.name and len(results) == 1:
            tool.name = args.name
        path = store.save(tool)
        problems = tool.validate()
        print("imported %s from %s format -> %s" % (tool.name, detected, path))
        for problem in problems:
            print("  todo: %s" % problem)
    return EXIT_OK


def cmd_schema_from_python(args: argparse.Namespace) -> int:
    context = Context(args)
    import importlib

    if ":" not in args.target_ref:
        raise AttestryError("use module:function, for example mypkg.tools:search")
    module_name, function_name = args.target_ref.split(":", 1)
    sys.path.insert(0, os.getcwd())
    module = importlib.import_module(module_name)
    function = getattr(module, function_name, None)
    if function is None:
        raise AttestryError("%s has no attribute %r" % (module_name, function_name))
    tool = from_callable(function, name=args.name or "")
    path = _store(context).save(tool)
    print("derived %s from %s -> %s" % (tool.name, args.target_ref, path))
    for problem in tool.validate():
        print("  todo: %s" % problem)
    return EXIT_OK


def cmd_schema_diff(args: argparse.Namespace) -> int:
    context = Context(args)
    store = _store(context)
    old = load_schema_file(args.old) if os.path.exists(args.old) else store.load(args.old)
    new = load_schema_file(args.new) if os.path.exists(args.new) else store.load(args.new)
    changes = schema_diff(old, new)
    if context.json:
        context.emit([c.to_dict() for c in changes])
    else:
        print(format_changes(changes))
    if any(c.severity in ("escalation", "breaking") for c in changes):
        return EXIT_MOVED
    return EXIT_OK


def cmd_schema_register(args: argparse.Namespace) -> int:
    context = Context(args)
    store = _store(context)
    names = [args.name] if args.name else store.names()
    worst = EXIT_OK
    for name in names:
        tool = store.load(name)
        changes, severity = store.register(tool)
        if not changes:
            print("%s: recorded (%s)" % (name, tool.digest()[:12]))
            continue
        print("%s: interface changed -- %s" % (name, severity))
        print(format_changes(changes))
        if severity in ("escalation", "breaking"):
            worst = EXIT_MOVED
    return worst


def cmd_schema_history(args: argparse.Namespace) -> int:
    context = Context(args)
    rows = _store(context).history(args.name)
    if context.json:
        context.emit(rows)
        return EXIT_OK
    if not rows:
        print("nothing recorded for %s; run 'attestry schema register %s'" % (args.name, args.name))
    for row in rows:
        print("#%-5d %s  %-18s %s  %s" % (
            row["seq"], row["ts"], row["kind"], (row["digest"] or "")[:12],
            row["severity"] or "",
        ))
        for change in row["changes"]:
            print("    %-11s %-22s %s" % (
                change["severity"], change["path"], change["detail"]
            ))
    return EXIT_OK


# -- receipts ------------------------------------------------------------


def _recorder(context: Context, actor: str = "", enforce: bool = False) -> Recorder:
    policy = ConsentPolicy.load(context.workspace.consent_path)
    return Recorder(context.ledger, policy, actor=actor or "agent:unnamed", enforce=enforce)


def cmd_receipts_init(args: argparse.Namespace) -> int:
    context = Context(args)
    path = context.workspace.consent_path
    if os.path.exists(path) and not args.force:
        raise AttestryError("%s already exists; pass --force to overwrite" % path)
    example_policy().save(path)
    print("wrote %s" % path)
    print("Edit the grants, then record accesses with 'attestry receipts record'")
    print("or the Python API (attestry.receipts.Recorder).")
    return EXIT_OK


def cmd_receipts_record(args: argparse.Namespace) -> int:
    context = Context(args)
    recorder = _recorder(context, args.actor)
    event = AccessEvent(
        actor=args.actor,
        action=args.action,
        resource=args.resource,
        purpose=args.purpose or "",
        items=args.items,
        fields=_split(args.fields),
        data_classes=_split(args.data_classes),
        egress=_split(args.egress),
        selector=args.selector or "",
        outcome=args.outcome,
        tool=args.tool or "",
        detail=args.detail or "",
    )
    entry, decision = recorder.record(event)
    record = recorder.history(limit=1)[0]
    print(render_receipt(record.event, decision, record.flags, entry.seq))
    return EXIT_OK if decision.allowed else EXIT_FAILED


def cmd_receipts_list(args: argparse.Namespace) -> int:
    context = Context(args)
    recorder = _recorder(context)
    records = recorder.history(
        actor=args.actor, resource=args.resource, since=args.since, limit=args.limit
    )
    if context.json:
        context.emit([
            {"seq": r.seq, "event": r.event.to_dict(),
             "decision": r.decision.to_dict() if r.decision else None,
             "flags": r.flags}
            for r in records
        ])
        return EXIT_OK
    if not records:
        print("no receipts recorded")
    for index, record in enumerate(records):
        if index:
            print("")
        print(render_receipt(record.event, record.decision, record.flags, record.seq))
    return EXIT_OK


def cmd_receipts_digest(args: argparse.Namespace) -> int:
    context = Context(args)
    recorder = _recorder(context)
    events = recorder.events(actor=args.actor, since=args.since)
    print(render_digest(events, args.title, args.period or ""))
    return EXIT_OK


def cmd_receipts_html(args: argparse.Namespace) -> int:
    context = Context(args)
    recorder = _recorder(context)
    records = recorder.history(actor=args.actor, since=args.since, limit=args.limit)
    html = render_html(
        [{"event": r.event, "decision": r.decision, "flags": r.flags, "seq": r.seq}
         for r in records],
        args.title,
    )
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(html)
    print("wrote %s (%d receipt(s))" % (args.out, len(records)))
    return EXIT_OK


def cmd_receipts_check(args: argparse.Namespace) -> int:
    context = Context(args)
    policy = ConsentPolicy.load(context.workspace.consent_path)
    recorder = Recorder(context.ledger, policy)
    records = recorder.history()
    offenders = []
    for record in records:
        decision = policy.check(record.event)
        if not decision.allowed:
            offenders.append((record, decision))
    print("checked %d recorded access(es) against the current policy" % len(records))
    if not offenders:
        print("all of them are covered by a grant still in force.")
        return EXIT_OK
    print("%d would not be permitted today:" % len(offenders))
    for record, decision in offenders:
        print("")
        print(render_receipt(record.event, decision, record.flags, record.seq))
    print("")
    print("Note: this re-checks history against the policy as it stands now. An")
    print("access can appear here because a grant was later narrowed or expired,")
    print("which is not the same as it having been unauthorised at the time.")
    return EXIT_FAILED


def cmd_receipts_grants(args: argparse.Namespace) -> int:
    context = Context(args)
    policy = ConsentPolicy.load(context.workspace.consent_path)
    if context.json:
        context.emit([g.to_dict() for g in policy.grants])
        return EXIT_OK
    print("default: %s" % ("deny" if policy.default_deny else "allow"))
    for grant in policy.grants:
        print("")
        print("%s  (%s)" % (grant.id, grant.actor))
        print("  may %s" % (", ".join(grant.actions) or "anything"))
        print("  on  %s" % ", ".join(grant.resources))
        if grant.purposes:
            print("  for %s" % ", ".join(grant.purposes))
        if grant.data_classes:
            print("  data %s" % ", ".join(grant.data_classes))
        print("  egress %s" % (", ".join(grant.egress) or "none permitted"))
        if grant.max_items is not None:
            print("  limit %d items" % grant.max_items)
        if grant.expires:
            print("  expires %s" % grant.expires)
        if grant.note:
            print("  note: %s" % grant.note)
    return EXIT_OK


# -- registry ------------------------------------------------------------


def _registry(context: Context) -> Registry:
    return Registry(context.ledger, context.trust, context.workspace.cache_dir)


def cmd_registry_pack(args: argparse.Namespace) -> int:
    # Packing needs no workspace: it only hashes a directory.
    package = Package.from_dir(args.directory)
    problems = package.manifest.validate()
    out = args.out or "%s-%s.tar.gz" % (
        package.manifest.name.replace("/", "-").lstrip("@"), package.manifest.version
    )
    package.write_archive(out)
    print("%s" % package.manifest.spec)
    print("  digest  %s" % package.digest())
    print("  files   %d (%d bytes)" % (len(package.files), package.total_bytes()))
    print("  archive %s" % out)
    for problem in problems:
        print("  todo: %s" % problem)
    return EXIT_OK


def cmd_registry_publish(args: argparse.Namespace) -> int:
    context = Context(args)
    package = Package.from_dir(args.directory)
    try:
        entry = _registry(context).publish(package, sources=_split(args.source), key=context.key)
    except ForkDetected as exc:
        print("REFUSED: %s" % exc)
        return EXIT_UNTRUSTED
    print("published %s at entry #%d" % (package.manifest.spec, entry.seq))
    print("  digest %s" % package.digest())
    print("  signed by %s" % context.key.keyid)
    if not _split(args.source):
        print("  no source recorded; installers will need --from")
    return EXIT_OK


def cmd_registry_list(args: argparse.Namespace) -> int:
    context = Context(args)
    registry = _registry(context)
    publications = registry.publications(args.name, include_revoked=args.all)
    if context.json:
        context.emit([p.to_dict() for p in publications])
        return EXIT_OK
    if not publications:
        print("nothing published yet")
    for publication in publications:
        print(publication.describe())
    return EXIT_OK


def cmd_registry_show(args: argparse.Namespace) -> int:
    context = Context(args)
    publication = _registry(context).resolve(args.spec, require_trusted=False)
    manifest = publication.manifest
    if context.json:
        payload = publication.to_dict()
        payload["manifest"] = manifest.to_dict()
        payload["files"] = publication.files
        context.emit(payload)
        return EXIT_OK
    print("%s" % publication.spec)
    print("  %s" % manifest.description)
    print("  author     %s" % (manifest.author or "unstated"))
    print("  license    %s" % (manifest.license or "unstated"))
    print("  digest     %s" % publication.digest)
    print("  published  entry #%d at %s" % (publication.seq, publication.ts))
    print("  publisher  %s%s" % (
        publication.publisher or "unsigned",
        "" if publication.trusted else "  (NOT TRUSTED: %s)" % publication.trust_note,
    ))
    if publication.revoked:
        print("  REVOKED    %s" % publication.revoke_reason)
    if manifest.requires:
        print("  requires   %s" % ", ".join(manifest.requires))
    if publication.sources:
        print("  sources    %s" % ", ".join(publication.sources))
    print("  files      %d" % len(publication.files))
    for item in publication.files:
        print("    %-40s %s" % (item.get("path", ""), (item.get("digest") or "")[:12]))
    if manifest.tools:
        print("  declares tools: %s" % ", ".join(manifest.tools))
        print("  Inspect what they do before installing: the NTS files in the package")
        print("  declare effects such as network access and destructive writes.")
    return EXIT_OK


def cmd_registry_resolve(args: argparse.Namespace) -> int:
    context = Context(args)
    publication = _registry(context).resolve(args.spec, require_trusted=not args.allow_untrusted)
    context.emit(publication.to_dict(), "%s  %s" % (publication.spec, publication.digest))
    return EXIT_OK


def cmd_registry_install(args: argparse.Namespace) -> int:
    context = Context(args)
    publication, path = _registry(context).install(
        args.spec,
        source=args.source,
        destination=args.to or "",
        require_trusted=not args.allow_untrusted,
        key=context.key,
    )
    print("installed %s" % publication.spec)
    print("  digest verified against the ledger: %s" % publication.digest[:16])
    print("  path   %s" % path)
    if not publication.trusted:
        print("  WARNING: published by an untrusted key (%s)" % publication.trust_note)
    return EXIT_OK


def cmd_registry_revoke(args: argparse.Namespace) -> int:
    context = Context(args)
    entry = _registry(context).revoke(args.spec, args.reason, key=context.key)
    print("revoked %s at entry #%d" % (entry.subject, entry.seq))
    print("The original publication stays in the chain; it just stops resolving.")
    return EXIT_OK


def cmd_registry_verify(args: argparse.Namespace) -> int:
    context = Context(args)
    registry = _registry(context)
    publication = registry.resolve(args.spec, require_trusted=False)
    ok, detail = registry.verify_installed(args.path, publication)
    print("%s: %s" % ("OK" if ok else "MISMATCH", detail))
    return EXIT_OK if ok else EXIT_UNTRUSTED


def cmd_registry_conflicts(args: argparse.Namespace) -> int:
    context = Context(args)
    conflicts = _registry(context).conflicts()
    if not conflicts:
        print("no conflicting publications")
        return EXIT_OK
    for conflict in conflicts:
        print(conflict.format())
        print("")
    print("The same version exists with different content. Nothing can decide this")
    print("automatically -- trust only the publisher you meant to trust.")
    return EXIT_UNTRUSTED


def cmd_registry_remote(args: argparse.Namespace) -> int:
    context = Context(args)
    remotes = Remotes.load(context.workspace.remotes_path)
    if args.action == "list":
        print(remotes.describe())
    elif args.action == "add":
        if not args.name or not args.url:
            raise AttestryError("give a name and a location")
        remotes.add(args.name, args.url)
        print("added remote %s -> %s" % (args.name, args.url))
    elif args.action == "remove":
        print("removed %s" % args.name if remotes.remove(args.name) else "no such remote")
    return EXIT_OK


# -- argument parsing ----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attestry",
        description=(
            "Verifiable trust infrastructure for AI agents: model-drift detection, "
            "tool-schema translation, consent receipts and a serverless skill "
            "registry, all recorded in one signed append-only ledger."
        ),
        epilog="Exit codes: 0 fine, 1 moved, 2 failed, 3 could not run, 4 untrustworthy.",
    )
    parser.add_argument("--version", action="version", version="attestry %s" % __version__)
    parser.add_argument("-C", "--directory", help="act as if run from this directory")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--key", help="key id to sign with (default: the workspace key)")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # init / doctor
    init = subparsers.add_parser("init", help="create a workspace here")
    init.add_argument("directory", nargs="?", help="where to create it (default: here)")
    init.add_argument("--label", default="default", help="label for the new signing key")
    init.add_argument("--trust-mode", default="tofu", choices=("strict", "tofu", "open"))
    init.add_argument("--bare", action="store_true", help="skip the example suite and policy")
    init.set_defaults(func=cmd_init, needs_workspace=False)

    doctor = subparsers.add_parser("doctor", help="show how everything is wired up")
    doctor.set_defaults(func=cmd_doctor, needs_workspace=False)

    _add_ledger(subparsers)
    _add_drift(subparsers)
    _add_schema(subparsers)
    _add_receipts(subparsers)
    _add_registry(subparsers)
    return parser


def _add_ledger(subparsers: Any) -> None:
    ledger = subparsers.add_parser("ledger", help="the signed append-only log")
    sub = ledger.add_subparsers(dest="subcommand", metavar="<action>")

    log = sub.add_parser("log", help="list entries")
    log.add_argument("--kind", help="filter by kind or namespace, e.g. receipt")
    log.add_argument("--subject", help="substring match on the subject")
    log.add_argument("--since", help="RFC 3339 lower bound")
    log.add_argument("--limit", type=int, help="show only the last N")
    log.set_defaults(func=cmd_ledger_log)

    verify = sub.add_parser("verify", help="check hashes, links, signatures and trust")
    verify.add_argument("--require-signatures", action="store_true",
                        help="treat an unsigned entry as an error rather than a warning")
    verify.set_defaults(func=cmd_ledger_verify)

    checkpoint = sub.add_parser("checkpoint", help="record a Merkle root over the log so far")
    checkpoint.set_defaults(func=cmd_ledger_checkpoint)

    prove = sub.add_parser("prove", help="produce or check an inclusion proof")
    prove.add_argument("seq", nargs="?", type=int, help="entry to prove")
    prove.add_argument("--out", help="write the proof here")
    prove.add_argument("--check", help="verify a proof file instead")
    prove.set_defaults(func=cmd_ledger_prove)

    export = sub.add_parser("export", help="copy the ledger out for others to sync")
    export.add_argument("out")
    export.set_defaults(func=cmd_ledger_export)

    sync = sub.add_parser("sync", help="fast-forward from another ledger")
    sync.add_argument("source", help="a remote name, path or URL")
    sync.set_defaults(func=cmd_ledger_sync)

    keys = sub.add_parser("keys", help="list or create signing keys")
    keys.add_argument("--new", metavar="LABEL", help="create a key with this label")
    keys.set_defaults(func=cmd_ledger_keys)

    trust = sub.add_parser("trust", help="manage which keys you accept")
    trust.add_argument("action", choices=("list", "add", "remove", "mode"))
    trust.add_argument("value", nargs="?", help="public key hex, key id, or mode")
    trust.add_argument("--label", help="label for a key being added")
    trust.set_defaults(func=cmd_ledger_trust)

    revoke = sub.add_parser("revoke", help="revoke a signing key")
    revoke.add_argument("keyid")
    revoke.add_argument("--reason", required=True)
    revoke.add_argument("--invalidates", choices=("after", "all"), required=True,
                        help="'after' for routine rotation, 'all' if the key leaked")
    revoke.set_defaults(func=cmd_ledger_revoke)

    stats = sub.add_parser("stats", help="entry counts by namespace")
    stats.set_defaults(func=cmd_ledger_stats)


def _add_drift(subparsers: Any) -> None:
    drift = subparsers.add_parser("drift", help="detect when model behaviour moves")
    sub = drift.add_subparsers(dest="subcommand", metavar="<action>")

    init = sub.add_parser("init", help="write a starter suite")
    init.add_argument("name", nargs="?", default="example")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_drift_init)

    listing = sub.add_parser("list", help="list suites")
    listing.set_defaults(func=cmd_drift_list)

    run = sub.add_parser("run", help="run a suite and compare against the baseline")
    run.add_argument("name")
    run.add_argument("--provider", choices=("echo", "ollama", "openai", "anthropic"))
    run.add_argument("--model")
    run.add_argument("--case", help="comma-separated case ids to run")
    run.add_argument("--pin", action="store_true", help="accept these outputs as the new baseline")
    run.add_argument("--no-pin-new", action="store_true",
                     help="do not create a baseline when none exists yet")
    run.add_argument("--diff", action="store_true", help="show output diffs for moved cases")
    run.add_argument("--markdown", action="store_true", help="report as markdown")
    run.add_argument("--no-record", action="store_true", help="do not write to the ledger")
    run.add_argument("--force", action="store_true", help="run even if the suite has problems")
    run.set_defaults(func=cmd_drift_run)

    baseline = sub.add_parser("baseline", help="pin current behaviour as the reference")
    baseline.add_argument("name")
    baseline.add_argument("--provider")
    baseline.add_argument("--model")
    baseline.add_argument("--force", action="store_true")
    baseline.set_defaults(func=cmd_drift_baseline)

    history = sub.add_parser("history", help="past runs of a suite")
    history.add_argument("name")
    history.add_argument("--limit", type=int, default=20)
    history.set_defaults(func=cmd_drift_history)

    show = sub.add_parser("show", help="one case's output digest over time")
    show.add_argument("name")
    show.add_argument("case")
    show.set_defaults(func=cmd_drift_show)


def _add_schema(subparsers: Any) -> None:
    schema = subparsers.add_parser("schema", help="one tool definition, every framework")
    sub = schema.add_subparsers(dest="subcommand", metavar="<action>")

    new = sub.add_parser("new", help="create a schema skeleton")
    new.add_argument("name")
    new.add_argument("--description")
    new.set_defaults(func=cmd_schema_new)

    listing = sub.add_parser("list", help="list schemas")
    listing.set_defaults(func=cmd_schema_list)

    validate = sub.add_parser("validate", help="check schemas for problems")
    validate.add_argument("name", nargs="?")
    validate.set_defaults(func=cmd_schema_validate)

    emit = sub.add_parser("emit", help="translate a schema to a target framework")
    emit.add_argument("name")
    emit.add_argument("--target", default="mcp", choices=sorted(TARGETS))
    emit.add_argument("--all", action="store_true", help="emit every target")
    emit.add_argument("--out", help="write files into this directory")
    emit.add_argument("--strict", action="store_true", help="OpenAI structured-outputs mode")
    emit.add_argument("--style", default="chat", choices=("chat", "responses"))
    emit.set_defaults(func=cmd_schema_emit)

    ingest = sub.add_parser("ingest", help="import tools from another framework's JSON")
    ingest.add_argument("file")
    ingest.add_argument("--name", help="override the imported name")
    ingest.set_defaults(func=cmd_schema_ingest)

    from_python = sub.add_parser("from-python", help="derive a schema from a Python function")
    from_python.add_argument("target_ref", metavar="module:function")
    from_python.add_argument("--name")
    from_python.set_defaults(func=cmd_schema_from_python)

    diff = sub.add_parser("diff", help="compare two schemas")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_schema_diff)

    register = sub.add_parser("register", help="record schemas in the ledger and report changes")
    register.add_argument("name", nargs="?")
    register.set_defaults(func=cmd_schema_register)

    history = sub.add_parser("history", help="how a tool's interface has changed")
    history.add_argument("name")
    history.set_defaults(func=cmd_schema_history)


def _add_receipts(subparsers: Any) -> None:
    receipts = subparsers.add_parser("receipts", help="plain-English consent receipts")
    sub = receipts.add_subparsers(dest="subcommand", metavar="<action>")

    init = sub.add_parser("init", help="write a starter consent policy")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_receipts_init)

    record = sub.add_parser("record", help="record one access")
    record.add_argument("--actor", required=True, help="e.g. agent:inbox-triage")
    record.add_argument("--action", required=True,
                        choices=("read", "list", "search", "write", "update",
                                 "send", "delete", "share", "execute"))
    record.add_argument("--resource", required=True, help="e.g. email:gmail/INBOX")
    record.add_argument("--purpose", help="why, in plain words")
    record.add_argument("--items", type=int, default=0)
    record.add_argument("--fields", help="comma-separated field names touched")
    record.add_argument("--data-classes", dest="data_classes", help="comma-separated")
    record.add_argument("--egress", help="comma-separated destinations data was sent to")
    record.add_argument("--selector", help="what range or subset, e.g. '1-25 Sep'")
    record.add_argument("--outcome", default="ok", choices=("ok", "partial", "denied", "error"))
    record.add_argument("--tool", help="the tool used")
    record.add_argument("--detail")
    record.set_defaults(func=cmd_receipts_record)

    listing = sub.add_parser("list", help="show receipts in plain English")
    listing.add_argument("--actor")
    listing.add_argument("--resource")
    listing.add_argument("--since")
    listing.add_argument("--limit", type=int)
    listing.set_defaults(func=cmd_receipts_list)

    digest = sub.add_parser("digest", help="a grouped summary")
    digest.add_argument("--actor")
    digest.add_argument("--since")
    digest.add_argument("--period", help="label for the period, e.g. 'last week'")
    digest.add_argument("--title", default="What your agents did")
    digest.set_defaults(func=cmd_receipts_digest)

    html = sub.add_parser("html", help="write a self-contained HTML receipt page")
    html.add_argument("--out", default="receipts.html")
    html.add_argument("--actor")
    html.add_argument("--since")
    html.add_argument("--limit", type=int)
    html.add_argument("--title", default="Access receipts")
    html.set_defaults(func=cmd_receipts_html)

    check = sub.add_parser("check", help="re-check recorded history against today's policy")
    check.set_defaults(func=cmd_receipts_check)

    grants = sub.add_parser("grants", help="show the consent grants in force")
    grants.set_defaults(func=cmd_receipts_grants)


def _add_registry(subparsers: Any) -> None:
    registry = subparsers.add_parser("registry", help="serverless, verifiable skill registry")
    sub = registry.add_subparsers(dest="subcommand", metavar="<action>")

    pack = sub.add_parser("pack", help="build a content-addressed archive")
    pack.add_argument("directory")
    pack.add_argument("--out")
    pack.set_defaults(func=cmd_registry_pack, needs_workspace=False)

    publish = sub.add_parser("publish", help="record a version in the ledger")
    publish.add_argument("directory")
    publish.add_argument("--source", help="comma-separated locations installers can fetch from")
    publish.set_defaults(func=cmd_registry_publish)

    listing = sub.add_parser("list", help="list published packages")
    listing.add_argument("name", nargs="?")
    listing.add_argument("--all", action="store_true", help="include revoked versions")
    listing.set_defaults(func=cmd_registry_list)

    show = sub.add_parser("show", help="everything recorded about one version")
    show.add_argument("spec")
    show.set_defaults(func=cmd_registry_show)

    resolve = sub.add_parser("resolve", help="find the best version matching a spec")
    resolve.add_argument("spec")
    resolve.add_argument("--allow-untrusted", action="store_true")
    resolve.set_defaults(func=cmd_registry_resolve)

    install = sub.add_parser("install", help="fetch, verify and unpack a package")
    install.add_argument("spec")
    install.add_argument("--from", dest="source", help="override the recorded source")
    install.add_argument("--to", help="install here instead of the cache")
    install.add_argument("--allow-untrusted", action="store_true")
    install.set_defaults(func=cmd_registry_install)

    revoke = sub.add_parser("revoke", help="withdraw a published version")
    revoke.add_argument("spec")
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(func=cmd_registry_revoke)

    verify = sub.add_parser("verify", help="re-hash an installed package")
    verify.add_argument("path")
    verify.add_argument("spec")
    verify.set_defaults(func=cmd_registry_verify)

    conflicts = sub.add_parser("conflicts", help="versions published twice with different content")
    conflicts.set_defaults(func=cmd_registry_conflicts)

    remote = sub.add_parser("remote", help="manage ledgers to sync with")
    remote.add_argument("action", choices=("list", "add", "remove"))
    remote.add_argument("name", nargs="?")
    remote.add_argument("url", nargs="?")
    remote.set_defaults(func=cmd_registry_remote)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        # A bare group like "attestry drift" should show that group's help, not
        # the top-level help, which is what argparse does by default.
        if getattr(args, "command", None):
            for action in parser._subparsers._group_actions:  # noqa: SLF001
                choices = getattr(action, "choices", {}) or {}
                if args.command in choices:
                    choices[args.command].print_help()
                    return EXIT_CANNOT_RUN
        parser.print_help()
        return EXIT_CANNOT_RUN
    try:
        return args.func(args)
    except (TrustError, IntegrityError, ForkDetected) as exc:
        print("attestry: %s" % exc, file=sys.stderr)
        return EXIT_UNTRUSTED
    except AttestryError as exc:
        print("attestry: %s" % exc, file=sys.stderr)
        return EXIT_CANNOT_RUN
    except BrokenPipeError:
        return EXIT_OK
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_CANNOT_RUN


if __name__ == "__main__":
    sys.exit(main())
