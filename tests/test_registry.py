"""The registry: content addressing, immutability, verification, syncing."""

from __future__ import annotations

import json
import os
import shutil
import unittest

from attestry.ledger import Keyring, Ledger, TrustStore
from attestry.registry import (
    Manifest,
    Package,
    Registry,
    Remotes,
    check_incoming,
    export_ledger,
    parse_ledger_text,
    parse_spec,
    sync,
    version_key,
)
from attestry.util.errors import (
    AttestryError,
    ForkDetected,
    IntegrityError,
    SchemaError,
    TrustError,
)
from attestry.workspace import Workspace

from .support import WorkspaceCase

MANIFEST = {
    "name": "hello-web",
    "version": "1.0.0",
    "description": "Fetch a URL and return its readable text.",
    "author": "Nulfied",
    "license": "MIT",
    "entry": "skill.py",
}


class SpecTests(unittest.TestCase):
    def test_parse_spec(self) -> None:
        self.assertEqual(parse_spec("a"), ("a", "latest"))
        self.assertEqual(parse_spec("a@1.2.3"), ("a", "1.2.3"))
        self.assertEqual(parse_spec("@scope/a@^1.0.0"), ("@scope/a", "^1.0.0"))

    def test_bad_spec_is_rejected(self) -> None:
        for spec in ("A", "has spaces", ""):
            with self.assertRaises(AttestryError):
                parse_spec(spec)

    def test_version_ordering_puts_prereleases_first(self) -> None:
        ordered = sorted(["2.0.0", "1.9.9", "2.0.0-rc.1", "2.0.0-rc.2"], key=version_key)
        self.assertEqual(ordered, ["1.9.9", "2.0.0-rc.1", "2.0.0-rc.2", "2.0.0"])

    def test_numeric_prerelease_parts_sort_numerically(self) -> None:
        ordered = sorted(["1.0.0-rc.10", "1.0.0-rc.2"], key=version_key)
        self.assertEqual(ordered, ["1.0.0-rc.2", "1.0.0-rc.10"])


class ManifestTests(unittest.TestCase):
    def test_valid_manifest(self) -> None:
        self.assertEqual(Manifest.from_dict(MANIFEST).validate(), [])

    def test_bad_name_and_version_are_reported(self) -> None:
        bad = dict(MANIFEST, name="Hello Web", version="1.0")
        problems = Manifest.from_dict(bad).validate()
        self.assertEqual(len(problems), 2)

    def test_scoped_names_are_allowed(self) -> None:
        self.assertEqual(Manifest.from_dict(dict(MANIFEST, name="@nulfied/tool")).validate(), [])

    def test_missing_fields_are_fatal(self) -> None:
        with self.assertRaises(SchemaError):
            Manifest.from_dict({"name": "a"})

    def test_unknown_fields_are_preserved(self) -> None:
        manifest = Manifest.from_dict(dict(MANIFEST, custom={"a": 1}))
        self.assertEqual(manifest.to_dict()["custom"], {"a": 1})


class PackageCase(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.mkdtemp(prefix="attestry-pkg-")
        self.source = os.path.join(self.tmp, "hello-web")
        os.makedirs(self.source)
        self.write("skill.json", json.dumps(MANIFEST, indent=2))
        self.write("skill.py", "def fetch_page(url):\n    return url\n")
        self.write("README.md", "# hello-web\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, relative: str, content: str) -> str:
        path = os.path.join(self.source, *relative.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path


class PackageTests(PackageCase):
    def test_digest_is_reproducible_across_locations(self) -> None:
        one = Package.from_dir(self.source)
        elsewhere = os.path.join(self.tmp, "copy")
        shutil.copytree(self.source, elsewhere)
        self.assertEqual(Package.from_dir(elsewhere).digest(), one.digest())

    def test_archive_bytes_are_deterministic(self) -> None:
        package = Package.from_dir(self.source)
        self.assertEqual(package.to_archive_bytes(), package.to_archive_bytes())

    def test_digest_survives_an_archive_round_trip(self) -> None:
        package = Package.from_dir(self.source)
        recovered = Package.from_archive_bytes(package.to_archive_bytes())
        self.assertEqual(recovered.digest(), package.digest())
        self.assertEqual(recovered.manifest.spec, package.manifest.spec)

    def test_changing_content_changes_the_digest(self) -> None:
        before = Package.from_dir(self.source).digest()
        self.write("skill.py", "def fetch_page(url):\n    return 'changed'\n")
        self.assertNotEqual(Package.from_dir(self.source).digest(), before)

    def test_renaming_a_file_changes_the_digest(self) -> None:
        """The path is part of the leaf, not just the bytes."""
        before = Package.from_dir(self.source).digest()
        os.rename(os.path.join(self.source, "README.md"),
                  os.path.join(self.source, "READ.md"))
        self.assertNotEqual(Package.from_dir(self.source).digest(), before)

    def test_ignored_paths_do_not_affect_the_digest(self) -> None:
        before = Package.from_dir(self.source).digest()
        os.makedirs(os.path.join(self.source, "__pycache__"))
        self.write("__pycache__/x.pyc", "junk")
        self.write(".attestryignore", "notes.txt\n")
        self.write("notes.txt", "scratch")
        self.assertEqual(Package.from_dir(self.source).digest(), before)

    def test_missing_manifest_is_refused(self) -> None:
        os.remove(os.path.join(self.source, "skill.json"))
        with self.assertRaises(AttestryError):
            Package.from_dir(self.source)

    def test_invalid_manifest_json_is_refused(self) -> None:
        self.write("skill.json", "{not json")
        with self.assertRaises(SchemaError):
            Package.from_dir(self.source)

    def test_symlinks_are_refused(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("no symlink support")
        try:
            os.symlink(os.path.join(self.source, "skill.py"),
                       os.path.join(self.source, "link.py"))
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        with self.assertRaises(AttestryError):
            Package.from_dir(self.source)

    def test_inclusion_proof_for_one_file(self) -> None:
        package = Package.from_dir(self.source)
        proof = package.inclusion_proof("skill.py")
        self.assertTrue(Package.verify_inclusion(proof, package.files["skill.py"]))
        self.assertFalse(Package.verify_inclusion(proof, b"different bytes"))

    def test_inclusion_proof_for_a_missing_file_raises(self) -> None:
        with self.assertRaises(KeyError):
            Package.from_dir(self.source).inclusion_proof("nope.py")

    def test_path_traversal_in_an_archive_is_refused(self) -> None:
        """A member named ../../evil must never be written."""
        import io
        import tarfile

        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as archive:
            for name, content in (
                ("skill.json", json.dumps(MANIFEST).encode()),
                ("../../evil.py", b"pwned"),
            ):
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        with self.assertRaises(IntegrityError):
            Package.from_archive_bytes(raw.getvalue())

    def test_archive_without_a_manifest_is_refused(self) -> None:
        import io
        import tarfile

        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as archive:
            info = tarfile.TarInfo(name="x.py")
            info.size = 3
            archive.addfile(info, io.BytesIO(b"abc"))
        with self.assertRaises(IntegrityError):
            Package.from_archive_bytes(raw.getvalue())


class RegistryTests(WorkspaceCase, PackageCase):
    def setUp(self) -> None:
        WorkspaceCase.setUp(self)
        PackageCase.setUp(self)
        self.registry = Registry(self.ledger, self.trust, self.workspace.cache_dir)
        self.package = Package.from_dir(self.source)
        self.archive = os.path.join(self.tmp, "hello-web-1.0.0.tar.gz")
        self.package.write_archive(self.archive)

    def tearDown(self) -> None:
        PackageCase.tearDown(self)
        WorkspaceCase.tearDown(self)

    def test_publish_and_list(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        publications = self.registry.publications()
        self.assertEqual(len(publications), 1)
        self.assertEqual(publications[0].digest, self.package.digest())
        self.assertEqual(publications[0].publisher, self.key.keyid)

    def test_publishing_the_same_content_twice_is_refused(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        with self.assertRaises(AttestryError):
            self.registry.publish(self.package, sources=[self.archive])

    def test_republishing_a_version_with_different_content_is_refused(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        self.write("skill.py", "def fetch_page(url):\n    return 'swapped'\n")
        with self.assertRaises(ForkDetected):
            self.registry.publish(Package.from_dir(self.source))

    def test_a_new_version_is_fine(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        self.write("skill.json", json.dumps(dict(MANIFEST, version="1.1.0")))
        self.registry.publish(Package.from_dir(self.source))
        self.assertEqual(len(self.registry.publications()), 2)

    def test_an_invalid_manifest_cannot_be_published(self) -> None:
        self.write("skill.json", json.dumps({"name": "x", "version": "1.0.0"}))
        with self.assertRaises(AttestryError):
            self.registry.publish(Package.from_dir(self.source))

    def test_resolve_ranges(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        self.write("skill.json", json.dumps(dict(MANIFEST, version="1.2.0")))
        self.registry.publish(Package.from_dir(self.source))
        self.assertEqual(self.registry.resolve("hello-web").version, "1.2.0")
        self.assertEqual(self.registry.resolve("hello-web@1.0.0").version, "1.0.0")
        self.assertEqual(self.registry.resolve("hello-web@^1.0.0").version, "1.2.0")
        self.assertEqual(self.registry.resolve("hello-web@~1.0.0").version, "1.0.0")

    def test_resolve_errors_are_specific(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        with self.assertRaises(AttestryError) as unknown:
            self.registry.resolve("nope")
        self.assertIn("nothing published under the name", str(unknown.exception))
        with self.assertRaises(AttestryError) as no_version:
            self.registry.resolve("hello-web@9.0.0")
        self.assertIn("available", str(no_version.exception))

    def test_untrusted_publisher_is_refused(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        strict = TrustStore(self.path("strict.json"), mode="strict")
        registry = Registry(self.ledger, strict, self.workspace.cache_dir)
        with self.assertRaises(TrustError):
            registry.resolve("hello-web")
        self.assertEqual(registry.resolve("hello-web", require_trusted=False).version, "1.0.0")

    def test_install_verifies_and_unpacks(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        publication, path = self.registry.install("hello-web@^1.0.0")
        self.assertTrue(os.path.exists(os.path.join(path, "skill.py")))
        self.assertEqual(self.registry.verify_installed(path, publication)[0], True)
        self.assertEqual(len(self.ledger.select(kind="registry.install")), 1)

    def test_install_refuses_an_altered_archive(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        self.write("skill.py", "def fetch_page(url):\n    return 'evil'\n")
        bad = os.path.join(self.tmp, "bad.tar.gz")
        Package.from_dir(self.source).write_archive(bad)
        destination = os.path.join(self.tmp, "installed")
        with self.assertRaises(IntegrityError):
            self.registry.install("hello-web@1.0.0", source=bad, destination=destination)
        self.assertFalse(os.path.exists(os.path.join(destination, "skill.py")))

    def test_install_without_a_source_explains_itself(self) -> None:
        self.registry.publish(self.package)
        with self.assertRaises(AttestryError) as caught:
            self.registry.install("hello-web@1.0.0")
        self.assertIn("--from", str(caught.exception))

    def test_editing_an_installed_package_is_detected(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        publication, path = self.registry.install("hello-web@1.0.0")
        with open(os.path.join(path, "skill.py"), "a", encoding="utf-8") as handle:
            handle.write("\n# sneaky\n")
        ok, detail = self.registry.verify_installed(path, publication)
        self.assertFalse(ok)
        self.assertIn("ledger says", detail)

    def test_revoked_versions_stop_resolving_but_stay_in_the_chain(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        self.registry.revoke("hello-web@1.0.0", "leaked a key")
        self.assertEqual(self.registry.publications(), [])
        with self.assertRaises(AttestryError):
            self.registry.resolve("hello-web")
        self.assertEqual(len(self.registry.publications(include_revoked=True)), 1)
        self.assertEqual(len(self.ledger.select(kind="registry.publish")), 1)

    def test_conflicts_are_reported(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        # Simulate a second publisher claiming the same version, as would arrive
        # through a sync from somebody else's ledger.
        other = Keyring(self.workspace.keys_dir).create("other")
        self.ledger.announce_key(other)
        self.ledger.append(
            "registry.publish", "hello-web@1.0.0",
            {"name": "hello-web", "version": "1.0.0", "digest": "ff" * 32,
             "manifest": MANIFEST},
            key=other,
        )
        conflicts = self.registry.conflicts()
        self.assertEqual(len(conflicts), 1)
        self.assertIn("hello-web@1.0.0", conflicts[0].format())

    def test_names_lists_published_packages(self) -> None:
        self.registry.publish(self.package, sources=[self.archive])
        self.assertEqual(self.registry.names(), ["hello-web"])


class SyncTests(WorkspaceCase):
    def test_sync_fast_forwards_then_is_idempotent(self) -> None:
        self.ledger.append("drift.run", "a", {})
        shared = self.path("shared.jsonl")
        export_ledger(self.ledger, shared)

        other = Workspace.init(self.path("other"))
        trust = TrustStore(other.trust_path, mode="tofu")
        mirror = Ledger(other.ledger_path, trust=trust)
        result, problems = sync(mirror, shared, trust)
        self.assertEqual(result.added, 2)
        self.assertEqual(problems, [])
        self.assertEqual(sync(mirror, shared, trust)[0].added, 0)
        self.assertTrue(mirror.verify().ok)

    def test_sync_refuses_a_fork(self) -> None:
        shared = self.path("shared.jsonl")
        export_ledger(self.ledger, shared)
        other = Workspace.init(self.path("other"))
        trust = TrustStore(other.trust_path, mode="tofu")
        mirror = Ledger(other.ledger_path, key=self.key, trust=trust)
        sync(mirror, shared, trust)
        mirror.append("drift.run", "theirs", {})
        self.ledger.append("drift.run", "ours", {})
        export_ledger(self.ledger, shared)
        with self.assertRaises(ForkDetected):
            sync(mirror, shared, trust)

    def test_a_tampered_incoming_ledger_is_refused_entirely(self) -> None:
        self.ledger.append("drift.run", "a", {})
        shared = self.path("shared.jsonl")
        export_ledger(self.ledger, shared)
        with open(shared, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        doc = json.loads(lines[1])
        doc["body"]["label"] = "hacked"
        lines[1] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        with open(shared, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

        other = Workspace.init(self.path("other"))
        trust = TrustStore(other.trust_path, mode="tofu")
        mirror = Ledger(other.ledger_path, trust=trust)
        with self.assertRaises(IntegrityError):
            sync(mirror, shared, trust)
        self.assertEqual(len(mirror.entries(refresh=True)), 0)

    def test_check_incoming_finds_edits(self) -> None:
        self.ledger.append("drift.run", "a", {})
        with open(self.workspace.ledger_path, encoding="utf-8") as handle:
            entries = parse_ledger_text(handle.read())
        self.assertEqual(check_incoming(entries, self.trust), [])

    def test_parse_ledger_text_rejects_rubbish(self) -> None:
        with self.assertRaises(IntegrityError):
            parse_ledger_text("not an entry\n")

    def test_remotes_round_trip(self) -> None:
        remotes = Remotes.load(self.workspace.remotes_path)
        remotes.add("upstream", "https://example.com/ledger.jsonl")
        again = Remotes.load(self.workspace.remotes_path)
        self.assertEqual(again.url("upstream"), "https://example.com/ledger.jsonl")
        self.assertEqual(again.url("./local.jsonl"), "./local.jsonl")
        self.assertTrue(again.remove("upstream"))
        self.assertFalse(again.remove("upstream"))


if __name__ == "__main__":
    unittest.main()
