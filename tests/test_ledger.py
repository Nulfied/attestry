"""The chain: appending, tamper detection, trust, checkpoints, merging."""

from __future__ import annotations

import json
import os
import unittest

from attestry.ledger import Entry, Keyring, Ledger, TrustStore
from attestry.util.canonical import ZERO_DIGEST
from attestry.util.errors import ForkDetected, IntegrityError
from attestry.workspace import Workspace

from .support import WorkspaceCase


class EntryTests(unittest.TestCase):
    def make(self, **overrides) -> Entry:
        fields = dict(
            seq=0, ts="2026-09-25T00:00:00Z", kind="drift.run",
            subject="s", body={"a": 1},
        )
        fields.update(overrides)
        return Entry(**fields)

    def test_sealed_hash_matches_content(self) -> None:
        entry = self.make().sealed()
        self.assertTrue(entry.hash_matches())

    def test_entries_are_immutable(self) -> None:
        entry = self.make().sealed()
        with self.assertRaises(AttributeError):
            entry.seq = 5

    def test_round_trip_through_dict(self) -> None:
        entry = self.make().sealed()
        self.assertEqual(Entry.from_dict(entry.to_dict()), entry)

    def test_hash_excludes_the_hash_and_signature_fields(self) -> None:
        plain = self.make().sealed()
        signed = plain.signed("ed25519:aaaa:bbbb")
        self.assertEqual(plain.hash, signed.hash)

    def test_bad_kind_is_rejected(self) -> None:
        for kind in ("Drift.Run", "drift", "drift run", "", "drift..run"):
            with self.assertRaises(ValueError):
                self.make(kind=kind)

    def test_body_must_be_a_mapping(self) -> None:
        with self.assertRaises(TypeError):
            self.make(body=[1, 2])

    def test_changing_any_byte_changes_the_hash(self) -> None:
        base = self.make().sealed()
        for change in ({"seq": 1}, {"ts": "2026-09-26T00:00:00Z"},
                       {"subject": "t"}, {"body": {"a": 2}}):
            self.assertNotEqual(base.hash, self.make(**change).sealed().hash)


class LedgerTests(WorkspaceCase):
    def test_append_chains_and_verifies(self) -> None:
        self.ledger.append("drift.run", "a", {"n": 1})
        self.ledger.append("receipt.access", "b", {"n": 2})
        result = self.ledger.verify()
        self.assertTrue(result.ok, result.format())
        self.assertEqual(result.entries, 3)
        self.assertEqual(result.signed, 3)

    def test_genesis_prev_is_zero_and_links_are_correct(self) -> None:
        self.ledger.append("drift.run", "a", {})
        entries = self.ledger.entries()
        self.assertEqual(entries[0].prev, ZERO_DIGEST)
        for previous, entry in zip(entries, entries[1:]):
            self.assertEqual(entry.prev, previous.hash)

    def test_editing_an_entry_is_detected(self) -> None:
        self.ledger.append("drift.run", "a", {"n": 1})
        self._rewrite_line(1, lambda doc: doc["body"].update({"n": 99}))
        result = Ledger(self.workspace.ledger_path, trust=self.trust).verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_seq, 1)
        self.assertIn("hash-mismatch", [p.code for p in result.errors])

    def test_editing_and_rehashing_breaks_the_next_link(self) -> None:
        """The attacker who knows to recompute the hash still cannot hide."""
        self.ledger.append("drift.run", "a", {"n": 1})
        self.ledger.append("drift.run", "b", {"n": 2})

        def rehash(doc):
            doc["body"]["n"] = 99
            doc.pop("sig", None)
            doc["hash"] = Entry.from_dict(doc).compute_hash()

        self._rewrite_line(1, rehash)
        result = Ledger(self.workspace.ledger_path, trust=self.trust).verify()
        self.assertFalse(result.ok)
        self.assertIn("broken-link", [p.code for p in result.errors])

    def test_signature_failure_is_reported(self) -> None:
        self.ledger.append("drift.run", "a", {"n": 1})
        self._rewrite_line(1, lambda doc: doc.update({"body": {"n": 2}, "hash": None}))
        # Recompute the hash so only the signature is wrong.
        lines = self._lines()
        doc = json.loads(lines[1])
        doc["hash"] = Entry.from_dict({**doc, "hash": ZERO_DIGEST}).compute_hash()
        lines[1] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        self._write(lines)
        result = Ledger(self.workspace.ledger_path, trust=self.trust).verify()
        self.assertFalse(result.ok)
        self.assertIn("bad-signature", [p.code for p in result.errors])

    def test_unsigned_entry_is_a_warning_by_default_and_an_error_on_request(self) -> None:
        unsigned = Ledger(self.workspace.ledger_path, key=None, trust=self.trust)
        unsigned.append("drift.run", "a", {})
        self.assertTrue(unsigned.verify().ok)
        self.assertFalse(unsigned.verify(require_signatures=True).ok)

    def test_strict_trust_rejects_a_signer_you_did_not_authorise(self) -> None:
        """The signature verifies; the key is simply not one you accepted."""
        other = Keyring(self.workspace.keys_dir).create("outsider")
        self.ledger.announce_key(other)  # the key material is in the ledger
        self.ledger.append("drift.run", "a", {}, key=other)
        strict = TrustStore(self.path("strict.json"), mode="strict")
        strict.add(self.key.public, "test")
        result = Ledger(self.workspace.ledger_path, trust=strict).verify()
        self.assertFalse(result.ok)
        self.assertIn("untrusted-key", [p.code for p in result.errors])

    def test_signer_whose_key_is_nowhere_is_reported_separately(self) -> None:
        """An unannounced key cannot be checked at all, which is a distinct fault."""
        other = Keyring(self.workspace.keys_dir).create("ghost")
        self.ledger.append("drift.run", "a", {}, key=other)
        strict = TrustStore(self.path("strict.json"), mode="strict")
        strict.add(self.key.public, "test")
        result = Ledger(self.workspace.ledger_path, trust=strict).verify()
        self.assertFalse(result.ok)
        self.assertIn("unknown-key", [p.code for p in result.errors])

    def test_revoked_key_invalidating_all_rejects_earlier_signatures(self) -> None:
        self.ledger.append("drift.run", "a", {})
        self.trust.revoke(self.key.keyid, "leaked", invalidates="all")
        result = self.ledger.verify()
        self.assertFalse(result.ok)
        self.assertIn("untrusted-key", [p.code for p in result.errors])

    def test_revoked_key_invalidating_after_keeps_earlier_signatures(self) -> None:
        self.ledger.append("drift.run", "a", {}, ts="2020-01-01T00:00:00Z")
        self.trust.revoke(self.key.keyid, "rotated", invalidates="after")
        self.assertTrue(self.ledger.verify().ok)

    def test_tofu_pins_a_key_and_rejects_a_later_substitution(self) -> None:
        store = TrustStore(self.path("tofu.json"), mode="tofu")
        ok, _ = store.check("abcd", "aa" * 32)
        self.assertTrue(ok)
        ok, reason = store.check(list(store.keys)[0], "bb" * 32)
        self.assertFalse(ok)
        self.assertIn("pinned", reason)

    def test_torn_final_line_is_recovered(self) -> None:
        self.ledger.append("drift.run", "a", {})
        with open(self.workspace.ledger_path, "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "kind": "drift.r')
        self.assertEqual(len(Ledger(self.workspace.ledger_path).entries()), 2)

    def test_corrupt_middle_line_is_fatal(self) -> None:
        self.ledger.append("drift.run", "a", {})
        self.ledger.append("drift.run", "b", {})
        lines = self._lines()
        lines[1] = "{not json"
        self._write(lines)
        with self.assertRaises(IntegrityError):
            Ledger(self.workspace.ledger_path).entries(refresh=True)

    def test_checkpoint_and_inclusion_proof(self) -> None:
        for index in range(6):
            self.ledger.append("drift.run", "s%d" % index, {"i": index})
        self.ledger.checkpoint()
        proof = self.ledger.inclusion_proof(3)
        self.assertTrue(Ledger.verify_inclusion(proof))

    def test_inclusion_proof_rejects_a_swapped_entry(self) -> None:
        self.ledger.append("receipt.access", "a", {"items": 5})
        self.ledger.checkpoint()
        proof = self.ledger.inclusion_proof(1)
        proof = json.loads(json.dumps(proof))
        proof["entry"]["body"]["items"] = 500
        self.assertFalse(Ledger.verify_inclusion(proof))

    def test_proof_without_a_checkpoint_is_refused(self) -> None:
        self.ledger.append("drift.run", "a", {})
        with self.assertRaises(IntegrityError):
            self.ledger.inclusion_proof(1)

    def test_merge_fast_forwards_and_is_idempotent(self) -> None:
        self.ledger.append("drift.run", "a", {})
        other = Workspace.init(self.path("other"))
        mirror = Ledger(other.ledger_path, trust=self.trust)
        self.assertEqual(mirror.merge(self.ledger.entries()).added, 2)
        self.assertEqual(mirror.merge(self.ledger.entries()).added, 0)
        self.assertTrue(mirror.verify().ok)

    def test_merge_refuses_a_fork(self) -> None:
        other = Workspace.init(self.path("other"))
        mirror = Ledger(other.ledger_path, key=self.key, trust=self.trust)
        mirror.merge(self.ledger.entries())
        mirror.append("drift.run", "theirs", {})
        self.ledger.append("drift.run", "ours", {})
        with self.assertRaises(ForkDetected):
            mirror.merge(self.ledger.entries())

    def test_append_is_serialised_by_a_lock(self) -> None:
        """A second writer must not build on a stale head."""
        second = Ledger(self.workspace.ledger_path, key=self.key, trust=self.trust)
        second.entries()  # warm the cache so its idea of the head goes stale
        self.ledger.append("drift.run", "first", {})
        second.append("drift.run", "second", {})
        self.assertTrue(Ledger(self.workspace.ledger_path, trust=self.trust).verify().ok)
        self.assertEqual([e.seq for e in second.entries()], [0, 1, 2])

    def test_stats_and_select(self) -> None:
        self.ledger.append("drift.run", "a", {})
        self.ledger.append("receipt.access", "b", {})
        self.assertEqual(self.ledger.stats()["drift"], 1)
        self.assertEqual(len(self.ledger.select(kind="receipt")), 1)
        self.assertEqual(len(self.ledger.select(kind="receipt.access")), 1)
        self.assertEqual(len(self.ledger.select(subject="a")), 1)

    # -- helpers ---------------------------------------------------------

    def _lines(self) -> list:
        with open(self.workspace.ledger_path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()

    def _write(self, lines: list) -> None:
        with open(self.workspace.ledger_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def _rewrite_line(self, index: int, mutate) -> None:
        lines = self._lines()
        doc = json.loads(lines[index])
        mutate(doc)
        lines[index] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        self._write(lines)


class WorkspaceTests(WorkspaceCase):
    def test_init_is_idempotent(self) -> None:
        again = Workspace.init(self.tmp)
        self.assertEqual(again.root, self.workspace.root)

    def test_config_round_trip(self) -> None:
        self.workspace.set_config("default_key", "abc")
        self.assertEqual(self.workspace.get_config("default_key"), "abc")

    def test_keys_and_cache_are_gitignored(self) -> None:
        with open(self.workspace.path(".gitignore"), "r", encoding="utf-8") as handle:
            ignored = handle.read()
        self.assertIn("keys/", ignored)
        self.assertIn("registry/cache/", ignored)

    def test_private_keys_are_not_world_readable(self) -> None:
        path = os.path.join(self.workspace.keys_dir, "%s.json" % self.key.keyid)
        self.assertTrue(os.path.exists(path))
        if os.name != "nt":
            self.assertEqual(os.stat(path).st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
