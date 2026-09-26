"""The append-only log every subsystem writes to.

Storage is a JSONL file: one canonical JSON entry per line, appended and never
rewritten. That choice is doing real work. It means the ledger diffs cleanly in
a pull request, merges by concatenation when two people have been appending in
parallel, survives being copied to a USB stick, and can be verified by a script
somebody writes in an afternoon in another language.

What the chain gives you:

* **tamper evidence** -- edit any entry and its hash changes, which breaks the
  ``prev`` link of every entry after it, all the way to the head;
* **authorship** -- each entry is signed, so appending requires a key rather
  than merely write access to the file;
* **cheap proofs** -- checkpoints publish a Merkle root, letting you prove one
  entry was recorded without handing over the rest of the log.

What it deliberately does not give you: consensus. Two people appending offline
will produce two valid ledgers, and :meth:`Ledger.merge` will fast-forward when
one is a prefix of the other and refuse when they genuinely diverge. Resolving a
real fork is a human decision about which history is the true one, and pretending
otherwise would be the dishonest kind of "decentralised".
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional

from ..util.canonical import ZERO_DIGEST, canonical_json
from ..util.errors import ForkDetected, IntegrityError
from ..util.timeutil import now_rfc3339
from . import merkle
from .entry import KNOWN_KINDS, Entry
from .keys import KeyPair, sign_bytes, verify_bytes
from .trust import TrustStore

__all__ = ["Ledger", "VerifyResult", "MergeResult", "Problem", "read_entries", "FileLock"]


class FileLock:
    """A crude cross-platform lock so two appends cannot interleave.

    ``os.O_EXCL`` is atomic on every platform Attestry targets, which is enough
    for the one thing that matters: two processes must not compute the same
    ``prev`` and both append. A stale lock left by a crashed process is broken
    after ``stale_after`` seconds rather than wedging the tool forever.
    """

    def __init__(self, path: str, timeout: float = 10.0, stale_after: float = 60.0) -> None:
        self.path = path
        self.timeout = timeout
        self.stale_after = stale_after
        self._fd: Optional[int] = None

    def __enter__(self) -> "FileLock":
        deadline = time.time() + self.timeout
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(self._fd, str(os.getpid()).encode("ascii"))
                return self
            except FileExistsError:
                if self._break_if_stale():
                    continue
                if time.time() > deadline:
                    raise IntegrityError(
                        "could not lock %s after %gs; another Attestry process may be "
                        "stuck, or delete the .lock file if you are sure none is running"
                        % (self.path, self.timeout)
                    )
                time.sleep(0.05)

    def _break_if_stale(self) -> bool:
        try:
            age = time.time() - os.path.getmtime(self.path)
        except OSError:
            return True
        if age > self.stale_after:
            try:
                os.unlink(self.path)
                return True
            except OSError:
                return False
        return False

    def __exit__(self, *exc: Any) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            os.unlink(self.path)
        except OSError:
            pass


class Problem:
    """One thing wrong with a ledger, at one sequence number."""

    __slots__ = ("seq", "code", "detail", "severity")

    def __init__(self, seq: int, code: str, detail: str, severity: str = "error") -> None:
        self.seq = seq
        self.code = code
        self.detail = detail
        self.severity = severity

    def __repr__(self) -> str:
        return "Problem(#%s %s: %s)" % (self.seq, self.code, self.detail)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "code": self.code,
            "detail": self.detail,
            "severity": self.severity,
        }

    def format(self) -> str:
        mark = "ERROR" if self.severity == "error" else "warn "
        return "  %s #%-4s %-16s %s" % (mark, self.seq, self.code, self.detail)


class VerifyResult:
    """The outcome of walking a ledger end to end."""

    def __init__(
        self,
        entries: int,
        signed: int,
        problems: List[Problem],
        head: Optional[str],
        root: str,
    ) -> None:
        self.entries = entries
        self.signed = signed
        self.problems = problems
        self.head = head
        self.root = root

    @property
    def errors(self) -> List[Problem]:
        return [p for p in self.problems if p.severity == "error"]

    @property
    def warnings(self) -> List[Problem]:
        return [p for p in self.problems if p.severity != "error"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def first_bad_seq(self) -> Optional[int]:
        """Where the trouble starts -- the only number worth acting on first."""
        return min((p.seq for p in self.errors), default=None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "signed": self.signed,
            "head": self.head,
            "merkle_root": self.root,
            "first_bad_seq": self.first_bad_seq,
            "problems": [p.to_dict() for p in self.problems],
        }

    def format(self) -> str:
        lines = []
        if self.ok:
            lines.append(
                "OK  %d entries, %d signed, chain intact" % (self.entries, self.signed)
            )
        else:
            lines.append(
                "BROKEN  %d entries, %d error(s); first problem at #%s"
                % (self.entries, len(self.errors), self.first_bad_seq)
            )
        for problem in self.problems:
            lines.append(problem.format())
        if self.head:
            lines.append("  head   %s" % self.head)
            lines.append("  merkle %s" % self.root)
        return "\n".join(lines)


class MergeResult:
    def __init__(self, added: int, already_had: int, fork_at: Optional[int] = None) -> None:
        self.added = added
        self.already_had = already_had
        self.fork_at = fork_at

    def format(self) -> str:
        if self.fork_at is not None:
            return "fork at #%d: histories diverge and cannot be merged" % self.fork_at
        if not self.added:
            return "already up to date (%d shared entries)" % self.already_had
        return "fast-forwarded %d entries (%d already held)" % (self.added, self.already_had)


def read_entries(path: str) -> List[Entry]:
    """Read a ledger file into Entries, tolerating a torn final line.

    A process killed mid-append can leave a partial last line. That is recovered
    from rather than treated as corruption, because the entry was never
    acknowledged to anyone -- but any malformed line other than the last one is
    a real problem and is surfaced as such.
    """
    if not os.path.exists(path):
        return []
    entries: List[Entry] = []
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            entries.append(Entry.from_dict(json.loads(stripped)))
        except (ValueError, TypeError, KeyError) as exc:
            if index == len(lines) - 1:
                break  # torn tail from an interrupted append
            raise IntegrityError(
                "ledger line %d in %s is not a valid entry: %s" % (index + 1, path, exc)
            )
    return entries


class Ledger:
    """An append-only, hash-chained, signed log on disk."""

    def __init__(
        self,
        path: str,
        key: Optional[KeyPair] = None,
        trust: Optional[TrustStore] = None,
    ) -> None:
        self.path = path
        self.key = key
        self.trust = trust
        self._cache: Optional[List[Entry]] = None
        self._cache_stamp: Optional[tuple] = None

    # -- reading ---------------------------------------------------------

    def _stamp(self) -> Optional[tuple]:
        try:
            info = os.stat(self.path)
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size)

    def entries(self, refresh: bool = False) -> List[Entry]:
        """All entries, cached until the file changes underneath us."""
        stamp = self._stamp()
        if refresh or self._cache is None or stamp != self._cache_stamp:
            self._cache = read_entries(self.path)
            self._cache_stamp = stamp
        return self._cache

    def __len__(self) -> int:
        return len(self.entries())

    def __iter__(self) -> Iterator[Entry]:
        return iter(self.entries())

    def head(self) -> Optional[Entry]:
        entries = self.entries()
        return entries[-1] if entries else None

    def head_hash(self) -> str:
        head = self.head()
        return head.hash if head else ZERO_DIGEST

    def select(
        self,
        kind: Optional[str] = None,
        subject: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Entry]:
        """Filter entries. ``kind`` may be a namespace like ``receipt`` or a full kind."""
        out = []
        for entry in self.entries():
            if kind and entry.kind != kind and not entry.kind.startswith(kind + "."):
                continue
            if subject and subject not in entry.subject:
                continue
            if since and entry.ts < since:
                continue
            if until and entry.ts > until:
                continue
            out.append(entry)
        if limit is not None and limit >= 0:
            out = out[-limit:]
        return out

    # -- writing ---------------------------------------------------------

    def append(
        self,
        kind: str,
        subject: str,
        body: Mapping[str, Any],
        key: Optional[KeyPair] = None,
        ts: Optional[str] = None,
    ) -> Entry:
        """Seal, sign and append one entry. Returns the entry as written."""
        signing_key = key or self.key
        lock_path = self.path + ".lock"
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with FileLock(lock_path):
            # Re-read inside the lock: another process may have appended since
            # this one last looked, and building on a stale head would fork the
            # chain in our own working directory.
            existing = self.entries(refresh=True)
            entry = Entry(
                seq=len(existing),
                ts=ts or now_rfc3339(),
                kind=kind,
                subject=subject,
                body=body,
                prev=existing[-1].hash if existing else ZERO_DIGEST,
            ).sealed()
            if signing_key is not None:
                entry = entry.signed(sign_bytes(signing_key, entry.signing_bytes()))
            line = canonical_json(entry.to_dict()) + "\n"
            with open(self.path, "a", encoding="utf-8", newline="") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        self.entries(refresh=True)
        return entry

    # -- verification ----------------------------------------------------

    def key_table(self) -> Dict[str, str]:
        """Public keys the ledger itself declares, keyed by key id.

        Built from ``ledger.key-trusted`` entries in a first pass, so an entry
        may be signed by a key announced later in the file. That matters for the
        genesis case, where the announcement is itself signed by the key it
        announces.
        """
        table: Dict[str, str] = {}
        for entry in self.entries():
            if entry.kind == "ledger.key-trusted":
                public = entry.body.get("public")
                keyid = entry.body.get("keyid")
                if isinstance(public, str) and isinstance(keyid, str):
                    table.setdefault(keyid, public)
        return table

    def verify(
        self,
        trust: Optional[TrustStore] = None,
        require_signatures: bool = False,
    ) -> VerifyResult:
        """Walk the whole chain and report everything wrong with it."""
        trust = trust or self.trust
        entries = self.entries(refresh=True)
        problems: List[Problem] = []
        declared = self.key_table()
        signed = 0
        previous: Optional[Entry] = None

        for index, entry in enumerate(entries):
            if entry.seq != index:
                problems.append(
                    Problem(
                        entry.seq,
                        "seq-gap",
                        "entry at line %d claims seq %d" % (index + 1, entry.seq),
                    )
                )
            edited = not entry.hash_matches()
            if edited:
                problems.append(
                    Problem(
                        entry.seq,
                        "hash-mismatch",
                        "contents do not match the recorded hash; this entry was edited",
                    )
                )
            # Compare against the previous entry's *recomputed* hash, not the
            # one it stores. Trusting the stored value would let an attacker who
            # edits a body and leaves the hash field alone keep the chain
            # looking intact from here on.
            previous_edited = previous is not None and not previous.hash_matches()
            expected_prev = previous.compute_hash() if previous else ZERO_DIGEST
            if entry.prev != expected_prev and not previous_edited:
                problems.append(
                    Problem(
                        entry.seq,
                        "broken-link",
                        "prev is %s but the entry before hashes to %s"
                        % (entry.prev[:12], (expected_prev or "")[:12]),
                    )
                )
            if previous is not None and entry.ts < previous.ts:
                problems.append(
                    Problem(
                        entry.seq,
                        "clock-regression",
                        "timestamp %s is before the previous entry's %s"
                        % (entry.ts, previous.ts),
                        severity="warning",
                    )
                )
            if entry.kind not in KNOWN_KINDS:
                problems.append(
                    Problem(
                        entry.seq,
                        "unknown-kind",
                        "%s is not a kind this version writes" % entry.kind,
                        severity="warning",
                    )
                )
            problems.extend(self._check_signature(entry, declared, trust, require_signatures))
            if entry.sig:
                signed += 1
            previous = entry

        hashes = [e.hash for e in entries if e.hash]
        return VerifyResult(
            entries=len(entries),
            signed=signed,
            problems=problems,
            head=entries[-1].hash if entries else None,
            root=merkle.root_hex(hashes),
        )

    def _check_signature(
        self,
        entry: Entry,
        declared: Dict[str, str],
        trust: Optional[TrustStore],
        require: bool,
    ) -> List[Problem]:
        if not entry.sig:
            if require:
                return [Problem(entry.seq, "unsigned", "entry carries no signature")]
            return [
                Problem(
                    entry.seq,
                    "unsigned",
                    "entry carries no signature; anyone could have written it",
                    severity="warning",
                )
            ]
        parts = entry.sig.split(":")
        if len(parts) != 3:
            return [Problem(entry.seq, "bad-signature", "malformed signature string")]
        keyid = parts[1]
        public = declared.get(keyid)
        if public is None and trust is not None:
            known = trust.keys.get(keyid)
            public = known["public"] if known else None
        if public is None:
            return [
                Problem(
                    entry.seq,
                    "unknown-key",
                    "signed by %s, whose public key is neither in the ledger nor "
                    "in your trust store" % keyid,
                )
            ]
        if not verify_bytes(entry.sig, entry.signing_bytes(), public):
            return [
                Problem(
                    entry.seq,
                    "bad-signature",
                    "signature from %s does not verify against this content" % keyid,
                )
            ]
        if trust is not None:
            ok, reason = trust.check(keyid, public, entry.ts)
            if not ok:
                return [Problem(entry.seq, "untrusted-key", reason)]
        return []

    # -- checkpoints and proofs ------------------------------------------

    def checkpoint(self, key: Optional[KeyPair] = None) -> Entry:
        """Record a Merkle root over everything so far, as its own entry."""
        entries = self.entries(refresh=True)
        hashes = [e.hash for e in entries if e.hash]
        return self.append(
            "ledger.checkpoint",
            "size=%d" % len(hashes),
            {
                "size": len(hashes),
                "root": merkle.root_hex(hashes),
                "covers": "0..%d" % (len(hashes) - 1) if hashes else "empty",
            },
            key=key,
        )

    def inclusion_proof(self, seq: int) -> Dict[str, Any]:
        """A proof that entry ``seq`` sits under the latest checkpoint's root.

        The point of handing this to somebody is that they learn one entry and
        one root, and nothing at all about the other entries.
        """
        entries = self.entries()
        if not 0 <= seq < len(entries):
            raise IndexError("no entry #%d in a ledger of %d" % (seq, len(entries)))
        checkpoint = None
        for entry in entries:
            if entry.kind == "ledger.checkpoint" and entry.body.get("size", 0) > seq:
                checkpoint = entry
                break
        if checkpoint is None:
            raise IntegrityError(
                "no checkpoint covers entry #%d; run 'attestry ledger checkpoint' first"
                % seq
            )
        size = int(checkpoint.body["size"])
        hashes = [e.hash for e in entries[:size]]
        return {
            "seq": seq,
            "leaf": entries[seq].hash,
            "index": seq,
            "size": size,
            "path": merkle.path_hex(hashes, seq),
            "root": checkpoint.body["root"],
            "checkpoint_seq": checkpoint.seq,
            "entry": entries[seq].to_dict(),
        }

    @staticmethod
    def verify_inclusion(proof: Mapping[str, Any]) -> bool:
        """Check a proof produced by :meth:`inclusion_proof`, offline.

        The entry is re-hashed from its own contents rather than trusting the
        ``leaf`` field, so a proof cannot claim inclusion for contents that were
        swapped after the fact.
        """
        entry_data = proof.get("entry")
        leaf = proof.get("leaf")
        if isinstance(entry_data, Mapping):
            recomputed = Entry.from_dict(entry_data).compute_hash()
            if recomputed != leaf:
                return False
        return merkle.verify_path_hex(
            leaf, int(proof["index"]), int(proof["size"]), proof["path"], proof["root"]
        )

    # -- merging ---------------------------------------------------------

    def merge(self, incoming: Iterable[Entry], key: Optional[KeyPair] = None) -> MergeResult:
        """Fast-forward from another copy of this ledger.

        Merging is only ever safe when one history is a prefix of the other.
        Anything else is a fork, and :class:`ForkDetected` is raised rather than
        picking a winner -- which entry is the real one is a question about the
        world, not about the data.
        """
        ours = self.entries(refresh=True)
        theirs = list(incoming)
        shared = min(len(ours), len(theirs))
        for index in range(shared):
            if ours[index].hash != theirs[index].hash:
                raise ForkDetected(
                    "ledgers agree up to #%d then diverge: local %s, incoming %s"
                    % (index - 1, ours[index].hash[:12], theirs[index].hash[:12])
                )
        if len(theirs) <= len(ours):
            return MergeResult(added=0, already_had=shared)

        new = theirs[len(ours):]
        lock_path = self.path + ".lock"
        with FileLock(lock_path):
            with open(self.path, "a", encoding="utf-8", newline="") as handle:
                for entry in new:
                    handle.write(canonical_json(entry.to_dict()) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        self.entries(refresh=True)
        return MergeResult(added=len(new), already_had=shared)

    def announce_key(self, key: KeyPair) -> Entry:
        """Publish a public key into the ledger so the file is self-describing."""
        return self.append(
            "ledger.key-trusted",
            key.label or key.keyid,
            {"keyid": key.keyid, "public": key.public, "alg": key.alg, "label": key.label},
            key=key,
        )

    def stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self.entries():
            namespace = entry.kind.split(".")[0]
            counts[namespace] = counts.get(namespace, 0) + 1
        return counts
