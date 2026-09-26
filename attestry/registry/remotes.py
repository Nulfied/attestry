"""Distribution without a distributor.

A ledger is one append-only text file, so "syncing the registry" means getting a
copy of somebody's file and merging it with yours. Any transport works: a git
repository, a URL, a shared drive, a file someone emailed you. There is nothing
to run and nothing to pay for, which is the point.

Merging is safe because it is only ever a fast-forward. If the incoming ledger
extends yours, the new entries are appended. If yours already contains theirs,
nothing happens. If the two disagree about an entry that both contain, that is a
fork -- somebody rewrote history -- and it is reported rather than resolved,
because choosing a winner is a judgement about the world and not about the data.

Incoming entries are verified before they are merged, never after. Appending
somebody else's file to your own signed log and checking it later would mean
your ledger had already vouched for content you had not examined.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from ..ledger.chain import Ledger, MergeResult
from ..ledger.entry import Entry
from ..ledger.trust import TrustStore
from ..util.canonical import ZERO_DIGEST
from ..util.errors import AttestryError, IntegrityError
from .index import fetch_source

__all__ = ["Remotes", "parse_ledger_text", "check_incoming", "sync"]


class Remotes:
    """The ledgers this workspace syncs with, stored as one JSON file."""

    def __init__(self, path: str, entries: Optional[Mapping[str, str]] = None) -> None:
        self.path = path
        self.entries: Dict[str, str] = dict(entries or {})

    @classmethod
    def load(cls, path: str) -> "Remotes":
        if not os.path.exists(path):
            return cls(path)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(path, data.get("remotes", {}))

    def save(self) -> str:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"remotes": self.entries}, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return self.path

    def add(self, name: str, url: str) -> None:
        self.entries[name] = url
        self.save()

    def remove(self, name: str) -> bool:
        if name in self.entries:
            del self.entries[name]
            self.save()
            return True
        return False

    def url(self, name: str) -> str:
        if name in self.entries:
            return self.entries[name]
        # Treat an unknown name as a literal location, so a one-off sync from a
        # path or URL does not require registering it first.
        return name

    def describe(self) -> str:
        if not self.entries:
            return "no remotes configured"
        return "\n".join(
            "  %-16s %s" % (name, url) for name, url in sorted(self.entries.items())
        )


def parse_ledger_text(text: str) -> List[Entry]:
    """Parse a ledger file's contents into entries."""
    entries: List[Entry] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            entries.append(Entry.from_dict(json.loads(stripped)))
        except (ValueError, TypeError, KeyError) as exc:
            raise IntegrityError("incoming ledger line %d is not an entry: %s" % (number, exc))
    return entries


def check_incoming(
    entries: Sequence[Entry], trust: Optional[TrustStore] = None
) -> List[str]:
    """Validate a foreign ledger on its own terms. Returns a list of problems.

    This checks the incoming file is internally sound -- sequence numbers,
    hashes, links, and signatures against keys the file itself declares -- before
    any of it touches the local ledger.
    """
    problems: List[str] = []
    declared: Dict[str, str] = {}
    for entry in entries:
        if entry.kind == "ledger.key-trusted":
            keyid, public = entry.body.get("keyid"), entry.body.get("public")
            if isinstance(keyid, str) and isinstance(public, str):
                declared.setdefault(keyid, public)

    previous: Optional[Entry] = None
    for index, entry in enumerate(entries):
        if entry.seq != index:
            problems.append("entry %d claims seq %d" % (index, entry.seq))
        if not entry.hash_matches():
            problems.append("#%d has been edited: contents do not match its hash" % entry.seq)
        expected = previous.compute_hash() if previous else ZERO_DIGEST
        if entry.prev != expected and (previous is None or previous.hash_matches()):
            problems.append("#%d does not link to the entry before it" % entry.seq)
        if entry.sig:
            from ..ledger.keys import verify_bytes

            keyid = entry.sig.split(":")[1] if entry.sig.count(":") == 2 else ""
            public = declared.get(keyid)
            if public is None and trust is not None:
                known = trust.keys.get(keyid)
                public = known["public"] if known else None
            if public is None:
                problems.append("#%d is signed by unknown key %s" % (entry.seq, keyid))
            elif not verify_bytes(entry.sig, entry.signing_bytes(), public):
                problems.append("#%d has a signature that does not verify" % entry.seq)
        previous = entry
    return problems


def sync(
    ledger: Ledger,
    source: str,
    trust: Optional[TrustStore] = None,
    verify_incoming: bool = True,
) -> Tuple[MergeResult, List[str]]:
    """Fetch a remote ledger and fast-forward the local one.

    Returns the merge result and any problems found in the incoming file. When
    ``verify_incoming`` is set and the incoming ledger is unsound, nothing is
    merged at all -- a partial merge of a broken log is worse than no merge.
    """
    raw = fetch_source(source)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AttestryError("%s is not a UTF-8 ledger file" % source)
    incoming = parse_ledger_text(text)
    problems = check_incoming(incoming, trust) if verify_incoming else []
    if problems and verify_incoming:
        raise IntegrityError(
            "refusing to merge %s: the incoming ledger has %d problem(s)\n  - %s"
            % (source, len(problems), "\n  - ".join(problems[:6]))
        )
    return ledger.merge(incoming), problems


def export_ledger(ledger: Ledger, destination: str) -> str:
    """Copy the ledger out for somebody else to sync from."""
    parent = os.path.dirname(destination)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(ledger.path, "r", encoding="utf-8") as source_handle:
        content = source_handle.read()
    with open(destination, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)
    return destination
