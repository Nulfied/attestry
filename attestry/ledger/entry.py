"""The unit of record.

One Entry is one thing that happened: a drift run, an access to a user's
mailbox, a skill published, a tool schema changed. All four Attestry subsystems
write Entries and nothing else, which is what makes them one product rather than
four scripts sharing a repository -- a single verification pass covers all of
them.

An Entry is immutable once built. Its ``hash`` covers the canonical form of
everything except ``hash`` and ``sig``; its ``prev`` is the hash of the entry
before it. Change any byte of any entry and every hash from there to the head
stops matching, which is the property the rest of the codebase leans on.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Optional

from ..util.canonical import ZERO_DIGEST, canonical_bytes, digest_of

#: Entry kinds are ``namespace.event``, lowercase, dots and dashes only. The
#: namespace says which subsystem wrote it, so a mixed ledger stays readable.
KIND_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")

#: Kinds the shipped subsystems write. Unknown kinds are allowed on purpose --
#: the ledger is meant to be extensible -- but the CLI marks them as foreign so
#: a typo does not silently become a new event type.
KNOWN_KINDS = {
    "ledger.genesis": "ledger created",
    "ledger.checkpoint": "Merkle checkpoint over the entries so far",
    "ledger.key-trusted": "a signing key was added to the trust store",
    "ledger.key-revoked": "a signing key was revoked",
    "drift.baseline": "behaviour snapshot recorded as the reference",
    "drift.run": "a suite was replayed against a model",
    "schema.registered": "a neutral tool schema was recorded",
    "schema.changed": "a tool schema changed shape",
    "receipt.access": "an agent touched a resource",
    "receipt.denied": "an access attempt was refused by policy",
    "registry.publish": "a skill package version was published",
    "registry.install": "a skill package was installed and verified",
    "registry.revoke": "a published version was withdrawn",
}


class Entry:
    """An append-only ledger record.

    Instances are immutable: :meth:`sealed` and :meth:`signed` return new
    Entries rather than mutating in place, so a caller can never end up holding
    an entry whose ``hash`` no longer describes its contents.
    """

    __slots__ = ("seq", "ts", "kind", "subject", "body", "prev", "hash", "sig")

    def __init__(
        self,
        seq: int,
        ts: str,
        kind: str,
        subject: str,
        body: Mapping[str, Any],
        prev: str = ZERO_DIGEST,
        hash: Optional[str] = None,
        sig: Optional[str] = None,
    ) -> None:
        if seq < 0:
            raise ValueError("seq must be non-negative, got %r" % (seq,))
        if not KIND_RE.match(kind):
            raise ValueError(
                "kind %r must look like 'namespace.event' (lowercase, dots)" % (kind,)
            )
        if not isinstance(body, Mapping):
            raise TypeError("body must be a mapping, got %s" % type(body).__name__)
        setter = object.__setattr__
        setter(self, "seq", int(seq))
        setter(self, "ts", ts)
        setter(self, "kind", kind)
        setter(self, "subject", subject)
        setter(self, "body", dict(body))
        setter(self, "prev", prev)
        setter(self, "hash", hash)
        setter(self, "sig", sig)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Entry is immutable; use .sealed() or .signed()")

    def __repr__(self) -> str:
        return "Entry(seq=%d, kind=%s, subject=%r, hash=%s)" % (
            self.seq,
            self.kind,
            self.subject,
            (self.hash or "unsealed")[:12],
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Entry):
            return NotImplemented
        return self.payload() == other.payload() and self.sig == other.sig

    def __hash__(self) -> int:
        return hash(self.compute_hash())

    # -- hashing ---------------------------------------------------------

    def payload(self) -> Dict[str, Any]:
        """The part of the entry that the hash covers."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "subject": self.subject,
            "body": self.body,
            "prev": self.prev,
        }

    def signing_bytes(self) -> bytes:
        """Exact bytes a signature is made over: the canonical payload.

        Signing the payload rather than the hex hash means a verifier never has
        to trust the ``hash`` field it was handed -- it recomputes from content.
        """
        return canonical_bytes(self.payload())

    def compute_hash(self) -> str:
        """Recompute the hash from content, ignoring whatever ``hash`` says."""
        return digest_of(self.payload())

    def sealed(self) -> "Entry":
        """Return a copy with ``hash`` set to the recomputed value."""
        return Entry(
            self.seq,
            self.ts,
            self.kind,
            self.subject,
            self.body,
            self.prev,
            hash=self.compute_hash(),
            sig=self.sig,
        )

    def signed(self, sig: str) -> "Entry":
        """Return a copy carrying ``sig``, sealing it first if needed."""
        return Entry(
            self.seq,
            self.ts,
            self.kind,
            self.subject,
            self.body,
            self.prev,
            hash=self.hash or self.compute_hash(),
            sig=sig,
        )

    def hash_matches(self) -> bool:
        """True when the stored hash agrees with the content."""
        return bool(self.hash) and self.hash == self.compute_hash()

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        out = self.payload()
        out["hash"] = self.hash or self.compute_hash()
        if self.sig:
            out["sig"] = self.sig
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Entry":
        required = ("seq", "ts", "kind", "subject", "body", "prev", "hash")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError("entry is missing %s" % ", ".join(missing))
        return cls(
            seq=data["seq"],
            ts=data["ts"],
            kind=data["kind"],
            subject=data["subject"],
            body=data["body"],
            prev=data["prev"],
            hash=data["hash"],
            sig=data.get("sig"),
        )

    def describe(self) -> str:
        """One human-readable line, used by ``attestry ledger log``."""
        label = KNOWN_KINDS.get(self.kind, "unrecognised kind")
        return "#%-5d %s  %-20s %-28s %s" % (
            self.seq,
            self.ts,
            self.kind,
            (self.subject or "-")[:28],
            label,
        )
