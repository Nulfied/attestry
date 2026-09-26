"""Exception hierarchy.

Every error Attestry raises on purpose descends from :class:`AttestryError`, so a
host application can catch one thing. The CLI maps these onto distinct exit
codes (see :mod:`attestry.cli`) because the whole point of this tool is to be
wired into CI, where the exit code is the signal.
"""

from __future__ import annotations


class AttestryError(Exception):
    """Base class for every deliberate Attestry failure."""


class IntegrityError(AttestryError):
    """The ledger does not hash-chain the way it claims to.

    Raised when a recomputed entry hash disagrees with the stored one, or when
    an entry's ``prev`` does not match the hash of the entry before it. This
    means the log was edited after the fact.
    """


class ForkDetected(AttestryError):
    """Two ledgers disagree about history rather than merely differing in length.

    An append-only log can be merged trivially when one side is a prefix of the
    other. When both sides contain a different entry at the same sequence
    number, someone rewrote history and there is no safe automatic merge.
    """


class TrustError(AttestryError):
    """A signature is absent, malformed, made by an unknown key, or revoked."""


class SchemaError(AttestryError):
    """A document does not satisfy the schema it declares."""


class PolicyViolation(AttestryError):
    """An access event falls outside the consent grants on record."""
