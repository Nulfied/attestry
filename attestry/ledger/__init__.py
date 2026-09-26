"""The shared substrate: a signed, hash-chained, append-only log.

Every other package in Attestry is a producer of :class:`Entry` values and a
reader of them. Drift runs, consent receipts, schema registrations and skill
publications all land in the same file, which is why one ``attestry ledger
verify`` covers the lot.
"""

from .chain import Ledger, MergeResult, Problem, VerifyResult, read_entries
from .entry import KIND_RE, KNOWN_KINDS, Entry
from .keys import ALG, BACKEND, KeyPair, Keyring, generate, keyid_for, sign_bytes, verify_bytes
from .trust import TrustStore

__all__ = [
    "Ledger",
    "Entry",
    "KeyPair",
    "Keyring",
    "TrustStore",
    "VerifyResult",
    "MergeResult",
    "Problem",
    "read_entries",
    "generate",
    "sign_bytes",
    "verify_bytes",
    "keyid_for",
    "KNOWN_KINDS",
    "KIND_RE",
    "ALG",
    "BACKEND",
]
