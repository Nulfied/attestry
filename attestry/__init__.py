"""Attestry -- verifiable trust infrastructure for AI agents.

Four things that keep going wrong in agent systems, and one mechanism underneath
all four:

1. **Model drift.** Providers update models behind stable names. Nothing errors;
   behaviour just changes. :mod:`attestry.drift` records what the behaviour was
   and re-checks it.
2. **Tool schema chaos.** MCP, OpenAI, Anthropic, LangChain, AutoGen and CrewAI
   all describe tools differently. :mod:`attestry.schema` defines a tool once and
   emits all of them.
3. **Invisible access.** Agents touch mail, calendars and files with no readable
   record. :mod:`attestry.receipts` produces receipts a person can check, and
   refuses accesses nobody granted.
4. **Unverifiable skills.** Sharing agent skills means trusting a server.
   :mod:`attestry.registry` content-addresses packages and tracks provenance
   through signatures instead.

The mechanism is :mod:`attestry.ledger`: one append-only, hash-chained, signed
log that all four write to. That is what makes this one tool rather than four --
a single ``attestry ledger verify`` covers every claim any subsystem has made.

::

    import attestry

    workspace = attestry.Workspace.init(".")
    ledger = attestry.Ledger(workspace.ledger_path)
"""

from .ledger import Entry, KeyPair, Keyring, Ledger, TrustStore
from .util.errors import (
    AttestryError,
    ForkDetected,
    IntegrityError,
    PolicyViolation,
    SchemaError,
    TrustError,
)
from .workspace import Workspace, find_workspace

__version__ = "0.1.0"
__author__ = "Nulfied"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "Workspace",
    "find_workspace",
    "Ledger",
    "Entry",
    "KeyPair",
    "Keyring",
    "TrustStore",
    "AttestryError",
    "IntegrityError",
    "ForkDetected",
    "TrustError",
    "SchemaError",
    "PolicyViolation",
]
