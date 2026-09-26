"""Shared test scaffolding.

Every test gets its own temporary workspace and points ``ATTESTRY_HOME`` at it,
so a test run can never read or append to a developer's real ledger.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from attestry.ledger import Keyring, Ledger, TrustStore
from attestry.workspace import Workspace


class WorkspaceCase(unittest.TestCase):
    """A TestCase with a throwaway workspace, key, trust store and ledger."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="attestry-test-")
        self.workspace = Workspace.init(self.tmp)
        self._saved_home = os.environ.get("ATTESTRY_HOME")
        os.environ["ATTESTRY_HOME"] = self.workspace.root
        self.keyring = Keyring(self.workspace.keys_dir)
        self.key = self.keyring.create("test")
        self.trust = TrustStore(self.workspace.trust_path, mode="tofu")
        self.trust.add(self.key.public, "test")
        self.ledger = Ledger(self.workspace.ledger_path, key=self.key, trust=self.trust)
        self.ledger.announce_key(self.key)

    def tearDown(self) -> None:
        if self._saved_home is None:
            os.environ.pop("ATTESTRY_HOME", None)
        else:
            os.environ["ATTESTRY_HOME"] = self._saved_home
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, *parts: str) -> str:
        return os.path.join(self.tmp, *parts)
