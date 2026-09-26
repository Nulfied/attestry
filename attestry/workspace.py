"""Where Attestry keeps things.

One directory, ``.attestry``, discovered by walking up from the working
directory the way git finds ``.git``. Everything the four subsystems write lands
inside it, which means a project's drift baselines, consent grants, trust store
and ledger travel together in version control and a fresh clone reproduces the
same verification result.

::

    .attestry/
      config.json             workspace settings, including the default key
      ledger.jsonl            the log: one canonical JSON entry per line
      trust.json              keys this machine accepts signatures from
      keys/<keyid>.json       private keys, owner-readable only
      drift/suites/*.json     prompt-to-expectation suites
      drift/baselines/*.json  the behaviour each suite was last pinned to
      drift/runs/*.json       full outputs of past runs, for diffing
      receipts/consent.json   what each agent is allowed to touch, and why
      registry/cache/         verified skill packages, keyed by content digest
      registry/remotes.json   ledgers to sync with

The ledger deliberately sits in a plain append-only text file. You can read it
with ``tail``, diff it in a pull request, and merge it by concatenation. A
database would have been easier to query and much harder to trust.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from .util.errors import AttestryError

__all__ = ["Workspace", "DIR_NAME", "find_workspace"]

DIR_NAME = ".attestry"
ENV_HOME = "ATTESTRY_HOME"


class Workspace:
    """A resolved ``.attestry`` directory and the paths inside it."""

    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)

    def __repr__(self) -> str:
        return "Workspace(%r)" % self.root

    # -- paths -----------------------------------------------------------

    def path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    @property
    def project_dir(self) -> str:
        """The directory containing ``.attestry``."""
        return os.path.dirname(self.root)

    @property
    def config_path(self) -> str:
        return self.path("config.json")

    @property
    def ledger_path(self) -> str:
        return self.path("ledger.jsonl")

    @property
    def trust_path(self) -> str:
        return self.path("trust.json")

    @property
    def keys_dir(self) -> str:
        return self.path("keys")

    @property
    def suites_dir(self) -> str:
        return self.path("drift", "suites")

    @property
    def baselines_dir(self) -> str:
        return self.path("drift", "baselines")

    @property
    def runs_dir(self) -> str:
        return self.path("drift", "runs")

    @property
    def receipts_dir(self) -> str:
        return self.path("receipts")

    @property
    def consent_path(self) -> str:
        return self.path("receipts", "consent.json")

    @property
    def schemas_dir(self) -> str:
        return self.path("schemas")

    @property
    def registry_dir(self) -> str:
        return self.path("registry")

    @property
    def cache_dir(self) -> str:
        return self.path("registry", "cache")

    @property
    def remotes_path(self) -> str:
        return self.path("registry", "remotes.json")

    # -- lifecycle -------------------------------------------------------

    @classmethod
    def init(cls, project_dir: str) -> "Workspace":
        """Create ``.attestry`` under ``project_dir``. Safe to run twice."""
        workspace = cls(os.path.join(os.path.abspath(project_dir), DIR_NAME))
        for directory in (
            workspace.root,
            workspace.keys_dir,
            workspace.suites_dir,
            workspace.baselines_dir,
            workspace.runs_dir,
            workspace.receipts_dir,
            workspace.schemas_dir,
            workspace.cache_dir,
        ):
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(workspace.config_path):
            workspace.write_config({"version": 1, "default_key": None, "trust_mode": "tofu"})
        gitignore = workspace.path(".gitignore")
        if not os.path.exists(gitignore):
            # Private keys and fetched packages are machine-local. Everything
            # else in here is meant to be committed -- that is the point.
            with open(gitignore, "w", encoding="utf-8") as handle:
                handle.write("keys/\nregistry/cache/\ndrift/runs/\n")
        return workspace

    @property
    def exists(self) -> bool:
        return os.path.isdir(self.root)

    # -- config ----------------------------------------------------------

    def read_config(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            return {"version": 1, "default_key": None, "trust_mode": "tofu"}
        with open(self.config_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def write_config(self, config: Dict[str, Any]) -> None:
        os.makedirs(self.root, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def set_config(self, key: str, value: Any) -> None:
        config = self.read_config()
        config[key] = value
        self.write_config(config)

    def get_config(self, key: str, default: Any = None) -> Any:
        return self.read_config().get(key, default)


def find_workspace(start: Optional[str] = None, required: bool = True) -> Optional[Workspace]:
    """Locate the workspace for ``start``, walking up toward the filesystem root.

    ``ATTESTRY_HOME`` overrides the search entirely, which is what CI and the
    test suite use to keep runs from touching a developer's real ledger.
    """
    override = os.environ.get(ENV_HOME)
    if override:
        workspace = Workspace(override)
        if workspace.exists or not required:
            return workspace
        raise AttestryError("%s points at %s, which does not exist" % (ENV_HOME, override))

    current = os.path.abspath(start or os.getcwd())
    while True:
        candidate = os.path.join(current, DIR_NAME)
        if os.path.isdir(candidate):
            return Workspace(candidate)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    if required:
        raise AttestryError(
            "no .attestry workspace here or in any parent directory; "
            "run 'attestry init' to create one"
        )
    return None
