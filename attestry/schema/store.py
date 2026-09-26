"""Keeping tool schemas on disk, and recording their history in the ledger.

Translation alone is a one-shot convenience. What makes it worth wiring into a
project is remembering what a tool looked like last time, so that the day a
dependency quietly turns a read-only tool into one that writes, something says
so out loud.

Each registration records the *interface* digest, which ignores prose. Rewording
a description does not create a change event; adding a required parameter does.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple

from ..ledger.chain import Ledger
from ..util.errors import SchemaError
from .diff import Change, diff, worst_severity
from .neutral import ToolSchema

__all__ = ["SchemaStore", "load_schema_file", "save_schema_file"]

SUFFIX = ".nts.json"


def load_schema_file(path: str) -> ToolSchema:
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except ValueError as exc:
            raise SchemaError("%s is not valid JSON: %s" % (path, exc))
    return ToolSchema.from_dict(data)


def save_schema_file(tool: ToolSchema, path: str) -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(tool.to_dict(), handle, indent=2)
        handle.write("\n")
    return path


class SchemaStore:
    """The NTS documents belonging to a workspace."""

    def __init__(self, directory: str, ledger: Optional[Ledger] = None) -> None:
        self.directory = directory
        self.ledger = ledger

    def path_for(self, name: str) -> str:
        return os.path.join(self.directory, name + SUFFIX)

    def names(self) -> List[str]:
        if not os.path.isdir(self.directory):
            return []
        return sorted(
            filename[: -len(SUFFIX)]
            for filename in os.listdir(self.directory)
            if filename.endswith(SUFFIX)
        )

    def load(self, name: str) -> ToolSchema:
        path = self.path_for(name)
        if not os.path.exists(path):
            raise SchemaError(
                "no schema named %r in %s; 'attestry schema list' shows what is there"
                % (name, self.directory)
            )
        return load_schema_file(path)

    def load_all(self) -> Dict[str, ToolSchema]:
        return {name: self.load(name) for name in self.names()}

    def save(self, tool: ToolSchema) -> str:
        return save_schema_file(tool, self.path_for(tool.name))

    # -- ledger integration ----------------------------------------------

    def last_registered(self, name: str) -> Optional[ToolSchema]:
        """The most recent schema recorded in the ledger for this tool."""
        if self.ledger is None:
            return None
        found = None
        for entry in self.ledger.entries():
            if entry.kind in ("schema.registered", "schema.changed") and entry.subject == name:
                found = entry
        if found is None:
            return None
        document = found.body.get("schema")
        return ToolSchema.from_dict(document) if document else None

    def register(self, tool: ToolSchema) -> Tuple[List[Change], Optional[str]]:
        """Record ``tool`` in the ledger. Returns ``(changes, severity)``.

        The first registration is a ``schema.registered`` entry with no changes.
        Later ones compare against what the ledger last held and, when the
        interface actually moved, write ``schema.changed`` carrying the diff --
        so the reason a tool call started failing is recoverable months later.
        """
        if self.ledger is None:
            raise SchemaError("this SchemaStore has no ledger to register against")
        previous = self.last_registered(tool.name)
        if previous is None:
            self.ledger.append(
                "schema.registered",
                tool.name,
                {
                    "digest": tool.digest(),
                    "schema": tool.to_dict(),
                    "validation": tool.validate(),
                },
            )
            return [], None

        if previous.digest() == tool.digest():
            return [], None

        changes = diff(previous, tool)
        severity = worst_severity(changes)
        self.ledger.append(
            "schema.changed",
            tool.name,
            {
                "from_digest": previous.digest(),
                "digest": tool.digest(),
                "severity": severity,
                "changes": [change.to_dict() for change in changes],
                "schema": tool.to_dict(),
            },
        )
        return changes, severity

    def history(self, name: str) -> List[dict]:
        """Every recorded state of one tool, oldest first."""
        if self.ledger is None:
            return []
        out = []
        for entry in self.ledger.entries():
            if entry.kind.startswith("schema.") and entry.subject == name:
                out.append(
                    {
                        "seq": entry.seq,
                        "ts": entry.ts,
                        "kind": entry.kind,
                        "digest": entry.body.get("digest"),
                        "severity": entry.body.get("severity"),
                        "changes": entry.body.get("changes", []),
                    }
                )
        return out
