"""Pillar two: describe a tool once, use it in every framework.

::

    from attestry.schema import ToolSchema, Param, emit

    tool = ToolSchema(
        name="search_docs",
        description="Search the product documentation.",
        params=[
            Param("query", "string", "What to search for.", required=True),
            Param("limit", "integer", "How many results.", default=10, maximum=50),
        ],
    )

    payload, notes = emit(tool, "mcp")       # a dict for MCP
    source, notes = emit(tool, "crewai")     # Python source for CrewAI

Going the other way, :func:`sniff` takes a tool payload from any supported
framework and recovers the neutral form.
"""

from .diff import Change, diff, format_changes, worst_severity
from .emit import CODE_TARGETS, TARGETS, emit, extension_for, render
from .ingest import detect_format, from_any, sniff
from .introspect import from_callable
from .neutral import (
    DATA_CLASSES,
    MISSING,
    NTS_VERSION,
    TYPES,
    Consent,
    Effects,
    Param,
    ToolSchema,
)
from .store import SchemaStore, load_schema_file, save_schema_file

__all__ = [
    "ToolSchema",
    "Param",
    "Effects",
    "Consent",
    "MISSING",
    "TYPES",
    "DATA_CLASSES",
    "NTS_VERSION",
    "emit",
    "render",
    "TARGETS",
    "CODE_TARGETS",
    "extension_for",
    "sniff",
    "from_any",
    "detect_format",
    "from_callable",
    "diff",
    "Change",
    "worst_severity",
    "format_changes",
    "SchemaStore",
    "load_schema_file",
    "save_schema_file",
]
