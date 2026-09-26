"""One entry point for every target.

``emit()`` returns the native object -- a dict for the JSON targets, a string of
Python source for the code-generating ones -- together with the notes about what
the translation could not carry across. ``render()`` gives you the text to write
to a file.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Tuple

from ..neutral import ToolSchema
from .code import to_autogen, to_crewai, to_langchain, to_pydantic
from .wire import to_anthropic, to_gemini, to_json_schema, to_mcp, to_openai

__all__ = ["TARGETS", "CODE_TARGETS", "emit", "render", "extension_for"]

#: Target name to emitter. ``ollama`` is an alias: its tool API is the OpenAI
#: shape, which is worth stating in one line rather than making people discover.
TARGETS: Dict[str, Callable[..., Tuple[Any, List[str]]]] = {
    "mcp": to_mcp,
    "openai": to_openai,
    "ollama": to_openai,
    "anthropic": to_anthropic,
    "gemini": to_gemini,
    "json-schema": to_json_schema,
    "langchain": to_langchain,
    "autogen": to_autogen,
    "crewai": to_crewai,
    "pydantic": to_pydantic,
}

#: The targets whose output is Python source rather than JSON.
CODE_TARGETS = frozenset({"langchain", "autogen", "crewai", "pydantic"})


def emit(tool: ToolSchema, target: str, **options: Any) -> Tuple[Any, List[str]]:
    """Translate ``tool`` into ``target``. Returns ``(payload, notes)``."""
    try:
        emitter = TARGETS[target]
    except KeyError:
        raise KeyError(
            "unknown target %r; try one of: %s" % (target, ", ".join(sorted(TARGETS)))
        )
    return emitter(tool, **options)


def render(tool: ToolSchema, target: str, indent: int = 2, **options: Any) -> Tuple[str, List[str]]:
    """Same as :func:`emit`, but always returns text ready to write to a file."""
    payload, notes = emit(tool, target, **options)
    if isinstance(payload, str):
        return payload, notes
    return json.dumps(payload, indent=indent, sort_keys=False) + "\n", notes


def extension_for(target: str) -> str:
    return ".py" if target in CODE_TARGETS else ".json"
