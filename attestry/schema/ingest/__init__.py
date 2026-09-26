"""Reading tools back out of the frameworks that already hold them.

Adoption matters more than elegance here. Almost nobody starts from a neutral
schema; they start with forty tools already defined for whatever framework they
picked first. :func:`sniff` takes any of those payloads, works out which shape
it is, and hands back an NTS document you can emit everywhere else.

What cannot be recovered is what was never there. A tool imported from OpenAI
has no declared effects, because the OpenAI format has nowhere to put them, so
:func:`sniff` leaves ``effects`` empty rather than guessing. Filling those in is
the one piece of manual work that importing cannot avoid, and
``attestry schema validate`` will keep reminding you.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Tuple

from ...util.errors import SchemaError
from ..neutral import Effects, Param, ToolSchema

__all__ = [
    "from_mcp",
    "from_openai",
    "from_anthropic",
    "from_json_schema",
    "sniff",
    "detect_format",
    "from_any",
]


def _params_from_object_schema(schema: Optional[Mapping[str, Any]]) -> List[Param]:
    if not isinstance(schema, Mapping):
        return []
    required = set(schema.get("required") or [])
    out = []
    for name, fragment in (schema.get("properties") or {}).items():
        if isinstance(fragment, Mapping):
            out.append(Param.from_json_schema(name, fragment, name in required))
    return out


def from_mcp(payload: Mapping[str, Any]) -> ToolSchema:
    """Parse an MCP tool descriptor, recovering effects from its hints."""
    annotations = payload.get("annotations") or {}
    read_only = bool(annotations.get("readOnlyHint", False))
    destructive = bool(annotations.get("destructiveHint", False))
    tool = ToolSchema(
        name=payload["name"],
        title=payload.get("title") or annotations.get("title", "") or "",
        description=payload.get("description", "") or "",
        params=_params_from_object_schema(payload.get("inputSchema")),
        effects=Effects(
            # MCP says whether a tool writes, not what it writes. "unspecified"
            # is honest; inventing a resource name would not be.
            writes=[] if read_only else ["unspecified"],
            network=bool(annotations.get("openWorldHint", False)),
            idempotent=bool(annotations.get("idempotentHint", True)),
            destructive=destructive,
        ),
    )
    output = payload.get("outputSchema")
    if isinstance(output, Mapping):
        tool.returns = Param.from_json_schema("result", output)
    return tool


def from_openai(payload: Mapping[str, Any]) -> ToolSchema:
    """Parse either the Chat Completions or the Responses function shape."""
    function = payload.get("function") if "function" in payload else payload
    if not isinstance(function, Mapping) or "name" not in function:
        raise SchemaError("not an OpenAI function definition: no name field")
    params = _params_from_object_schema(function.get("parameters"))
    if function.get("strict"):
        # Strict mode requires every property in "required", so requiredness
        # there means nothing. The nullable union is the real signal, and
        # Param.from_json_schema has already turned it into required=False.
        pass
    return ToolSchema(
        name=function["name"],
        description=function.get("description", "") or "",
        params=params,
    )


def from_anthropic(payload: Mapping[str, Any]) -> ToolSchema:
    """Parse an Anthropic Messages API tool definition."""
    if "input_schema" not in payload:
        raise SchemaError("not an Anthropic tool: no input_schema field")
    return ToolSchema(
        name=payload["name"],
        description=payload.get("description", "") or "",
        params=_params_from_object_schema(payload.get("input_schema")),
    )


def from_json_schema(schema: Mapping[str, Any], name: str = "") -> ToolSchema:
    """Treat a bare JSON Schema object as a tool's argument list."""
    return ToolSchema(
        name=name or schema.get("title") or "tool",
        description=schema.get("description", "") or "",
        params=_params_from_object_schema(schema),
    )


def detect_format(payload: Mapping[str, Any]) -> str:
    """Name the shape of a tool payload, or ``unknown``.

    Ordered most specific first. ``inputSchema`` and ``input_schema`` differ
    only in punctuation, which is a fair summary of the problem this package
    exists to solve.
    """
    if not isinstance(payload, Mapping):
        return "unknown"
    if "nts" in payload:
        return "nts"
    if "inputSchema" in payload:
        return "mcp"
    if "input_schema" in payload:
        return "anthropic"
    if payload.get("type") == "function" or "function" in payload:
        return "openai"
    if "parameters" in payload and "name" in payload:
        return "gemini"
    if payload.get("type") == "object" and "properties" in payload:
        return "json-schema"
    return "unknown"


def sniff(payload: Mapping[str, Any], name: str = "") -> Tuple[ToolSchema, str]:
    """Detect the format and parse it. Returns ``(tool, format_name)``."""
    detected = detect_format(payload)
    if detected == "nts":
        return ToolSchema.from_dict(payload), detected
    if detected == "mcp":
        return from_mcp(payload), detected
    if detected == "anthropic":
        return from_anthropic(payload), detected
    if detected in ("openai", "gemini"):
        return from_openai(payload), detected
    if detected == "json-schema":
        return from_json_schema(payload, name), detected
    raise SchemaError(
        "cannot tell what format this is; it has none of the fields that "
        "identify an MCP, OpenAI, Anthropic, Gemini or NTS tool"
    )


def from_any(payload: Any, name: str = "") -> List[Tuple[ToolSchema, str]]:
    """Parse one tool, a list of tools, or a container holding a list.

    Exports from these frameworks arrive in all three shapes, and making the
    caller unwrap them first is a pointless chore.
    """
    if isinstance(payload, list):
        return [sniff(item, name) for item in payload if isinstance(item, Mapping)]
    if isinstance(payload, Mapping):
        for key in ("tools", "functions", "function_declarations", "toolDefinitions"):
            nested = payload.get(key)
            if isinstance(nested, list):
                return [sniff(item, name) for item in nested if isinstance(item, Mapping)]
        return [sniff(payload, name)]
    raise SchemaError("expected a tool object or a list of them")
