"""Emitters for the targets that want JSON rather than code.

Each of these is a lossy projection of an NTS document, and the losses are the
interesting part -- they are exactly the places where moving a tool between
frameworks silently changes its meaning. Every emitter returns the payload plus
a list of notes saying what it had to drop, and the CLI prints them.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..neutral import ToolSchema

__all__ = ["to_mcp", "to_openai", "to_anthropic", "to_json_schema", "to_gemini"]

Emitted = Tuple[Dict[str, Any], List[str]]


def to_mcp(tool: ToolSchema, **options: Any) -> Emitted:
    """Model Context Protocol tool descriptor.

    MCP is the only one of the targets with a place for behavioural hints, so
    effects survive the trip here almost intact. They are hints rather than
    guarantees -- an MCP client uses them to decide what to confirm with a human,
    not to sandbox anything.
    """
    notes: List[str] = []
    payload: Dict[str, Any] = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.params_json_schema(),
    }
    if tool.title:
        payload["title"] = tool.title
    if tool.returns is not None:
        payload["outputSchema"] = tool.returns.to_json_schema()
    payload["annotations"] = {
        "title": tool.title or tool.name,
        "readOnlyHint": not tool.effects.writes and not tool.effects.destructive,
        "destructiveHint": tool.effects.destructive,
        "idempotentHint": tool.effects.idempotent,
        "openWorldHint": tool.effects.network,
    }
    if tool.consent.required:
        notes.append(
            "MCP has no consent field; the declared purpose and data classes are "
            "kept in the Attestry ledger and checked by 'attestry receipts check'"
        )
    return payload, notes


def to_openai(tool: ToolSchema, strict: bool = False, style: str = "chat", **options: Any) -> Emitted:
    """OpenAI function calling, for either the Chat Completions or Responses shape.

    ``strict=True`` switches to structured outputs, which guarantees the model
    returns arguments matching the schema but demands that every property appear
    in ``required``. Optional parameters are therefore emitted as a union with
    ``null`` -- the model must still pass them, just possibly as null, which is
    a real behavioural difference worth knowing about before you turn it on.
    """
    notes: List[str] = []
    if strict:
        optional = [p.name for p in tool.params if not p.required]
        if optional:
            notes.append(
                "strict mode: %s became nullable-but-required, so the model will "
                "pass null rather than omitting them" % ", ".join(optional)
            )
    function: Dict[str, Any] = {
        "name": tool.name,
        "description": tool.description,
        "parameters": tool.params_json_schema(strict=strict),
    }
    if strict:
        function["strict"] = True
    if tool.returns is not None:
        notes.append("OpenAI tool definitions carry no return schema; returns dropped")
    if tool.effects.destructive or tool.effects.writes:
        notes.append(
            "no place to declare side effects; a caller cannot tell from this "
            "payload that the tool writes or destroys data"
        )
    if style == "responses":
        # The Responses API flattens the function fields to the top level.
        payload = {"type": "function"}
        payload.update(function)
        return payload, notes
    return {"type": "function", "function": function}, notes


def to_anthropic(tool: ToolSchema, **options: Any) -> Emitted:
    """Anthropic Messages API tool definition."""
    notes: List[str] = []
    payload = {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.params_json_schema(),
    }
    if tool.returns is not None:
        notes.append("no return schema in the tool definition; returns dropped")
    if tool.effects.destructive:
        notes.append(
            "destructive tools have no marker here; put the warning in the "
            "description so the model can act on it"
        )
    return payload, notes


def to_gemini(tool: ToolSchema, **options: Any) -> Emitted:
    """Google Gemini function declaration.

    Gemini's schema dialect is a subset: no ``additionalProperties``, no
    ``examples``, no ``$``-prefixed keywords. Those keys are stripped rather
    than passed through, because Gemini rejects the whole declaration on an
    unknown field instead of ignoring it.
    """
    notes: List[str] = []
    schema = _strip_unsupported(tool.params_json_schema(), notes)
    return (
        {
            "name": tool.name,
            "description": tool.description,
            "parameters": schema,
        },
        notes,
    )


def _strip_unsupported(node: Any, notes: List[str]) -> Any:
    unsupported = ("additionalProperties", "examples", "default", "$schema")
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key in unsupported:
                if key == "default" and "dropped defaults" not in notes:
                    notes.append("dropped defaults")
                continue
            out[key] = _strip_unsupported(value, notes)
        return out
    if isinstance(node, list):
        return [_strip_unsupported(item, notes) for item in node]
    return node


def to_json_schema(tool: ToolSchema, **options: Any) -> Emitted:
    """Plain JSON Schema for the arguments, for anything not listed above."""
    schema = tool.params_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = tool.title or tool.name
    if tool.description:
        schema["description"] = tool.description
    return schema, []
