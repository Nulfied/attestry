"""Build an NTS document from a Python function.

The fastest path to a schema is usually the function you already wrote. This
reads its signature, type hints and docstring, and produces something you can
then correct by hand rather than compose from nothing.

Three docstring conventions are understood -- Google, NumPy and reST -- because
picking one and rejecting the others would just move the work rather than remove
it. Whatever cannot be inferred is left empty, and ``attestry schema validate``
lists exactly what is still missing.
"""

from __future__ import annotations

import inspect
import re
import typing
from typing import Any, Callable, Dict, List, Optional, Tuple

from .neutral import MISSING, Param, ToolSchema

__all__ = ["from_callable", "parse_docstring"]

_SIMPLE = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}

_SECTION = re.compile(
    r"^\s*(Args|Arguments|Parameters|Params|Keyword Args)\s*:?\s*$", re.IGNORECASE
)
_GOOGLE_PARAM = re.compile(r"^\s*([*\w]+)\s*(?:\(([^)]*)\))?\s*:\s*(.*)$")
_REST_PARAM = re.compile(r"^\s*:param\s+(?:[\w\[\], ]+\s+)?(\w+)\s*:\s*(.*)$")


def parse_docstring(doc: Optional[str]) -> Tuple[str, Dict[str, str]]:
    """Split a docstring into a summary and a map of parameter descriptions."""
    if not doc:
        return "", {}
    lines = inspect.cleandoc(doc).splitlines()
    summary: List[str] = []
    params: Dict[str, str] = {}
    in_params = False
    current: Optional[str] = None

    for index, line in enumerate(lines):
        rest = _REST_PARAM.match(line)
        if rest:
            in_params, current = True, rest.group(1)
            params[current] = rest.group(2).strip()
            continue
        if _SECTION.match(line):
            in_params, current = True, None
            continue
        if in_params:
            if not line.strip():
                continue
            # A NumPy section underline, or the start of a different section,
            # ends the parameter block.
            if set(line.strip()) <= {"-", "="} and line.strip():
                continue
            if re.match(r"^\s*(Returns|Raises|Yields|Examples?|Notes?)\s*:?\s*$", line, re.I):
                in_params, current = False, None
                continue
            match = _GOOGLE_PARAM.match(line)
            if match and not line.startswith("        "):
                current = match.group(1).lstrip("*")
                params[current] = match.group(3).strip()
            elif current:
                params[current] = (params[current] + " " + line.strip()).strip()
            continue
        # NumPy puts the parameter name and type on one line with the
        # description indented beneath, and marks the section with an underline.
        if index + 1 < len(lines) and set(lines[index + 1].strip()) == {"-"}:
            if re.match(r"^\s*Parameters\s*$", line, re.IGNORECASE):
                in_params = True
                continue
        summary.append(line)

    return "\n".join(summary).strip(), params


def _type_name(hint: Any) -> Tuple[str, Optional[Param], List[Any]]:
    """Map a type hint to an NTS type, plus item type and enum values."""
    if hint is inspect.Signature.empty or hint is Any:
        return "any", None, []
    if hint in _SIMPLE:
        return _SIMPLE[hint], None, []

    origin = typing.get_origin(hint)
    args = typing.get_args(hint)

    if origin is typing.Literal:
        return "enum", None, list(args)
    if origin in (list, set, tuple, frozenset):
        inner = args[0] if args else Any
        kind, _, _ = _type_name(inner)
        return "array", Param("item", kind), []
    if origin is dict:
        return "object", None, []
    if origin is typing.Union:
        # Optional[X] is Union[X, None]: unwrap to X, since optionality is
        # carried by requiredness rather than by the type.
        concrete = [a for a in args if a is not type(None)]
        if len(concrete) == 1:
            return _type_name(concrete[0])
        return "any", None, []
    if isinstance(hint, type) and issubclass(hint, bool):
        return "boolean", None, []
    return "any", None, []


def from_callable(
    func: Callable[..., Any],
    name: str = "",
    include_self: bool = False,
) -> ToolSchema:
    """Derive an NTS document from a function or method."""
    signature = inspect.signature(func)
    try:
        hints = typing.get_type_hints(func, include_extras=False)
    except Exception:
        # Unresolvable forward references should degrade to "any" rather than
        # stop you generating a schema at all.
        hints = {}
    summary, docs = parse_docstring(inspect.getdoc(func))

    params: List[Param] = []
    for param_name, spec in signature.parameters.items():
        if param_name in ("self", "cls") and not include_self:
            continue
        if spec.kind in (spec.VAR_POSITIONAL, spec.VAR_KEYWORD):
            continue
        hint = hints.get(param_name, spec.annotation)
        kind, items, values = _type_name(hint)
        has_default = spec.default is not inspect.Signature.empty
        params.append(
            Param(
                name=param_name,
                type=kind,
                description=docs.get(param_name, ""),
                required=not has_default,
                default=spec.default if has_default else MISSING,
                items=items,
                values=values,
            )
        )

    returns = None
    if "return" in hints and hints["return"] is not type(None):
        kind, items, values = _type_name(hints["return"])
        returns = Param(name="result", type=kind, items=items, values=values)

    return ToolSchema(
        name=name or getattr(func, "__name__", "tool"),
        description=summary,
        params=params,
        returns=returns,
    )
