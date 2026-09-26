"""The Neutral Tool Schema (NTS): describe a tool once.

MCP, OpenAI function calling, the Anthropic Messages API, LangChain, AutoGen and
CrewAI all want a description of the same thing -- a callable with typed
arguments -- and all six want it in a different shape. Supporting two frameworks
means writing the tool twice and keeping the copies honest by hand, which is a
thing nobody does for long.

NTS is the single source that the emitters in :mod:`attestry.schema.emit` render
into each of those shapes, and that the parsers in
:mod:`attestry.schema.ingest` recover from them. It is deliberately a little
richer than the intersection of the six, because the extra fields are what make
the other three Attestry subsystems work:

``effects``
    What the tool actually does -- reads, writes, network, destructive. The
    registry surfaces this before you install somebody's skill, so "adds two
    numbers" cannot quietly also mean "posts to Slack".

``consent``
    Which classes of personal data the tool touches and for what declared
    purpose. :mod:`attestry.receipts` checks real access against this, so a tool
    that declared it reads calendar titles and then reads attendee lists is
    caught rather than trusted.

Both degrade gracefully: emitters drop what a target framework has no room for,
and the information stays in the ledger where it still means something.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..util.canonical import digest_of
from ..util.errors import SchemaError

__all__ = [
    "NTS_VERSION",
    "TYPES",
    "MISSING",
    "Param",
    "ToolSchema",
    "Effects",
    "Consent",
    "DATA_CLASSES",
]

NTS_VERSION = "1"

#: The type vocabulary. Kept small on purpose: every one of these maps cleanly
#: onto JSON Schema, and onto Python type hints, in all six target frameworks.
TYPES = ("string", "integer", "number", "boolean", "enum", "array", "object", "any")

#: Tool names that work everywhere. OpenAI is the strictest of the six, so its
#: rule is the one adopted.
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")

#: Vocabulary for consent declarations, shared with the receipts subsystem so a
#: declaration and an actual access are comparable without a mapping table.
DATA_CLASSES = (
    "contact_info",
    "message_content",
    "calendar",
    "files",
    "location",
    "credentials",
    "financial",
    "health",
    "browsing",
    "identifiers",
    "other",
)

_PY_TYPES = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
    "array": "list",
    "object": "dict",
    "any": "Any",
}


class _Missing:
    """Sentinel: distinguishes "no default" from "defaults to None"."""

    _instance = None

    def __new__(cls) -> "_Missing":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING = _Missing()


class Param:
    """One argument, or one field inside an object argument."""

    __slots__ = (
        "name", "type", "description", "required", "default", "values", "items",
        "properties", "minimum", "maximum", "min_items", "max_items",
        "min_length", "max_length", "pattern", "format", "examples", "additional",
    )

    def __init__(
        self,
        name: str,
        type: str = "string",
        description: str = "",
        required: bool = False,
        default: Any = MISSING,
        values: Optional[Sequence[Any]] = None,
        items: Optional["Param"] = None,
        properties: Optional[Sequence["Param"]] = None,
        minimum: Optional[float] = None,
        maximum: Optional[float] = None,
        min_items: Optional[int] = None,
        max_items: Optional[int] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        format: Optional[str] = None,
        examples: Optional[Sequence[Any]] = None,
        additional: bool = False,
    ) -> None:
        if type not in TYPES:
            raise SchemaError(
                "unknown type %r for parameter %r; expected one of %s"
                % (type, name, ", ".join(TYPES))
            )
        self.name = name
        self.type = type
        self.description = description
        self.required = required
        self.default = default
        self.values = list(values) if values else []
        self.items = items
        self.properties = list(properties) if properties else []
        self.minimum = minimum
        self.maximum = maximum
        self.min_items = min_items
        self.max_items = max_items
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.format = format
        self.examples = list(examples) if examples else []
        self.additional = additional

    def __repr__(self) -> str:
        return "Param(%s: %s%s)" % (
            self.name, self.type, "" if self.required else "?"
        )

    @property
    def has_default(self) -> bool:
        return not isinstance(self.default, _Missing)

    def python_type(self) -> str:
        """A type annotation string, used by the source-generating emitters."""
        if self.type == "enum":
            if self.values and all(isinstance(v, str) for v in self.values):
                return "Literal[%s]" % ", ".join(repr(v) for v in self.values)
            return "str"
        if self.type == "array":
            inner = self.items.python_type() if self.items else "Any"
            return "List[%s]" % inner
        if self.type == "object" and self.properties:
            return "Dict[str, Any]"
        return _PY_TYPES.get(self.type, "Any")

    # -- JSON Schema -----------------------------------------------------

    def to_json_schema(self) -> Dict[str, Any]:
        """Render as a JSON Schema fragment (draft 2020-12 compatible)."""
        out: Dict[str, Any] = {}
        if self.type == "enum":
            out["type"] = _enum_json_type(self.values)
            out["enum"] = list(self.values)
        elif self.type == "any":
            pass  # no "type" key at all means "anything"
        else:
            out["type"] = self.type
        if self.description:
            out["description"] = self.description
        if self.type == "array":
            out["items"] = self.items.to_json_schema() if self.items else {}
            if self.min_items is not None:
                out["minItems"] = self.min_items
            if self.max_items is not None:
                out["maxItems"] = self.max_items
        if self.type == "object":
            out["properties"] = {p.name: p.to_json_schema() for p in self.properties}
            required = [p.name for p in self.properties if p.required]
            if required:
                out["required"] = required
            out["additionalProperties"] = bool(self.additional)
        if self.minimum is not None:
            out["minimum"] = self.minimum
        if self.maximum is not None:
            out["maximum"] = self.maximum
        if self.min_length is not None:
            out["minLength"] = self.min_length
        if self.max_length is not None:
            out["maxLength"] = self.max_length
        if self.pattern:
            out["pattern"] = self.pattern
        if self.format:
            out["format"] = self.format
        if self.has_default:
            out["default"] = self.default
        if self.examples:
            out["examples"] = list(self.examples)
        return out

    @classmethod
    def from_json_schema(
        cls, name: str, schema: Mapping[str, Any], required: bool = False
    ) -> "Param":
        """Recover a Param from a JSON Schema fragment.

        Union types such as ``["string", "null"]`` -- which is how OpenAI's
        strict mode expresses an optional argument -- are collapsed back to the
        non-null branch with ``required=False``, so a round trip through strict
        mode does not permanently mark every optional parameter as nullable.
        """
        raw_type = schema.get("type", "any")
        nullable = False
        if isinstance(raw_type, list):
            options = [t for t in raw_type if t != "null"]
            nullable = "null" in raw_type
            raw_type = options[0] if options else "any"
        kind = "enum" if "enum" in schema else raw_type
        if kind not in TYPES:
            kind = "any"
        items = None
        if kind == "array" and isinstance(schema.get("items"), Mapping):
            items = cls.from_json_schema("item", schema["items"])
        properties: List[Param] = []
        if kind == "object":
            sub_required = set(schema.get("required") or [])
            for key, sub in (schema.get("properties") or {}).items():
                if isinstance(sub, Mapping):
                    properties.append(cls.from_json_schema(key, sub, key in sub_required))
        return cls(
            name=name,
            type=kind,
            description=schema.get("description", "") or "",
            required=required and not nullable,
            default=schema.get("default", MISSING),
            values=schema.get("enum"),
            items=items,
            properties=properties,
            minimum=schema.get("minimum"),
            maximum=schema.get("maximum"),
            min_items=schema.get("minItems"),
            max_items=schema.get("maxItems"),
            min_length=schema.get("minLength"),
            max_length=schema.get("maxLength"),
            pattern=schema.get("pattern"),
            format=schema.get("format"),
            examples=schema.get("examples"),
            additional=bool(schema.get("additionalProperties", False)),
        )

    # -- NTS document form -----------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"name": self.name, "type": self.type}
        if self.description:
            out["description"] = self.description
        if self.required:
            out["required"] = True
        if self.has_default:
            out["default"] = self.default
        if self.values:
            out["values"] = list(self.values)
        if self.items is not None:
            out["items"] = self.items.to_dict()
        if self.properties:
            out["properties"] = [p.to_dict() for p in self.properties]
        for attr, key in (
            ("minimum", "minimum"), ("maximum", "maximum"),
            ("min_items", "minItems"), ("max_items", "maxItems"),
            ("min_length", "minLength"), ("max_length", "maxLength"),
            ("pattern", "pattern"), ("format", "format"),
        ):
            value = getattr(self, attr)
            if value is not None:
                out[key] = value
        if self.examples:
            out["examples"] = list(self.examples)
        if self.additional:
            out["additional"] = True
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Param":
        return cls(
            name=data["name"],
            type=data.get("type", "string"),
            description=data.get("description", ""),
            required=bool(data.get("required", False)),
            default=data.get("default", MISSING),
            values=data.get("values"),
            items=cls.from_dict(data["items"]) if data.get("items") else None,
            properties=[cls.from_dict(p) for p in data.get("properties", [])],
            minimum=data.get("minimum"),
            maximum=data.get("maximum"),
            min_items=data.get("minItems"),
            max_items=data.get("maxItems"),
            min_length=data.get("minLength"),
            max_length=data.get("maxLength"),
            pattern=data.get("pattern"),
            format=data.get("format"),
            examples=data.get("examples"),
            additional=bool(data.get("additional", False)),
        )


def _enum_json_type(values: Sequence[Any]) -> str:
    if values and all(isinstance(v, bool) for v in values):
        return "boolean"
    if values and all(isinstance(v, int) and not isinstance(v, bool) for v in values):
        return "integer"
    if values and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in values):
        return "number"
    return "string"


class Effects:
    """What a tool does to the world, beyond returning a value."""

    __slots__ = ("reads", "writes", "network", "idempotent", "destructive")

    def __init__(
        self,
        reads: Optional[Sequence[str]] = None,
        writes: Optional[Sequence[str]] = None,
        network: bool = False,
        idempotent: bool = True,
        destructive: bool = False,
    ) -> None:
        self.reads = list(reads or [])
        self.writes = list(writes or [])
        self.network = network
        self.idempotent = idempotent
        self.destructive = destructive

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reads": self.reads,
            "writes": self.writes,
            "network": self.network,
            "idempotent": self.idempotent,
            "destructive": self.destructive,
        }

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "Effects":
        data = data or {}
        return cls(
            reads=data.get("reads"),
            writes=data.get("writes"),
            network=bool(data.get("network", False)),
            idempotent=bool(data.get("idempotent", True)),
            destructive=bool(data.get("destructive", False)),
        )

    def summary(self) -> str:
        bits = []
        if self.reads:
            bits.append("reads " + ", ".join(self.reads))
        if self.writes:
            bits.append("writes " + ", ".join(self.writes))
        if self.network:
            bits.append("uses the network")
        if self.destructive:
            bits.append("can destroy data")
        return "; ".join(bits) or "no declared side effects"


class Consent:
    """What personal data a tool expects to touch, and why."""

    __slots__ = ("required", "data_classes", "purpose", "egress")

    def __init__(
        self,
        required: bool = False,
        data_classes: Optional[Sequence[str]] = None,
        purpose: str = "",
        egress: Optional[Sequence[str]] = None,
    ) -> None:
        self.required = required
        self.data_classes = list(data_classes or [])
        self.purpose = purpose
        self.egress = list(egress or [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required": self.required,
            "data_classes": self.data_classes,
            "purpose": self.purpose,
            "egress": self.egress,
        }

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "Consent":
        data = data or {}
        return cls(
            required=bool(data.get("required", False)),
            data_classes=data.get("data_classes"),
            purpose=data.get("purpose", ""),
            egress=data.get("egress"),
        )


class ToolSchema:
    """One tool, described once."""

    __slots__ = (
        "name", "title", "description", "params", "returns",
        "effects", "consent", "version", "tags",
    )

    def __init__(
        self,
        name: str,
        description: str = "",
        params: Optional[Sequence[Param]] = None,
        returns: Optional[Param] = None,
        title: str = "",
        effects: Optional[Effects] = None,
        consent: Optional[Consent] = None,
        version: str = "",
        tags: Optional[Sequence[str]] = None,
    ) -> None:
        self.name = name
        self.title = title
        self.description = description
        self.params = list(params or [])
        self.returns = returns
        self.effects = effects or Effects()
        self.consent = consent or Consent()
        self.version = version
        self.tags = list(tags or [])

    def __repr__(self) -> str:
        return "ToolSchema(%s, %d params)" % (self.name, len(self.params))

    def param(self, name: str) -> Optional[Param]:
        for candidate in self.params:
            if candidate.name == name:
                return candidate
        return None

    # -- validation ------------------------------------------------------

    def validate(self) -> List[str]:
        """Return a list of problems. Empty means the schema is sound.

        Returning warnings rather than raising is deliberate: most of these are
        about a schema being *unhelpful to a model* rather than malformed, and
        it should still be possible to emit one while you fix it.
        """
        problems: List[str] = []
        if not NAME_RE.match(self.name or ""):
            problems.append(
                "name %r must start with a letter or underscore and use only "
                "letters, digits, underscore or dash (max 64 chars)" % (self.name,)
            )
        if not self.description:
            problems.append(
                "no description: models choose tools almost entirely on this field"
            )
        seen = set()
        for param in self.params:
            problems.extend(self._validate_param(param, seen, self.name))
        for cls in self.consent.data_classes:
            if cls not in DATA_CLASSES:
                problems.append(
                    "consent data class %r is not in the shared vocabulary; "
                    "receipts will not be able to match it" % cls
                )
        if self.consent.required and not self.consent.purpose:
            problems.append("consent.required is set but no purpose is declared")
        if self.effects.destructive and self.effects.idempotent:
            problems.append(
                "declared both destructive and idempotent, which is usually a mistake"
            )
        return problems

    def _validate_param(self, param: Param, seen: set, path: str) -> List[str]:
        problems: List[str] = []
        key = "%s.%s" % (path, param.name)
        if key in seen:
            problems.append("duplicate parameter %s" % key)
        seen.add(key)
        if not param.name:
            problems.append("a parameter under %s has no name" % path)
        if not param.description:
            problems.append("parameter %s has no description" % key)
        if param.type == "enum" and not param.values:
            problems.append("enum parameter %s lists no values" % key)
        if param.type == "array" and param.items is None:
            problems.append(
                "array parameter %s does not say what it contains; some "
                "providers reject an items-less array" % key
            )
        if param.required and param.has_default:
            problems.append(
                "parameter %s is required but also has a default, which cannot "
                "both be true" % key
            )
        if (
            param.minimum is not None
            and param.maximum is not None
            and param.minimum > param.maximum
        ):
            problems.append("parameter %s has minimum above maximum" % key)
        for child in param.properties:
            problems.extend(self._validate_param(child, seen, key))
        if param.items is not None:
            problems.extend(self._validate_param(param.items, seen, key))
        return problems

    def require_valid(self) -> "ToolSchema":
        problems = self.validate()
        if problems:
            raise SchemaError(
                "tool %s is not valid:\n  - %s" % (self.name, "\n  - ".join(problems))
            )
        return self

    # -- shapes ----------------------------------------------------------

    def params_json_schema(self, strict: bool = False) -> Dict[str, Any]:
        """The argument object as JSON Schema, which most targets want.

        ``strict`` follows OpenAI's structured-outputs rules: every property
        listed in ``required`` and ``additionalProperties: false``. Optional
        parameters survive as a union with ``null``, which is the only way to
        express "may be omitted" once everything must be required.
        """
        properties: Dict[str, Any] = {}
        required: List[str] = []
        for param in self.params:
            fragment = param.to_json_schema()
            if strict and not param.required:
                fragment = _nullable(fragment)
            properties[param.name] = fragment
            if param.required or strict:
                required.append(param.name)
        schema: Dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        schema["additionalProperties"] = False
        return schema

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "nts": NTS_VERSION,
            "name": self.name,
            "description": self.description,
            "params": [p.to_dict() for p in self.params],
            "effects": self.effects.to_dict(),
            "consent": self.consent.to_dict(),
        }
        if self.title:
            out["title"] = self.title
        if self.version:
            out["version"] = self.version
        if self.tags:
            out["tags"] = self.tags
        if self.returns is not None:
            out["returns"] = self.returns.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ToolSchema":
        declared = str(data.get("nts", NTS_VERSION))
        if declared != NTS_VERSION:
            raise SchemaError(
                "this build reads NTS version %s, document declares %s"
                % (NTS_VERSION, declared)
            )
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            params=[Param.from_dict(p) for p in data.get("params", [])],
            returns=Param.from_dict(data["returns"]) if data.get("returns") else None,
            title=data.get("title", ""),
            effects=Effects.from_dict(data.get("effects")),
            consent=Consent.from_dict(data.get("consent")),
            version=data.get("version", ""),
            tags=data.get("tags"),
        )

    def digest(self) -> str:
        """Content hash of the *interface*, ignoring prose.

        Descriptions are excluded so that rewording a tool's help text does not
        register as an interface change. What is hashed is the part that breaks
        a caller: names, types, requiredness, enum values, bounds.
        """
        return digest_of(_shape_of(self))


def _nullable(fragment: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(fragment)
    kind = out.get("type")
    if kind is None:
        return out
    if isinstance(kind, list):
        if "null" not in kind:
            out["type"] = list(kind) + ["null"]
    else:
        out["type"] = [kind, "null"]
    return out


def _shape_of(tool: ToolSchema) -> Dict[str, Any]:
    def shape_param(param: Param) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "name": param.name,
            "type": param.type,
            "required": param.required,
        }
        if param.values:
            out["values"] = sorted(param.values, key=repr)
        if param.items is not None:
            out["items"] = shape_param(param.items)
        if param.properties:
            out["properties"] = [shape_param(p) for p in param.properties]
        for attr in ("minimum", "maximum", "min_items", "max_items",
                     "min_length", "max_length", "pattern"):
            value = getattr(param, attr)
            if value is not None:
                out[attr] = value
        if param.has_default:
            out["default"] = param.default
        return out

    return {
        "name": tool.name,
        "params": [shape_param(p) for p in tool.params],
        "returns": shape_param(tool.returns) if tool.returns else None,
        "effects": tool.effects.to_dict(),
    }
