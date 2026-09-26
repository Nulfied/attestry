# The Neutral Tool Schema (NTS)

Version 1. Describe a tool once; emit it for every framework.

## Why another format

Six frameworks, six shapes for the same idea:

| Framework | Argument schema lives in | Shape |
|---|---|---|
| MCP | `inputSchema` | JSON Schema |
| Anthropic Messages | `input_schema` | JSON Schema |
| OpenAI chat | `function.parameters` | JSON Schema, optionally `strict` |
| OpenAI responses | `parameters` (flat) | as above |
| Gemini | `parameters` | a JSON Schema *subset* |
| LangChain | `args_schema` | a pydantic class |
| AutoGen | the function signature | `Annotated[...]` hints |
| CrewAI | `args_schema` on a `BaseTool` | a pydantic class |

Supporting two of these means writing the tool twice and keeping the copies
honest by hand, which nobody does for long.

NTS is deliberately a little richer than the intersection, because the extra
fields are what let the other three Attestry subsystems work.

## Document

```json
{
  "nts": "1",
  "name": "search_docs",
  "title": "Search documentation",
  "description": "Search the product documentation and return matching passages.",
  "version": "1.0.0",
  "tags": ["search"],
  "params": [ … ],
  "returns": { "name": "result", "type": "object" },
  "effects": {
    "reads": ["docs"],
    "writes": [],
    "network": true,
    "idempotent": true,
    "destructive": false
  },
  "consent": {
    "required": false,
    "data_classes": [],
    "purpose": "",
    "egress": []
  }
}
```

`name` must match `^[A-Za-z_][A-Za-z0-9_-]{0,63}$` — OpenAI is the strictest of
the targets, so its rule is the one adopted.

### The two fields other formats do not have

**`effects`** — what the tool does beyond returning a value. The registry
surfaces this before you install somebody's skill, so "adds two numbers" cannot
quietly also mean "posts to Slack". `attestry schema register` treats a *gain*
here as an `escalation`.

**`consent`** — which classes of personal data the tool touches and for what
declared purpose, drawn from the same vocabulary as
[receipts](RECEIPTS.md). `attestry.receipts.event_from_schema` uses it as the
default for a recorded access, so a tool that declared it reads calendar titles
and then reads attendee lists is caught rather than trusted.

Both degrade gracefully: emitters drop what a target has no room for and say so,
and the information stays in the ledger where it still means something.

## Parameters

```json
{
  "name": "limit",
  "type": "integer",
  "description": "How many results to return.",
  "required": false,
  "default": 10,
  "minimum": 1,
  "maximum": 50
}
```

Types: `string`, `integer`, `number`, `boolean`, `enum`, `array`, `object`,
`any`.

| Key | Applies to | Notes |
|---|---|---|
| `values` | `enum` | the permitted values; required for `enum` |
| `items` | `array` | a nested parameter describing the element |
| `properties` | `object` | a list of nested parameters |
| `additional` | `object` | allow keys beyond `properties`; default false |
| `minimum`, `maximum` | numbers | inclusive |
| `minLength`, `maxLength` | strings | |
| `minItems`, `maxItems` | arrays | |
| `pattern` | strings | regular expression |
| `format` | strings | passed through, e.g. `date-time` |
| `examples` | any | passed through where the target allows it |

`required` and `default` are mutually exclusive; `validate()` reports it.

## Validation

`attestry schema validate` returns problems rather than raising, because most are
about a schema being *unhelpful to a model* rather than malformed:

- name not portable across targets
- no description — models choose tools almost entirely on this field
- a parameter with no description
- `enum` with no values
- `array` with no `items` (some providers reject an items-less array)
- `required` together with `default`
- `minimum` above `maximum`
- a consent data class outside the shared vocabulary
- `destructive` and `idempotent` both set, which is usually a mistake

## Interface digest

`ToolSchema.digest()` hashes the **interface**, not the prose: names, types,
requiredness, enum values, bounds, defaults, and `effects`. Descriptions and
titles are excluded.

Consequence: rewording a description does not register as a change, and
`attestry schema register` writes no `schema.changed` entry for it. Adding a
required parameter does.

## Diff severities

| Severity | Meaning | Examples |
|---|---|---|
| `escalation` | the tool now does more to the world | gained `writes`, gained `network`, became `destructive`, new `data_classes`, new `egress`, now requires consent |
| `breaking` | existing callers stop working | parameter removed, type changed, became required, enum value withdrawn, bound tightened, pattern added |
| `behaviour` | still works, may act differently | new optional parameter, no longer required, enum value added, bound loosened, default changed, no longer idempotent |
| `cosmetic` | prose only | description reworded |

`escalation` is separate from `breaking` because "the signature broke" and "this
tool can now delete things" are different questions, and only the second one
should stop you installing a dependency.

`attestry schema diff` and `register` exit 1 when the worst severity is
`escalation` or `breaking`.

## Target mappings

### MCP

```json
{
  "name": "…", "title": "…", "description": "…",
  "inputSchema": { "type": "object", "properties": {…}, "required": [...],
                   "additionalProperties": false },
  "outputSchema": { … },
  "annotations": {
    "title": "…",
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": true
  }
}
```

The only target with somewhere for behavioural hints, so `effects` mostly
survives. `readOnlyHint` is derived: true when there are no `writes` and nothing
is `destructive`. `openWorldHint` maps from `network`.

Parsing back recovers `effects` from the hints. MCP says *whether* a tool writes,
not *what* it writes, so `writes` becomes `["unspecified"]` — honest, where
inventing a resource name would not be.

### OpenAI

Default (Chat Completions):

```json
{ "type": "function",
  "function": { "name": "…", "description": "…", "parameters": { … } } }
```

`--style responses` flattens the function fields to the top level.

`--strict` switches to structured outputs, which guarantees arguments match the
schema but requires **every** property in `required`. Optional parameters are
therefore emitted as a union with `null`:

```json
{ "limit": { "type": ["integer", "null"], … } }
```

The model must then pass them, possibly as null, rather than omitting them.
That is a real behavioural difference and the emitter reports it as a note.
Parsing back collapses `["integer","null"]` to `integer` with `required: false`,
so a round trip through strict mode does not permanently mark every optional
parameter as nullable.

### Anthropic

```json
{ "name": "…", "description": "…", "input_schema": { … } }
```

No return schema and no place for effects; both are reported as dropped. For a
destructive tool, put the warning in the description so the model can act on it.

### Gemini

A JSON Schema subset. `additionalProperties`, `examples`, `default` and
`$`-prefixed keywords are **stripped**, because Gemini rejects the whole
declaration on an unknown field rather than ignoring it.

### LangChain, CrewAI, pydantic

Generated Python source: a pydantic `BaseModel` for the arguments, plus a
`StructuredTool.from_function` binding (LangChain) or a `BaseTool` subclass
(CrewAI). NTS bounds become `Field` constraints (`ge`, `le`, `min_length`,
`max_length`, `pattern`). Non-required parameters without a default are typed
`Optional[...]`.

### AutoGen

A function signature with `Annotated[type, "description"]` hints, plus a
commented `register_function` call. Parameters are reordered so required ones
come first — a Python signature cannot put a defaulted parameter before a bare
one — and the reordering is reported, since a reader comparing the adapter to the
schema deserves to know why the list moved. Argument order is irrelevant to every
target here; they all pass by name.

### All code targets

The header records the source, the interface digest and the regeneration command,
so a diff shows immediately whether the interface moved or only the prose did.
Declared effects appear as a comment, so "can destroy data" survives into
frameworks with nowhere to put it.

Parameter names that are not Python identifiers are converted and reported; add a
pydantic alias if the wire name must be preserved.

## Importing what you already have

```bash
attestry schema ingest their-tools.json      # auto-detects the format
attestry schema from-python mypkg.tools:search
```

`detect_format` recognises NTS, MCP, Anthropic, OpenAI, Gemini and bare JSON
Schema. `from_any` accepts a single tool, a list, or a container with a `tools`,
`functions`, `function_declarations` or `toolDefinitions` key, because exports
arrive in all of those shapes.

`from-python` reads a function's signature, type hints and docstring. Google,
NumPy and reST docstring conventions are all understood. `Literal[...]` becomes
an `enum`; `Optional[X]` unwraps to `X` with `required: false`, since optionality
is carried by requiredness rather than by the type.

What cannot be recovered is what was never there. A tool imported from OpenAI has
no declared effects, because the format has nowhere to put them, so `effects` is
left empty rather than guessed — and `validate` keeps reminding you.
