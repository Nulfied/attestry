# Attestry

**Verifiable trust infrastructure for AI agents.** Four things that keep going
wrong in agent systems, fixed by one mechanism underneath all four.

No server. No account. No API keys required. No runtime dependencies.

```bash
pip install attestry
```

---

## The four gaps

| | The problem | Attestry's answer |
|---|---|---|
| **Model drift** | Providers update models behind stable names. Nothing errors; behaviour just changes. You find out from a customer. | Record what the behaviour *was*, re-check it nightly, and report movement separately from failure. |
| **Tool schema chaos** | MCP wants `inputSchema`. Anthropic wants `input_schema`. OpenAI wants `parameters`. LangChain wants a pydantic model. CrewAI wants a `BaseTool` subclass. | Define the tool once; generate all ten shapes, and report what each translation loses. |
| **Invisible access** | An agent reads your mail, calendar and files. The audit trail, if any, is JSON nobody reads. | Receipts in plain English, checked against consent grants that can actually refuse. |
| **Unverifiable skills** | Sharing agent skills means trusting a registry server to keep telling the truth. | Content-addressed packages, signed provenance, and a ledger you can sync over git. |

## The one mechanism

All four write to the same thing: **an append-only, hash-chained, signed ledger**
— one JSONL file you commit alongside your code.

That is what makes this one tool instead of four scripts in a repository. A
drift run, a mailbox access, a tool schema change and a package publication are
all entries in the same chain, so **one command verifies every claim any
subsystem has ever made**:

```
$ attestry ledger verify
OK  12 entries, 12 signed, chain intact
  head   0edf10907b3ea58671f46413ddd43818d612cf4af019ec2c86154b244a5d4f56
  merkle 638c02e307e766c681e1473d6f4200770a2c6736e9fa46e86c5dba1b51f2859e

$ attestry ledger stats
12 entries
  drift      3
  ledger     3
  receipt    2
  registry   2
  schema     2
```

Edit any byte of any entry and every hash after it stops matching. Signatures
mean appending needs a key, not just write access to the file.

---

## Sixty seconds, no API key

The bundled `echo` provider is a deterministic stand-in, so the whole loop works
offline and free. Set `ATTESTRY_ECHO_VARIANT=b` and it answers differently —
which is how you can watch drift detection actually fire.

```bash
mkdir demo && cd demo
attestry init .
attestry drift run example          # first run records the baseline
ATTESTRY_ECHO_VARIANT=b attestry drift run example --diff
```

The second run:

```
suite    example
model    echo:demo

  !! model identity changed: 'demo' was serving 'demo-variant-a', now serves
     'demo-variant-b' (3 case(s)). Any movement below is explained by this.

  case                     status   score   detail
  --------------------------------------------------------------------------
  refund-window            drift    0.535   behaviour moved (similarity 0.535)
  tone-check               drift    0.530   behaviour moved (similarity 0.530)
  length-guard             drift    0.485   behaviour moved (similarity 0.485)

  DRIFT  (3 drift)

--- refund-window ---
--- baseline
+++ current
-Answer: How long does a customer have to request a refund?. Confidence: high.
+I think the answer here is how long does a customer have to request a refund?,
+though it depends on context.
```

Exit code 1. In CI that fails the build, and the first line already tells you
*why* the outputs moved.

Then point it at a real model — same suite, same commands:

```bash
attestry drift run example --provider ollama --model llama3      # free, local
attestry drift run example --provider anthropic --model claude-sonnet-5
```

---

## 1. Model-drift detection

A suite is a JSON file you commit: prompts, and what counts as a correct answer.

```json
{
  "name": "support",
  "provider": "anthropic",
  "model": "claude-sonnet-5",
  "params": { "temperature": 0 },
  "drift_threshold": 0.95,
  "cases": [
    {
      "id": "refund-window",
      "prompt": "How long does a customer have to request a refund?",
      "system": "You are a concise support agent.",
      "expect": { "mode": "contains_all", "value": ["refund", "14 days"] }
    },
    {
      "id": "no-apology-boilerplate",
      "prompt": "Explain our uptime guarantee to an annoyed customer.",
      "expect": { "mode": "never_contains", "value": ["sorry for the inconvenience"] }
    },
    {
      "id": "structured-output",
      "prompt": "Classify this ticket. Reply with JSON.",
      "expect": { "mode": "json_shape", "value": { "category": "string", "urgency": "integer" } }
    }
  ]
}
```

Expectation modes: `exact`, `normalized`, `contains_all`, `contains_any`,
`never_contains`, `regex`, `json_shape`, `numeric`, `similarity`.

### Why two verdicts per case, not one

Every case is graded twice, and keeping these apart is the whole point:

- **Did it meet the expectation?** A pass/fail assertion. Fails loudly.
- **Did the behaviour move?** Compared against the last accepted output for the
  same prompt.

A case can keep passing while the answer changes character completely — longer,
differently formatted, suddenly hedged. That is drift, and it is the early
warning. By the time your assertions start failing you have usually been
shipping different behaviour for weeks.

So the exit codes differ: `1` for moved, `2` for broken.

### The model-identity check

Every provider response carries the model string the provider actually *served*.
Attestry compares it against what the baseline saw — not against the alias you
asked for.

That distinction matters. `gpt-4o` resolving to `gpt-4o-2024-08-06` is normal.
That snapshot *changing between runs* is the event this whole subsystem exists
to catch, and comparing only against the alias would miss it entirely. OpenAI's
`system_fingerprint` is captured for the same reason.

### What goes where

| | Contents | Committed? |
|---|---|---|
| the ledger | digests, scores, statuses | yes — signed, tamper-evident |
| `drift/baselines/` | the accepted outputs | yes — this is what a reviewer reads |
| `drift/runs/` | full outputs of every run | no — gitignored |

Model outputs echo whatever was in the prompt. Writing them into a signed
append-only log that you then push to a shared repository would take a privacy
problem and make it permanent. The digest proves what was seen without
disclosing it.

```bash
attestry drift show support refund-window     # when exactly did this change?
```

```
entry  when                   output digest  status   served model
#2     2026-09-25T23:54:03Z   f3c959bfa51e   ok       claude-sonnet-5
#4     2026-09-26T04:11:44Z   560a1b58ecf8   drift    claude-sonnet-5   <- changed here
```

---

## 2. One tool definition, ten frameworks

```bash
attestry schema ingest their-mcp-tools.json   # start from tools you already have
attestry schema emit send_invoice --all --out ./adapters
```

Targets: `mcp`, `openai`, `ollama`, `anthropic`, `gemini`, `json-schema`,
`langchain`, `autogen`, `crewai`, `pydantic`.

The last four emit **Python source**, because those frameworks do not consume a
JSON description of a tool — they want a pydantic model, an annotated signature,
a `BaseTool` subclass:

```python
# Generated by Attestry from the neutral tool schema for 'send_invoice'.
# NTS interface digest: d2699c38f63837e9
# Declared effects: writes billing records; uses the network; can destroy data

class SendInvoiceInput(BaseModel):
    'Email an invoice to a customer.'
    customer_id: str = Field(..., description='Account id.')
    amount: float = Field(..., description='Amount in USD.', ge=0)
    cc: Optional[List[str]] = Field(None, description='Extra recipients.')


class SendInvoiceTool(BaseTool):
    name: str = 'send_invoice'
    description: str = 'Email an invoice to a customer.'
    args_schema: Type[BaseModel] = SendInvoiceInput

    def _run(self, **kwargs: Any) -> Any:
        raise NotImplementedError('implement SendInvoiceTool._run')
```

Note the header. The declared effects survive into the framework that has
nowhere to put them, so "this tool can destroy data" does not get lost in
translation.

### Every emitter reports what it drops

```
$ attestry schema emit send_invoice --target openai --strict
  note (openai): strict mode: cc became nullable-but-required, so the model will
                 pass null rather than omitting it
  note (openai): no place to declare side effects; a caller cannot tell from this
                 payload that the tool writes or destroys data
```

Those losses are exactly where moving a tool between frameworks silently changes
its meaning. Round trips are tested: emit to MCP, OpenAI (including strict mode)
and Anthropic, parse back, and names, types and requiredness all survive.

### Tool schemas drift too

```bash
attestry schema register send_invoice
```

```
send_invoice: interface changed -- escalation
escalation (4):
  escalation  consent.data_classes     now touches financial, contact_info
  escalation  consent.egress           data can now leave to mail.example.com
  escalation  effects.destructive      can now destroy data
  escalation  effects.writes           now writes customer billing records
breaking (1):
  breaking    force                    new required parameter
```

Four severities, and **`escalation` is the one no other schema tool reports**:
the call signature did not break, but the tool now does more to the world than
it used to. That is the severity that matters when you are about to install
somebody else's skill.

`breaking` stops existing callers. `behaviour` still works but may act
differently. `cosmetic` is prose. Rewording a description is not a change —
the digest covers the interface, not the help text.

---

## 3. Consent receipts a human can read

```bash
attestry receipts record --actor agent:inbox-triage --action read \
  --resource email:gmail/INBOX --purpose "draft daily priorities" \
  --items 42 --fields subject,from --data-classes message_content
```

```
On 25 Sep 2026 at 23:54 UTC, the inbox-triage agent read 42 messages in your
Gmail inbox (subject and from only), in order to draft daily priorities. No data
left your machine.

  ledger entry   #7
  actor          agent:inbox-triage
  action         read on email:gmail/INBOX
  data touched   message_content
  consent        permitted by grant inbox-triage
  unusual        first recorded access by agent:inbox-triage
```

Structured audit logs already exist and nobody reads them, because reading one
requires knowing the schema. If the person whose inbox it was can read that
sentence and think *"it did what?"*, the system worked.

The renderer holds to two rules. It never invents specificity — an unrecognised
resource keeps its raw identifier rather than being dressed up in prose that
might be wrong. And it always states the egress position **in both directions**,
because "no data left your machine" is the sentence people most want, and
silence does not convey it.

### Grants can refuse, not just record

`.attestry/receipts/consent.json`, committed:

```json
{
  "default_deny": true,
  "grants": [
    {
      "id": "inbox-triage",
      "actor": "agent:inbox-triage",
      "resources": ["email:*/INBOX"],
      "actions": ["read", "list", "search"],
      "purposes": ["draft daily priorities", "flag urgent messages"],
      "data_classes": ["message_content", "contact_info"],
      "egress": [],
      "max_items": 200
    }
  ]
}
```

**Purpose is part of the permission.** "May read your calendar" and "may read
your calendar in order to schedule meetings" are different grants, and the
second is the one people think they gave. Most access-control systems leave this
out entirely.

In Python, with `enforce=True`, an ungranted access is stopped before your code
touches anything:

```python
from attestry.receipts import Recorder, ConsentPolicy

recorder = Recorder(ledger, ConsentPolicy.load(ws.consent_path),
                    actor="agent:inbox-triage", enforce=True)

with recorder.access("read", "email:gmail/INBOX",
                     purpose="draft daily priorities",
                     fields=["subject", "from"],
                     data_classes=["message_content"]) as event:
    messages = mailbox.fetch(limit=50)
    event.items = len(messages)      # filled in after the fact
```

The consent check runs on entry. The receipt is written on exit either way —
including when the body raises, because *"the agent tried to read your mailbox
and crashed"* is exactly the event an investigator wants and the one a naive
implementation drops.

### It flags what is out of character

Compared against recorded history, not statistics:

```
  unusual   agent:inbox-triage has only ever read before; this is its first
            write-type action (send)
  unusual   touched 900 items, more than three times the previous high of 42
  unusual   data sent to api.example.com for the first time
  unusual   first access to financial by this actor
```

### Denied attempts are counted, never credited

```bash
attestry receipts digest --period "18-25 September 2026"
```

```
5 accesses by 2 agents, touching 42 items in total.
Nothing was changed, sent or deleted.
No data left your machine.
3 attempts refused by policy (one of which would have sent data to api.example.com).

the inbox-triage agent
  your Gmail inbox -- 42 items
  refused: send on your Gmail Sent folder (reply to customers)
  refused: read on your Gmail inbox (train a model)
  stated purposes: draft daily priorities
```

A refused read touched nothing, so its item count and its intended egress stay
out of every total. A receipt that overstates what happened is worse than no
receipt.

Also: `attestry receipts html --out receipts.html` for a self-contained page
with no scripts and no external assets, and `attestry receipts check` to
re-check recorded history against the policy as it stands today — which catches
grants that were later narrowed or expired.

---

## 4. A skill registry with no server

```bash
attestry registry pack ./my-skill
attestry registry publish ./my-skill --source https://example.com/my-skill-1.0.0.tar.gz
attestry registry install my-skill@^1.0.0
```

The ledger **is** the index. A package's digest is a Merkle root over its **file
tree** — not over the archive bytes, because tar and zip embed timestamps and
ordering, and a content address that depends on who ran the build is not a
content address.

What that substitution buys, cryptographically rather than socially:

- **provenance** — publications are signed, so "who published this" is a fact
  about the entry, not a claim about an account;
- **immutability** — republishing a version with different content is refused,
  because the earlier entry is still in the chain saying what that version was;
- **transparency** — you cannot show one person one version and somebody else a
  different one without producing two ledgers that visibly fork;
- **no operator** — sync over git, a URL, a shared drive, a USB stick.

```
$ attestry registry publish ./hello-web
REFUSED: hello-web@1.0.0 was already published as 9013e3f93e80 at entry #1, but
this package hashes to 8a2c1f0b4e91. Published versions are immutable -- release
a new version instead.
```

Installing verifies entirely in memory before a single byte reaches the
filesystem, and keeps working afterwards:

```
$ attestry registry install hello-web@1.0.0 --from ./tampered.tar.gz
attestry: hello-web@1.0.0 does not match the ledger: expected 9013e3f93e80, the
fetched archive hashes to d0c17f2c8281. The source has been altered since
publication.

$ attestry registry verify ./installed hello-web@1.0.0
MISMATCH: on disk hashes to d0c17f2c8281, ledger says 9013e3f93e80
```

Archive members that try to escape the extraction directory are rejected rather
than extracted, because installing a stranger's skill is exactly where that
matters.

### What it deliberately does not solve

Namespace arbitration. Two people can publish `pdf-tools` from different keys,
and no amount of hashing decides which one deserves the name.

```
$ attestry registry conflicts
pdf-tools@1.0.0 was published 2 times with different content:
  #14    2026-09-20T09:12:03Z  digest 9013e3f93e80  by 2185f517b640c9c6
  #31    2026-09-24T17:40:55Z  digest 61ba0c7d4e12  by af5a0aef8f5ad858

The same version exists with different content. Nothing can decide this
automatically -- trust only the publisher you meant to trust.
```

Trust settles it: you install from keys you chose, which is roughly how you
already decide whose code to run.

---

## Verification, in more detail

### Trust modes

| Mode | Behaviour | Use it for |
|---|---|---|
| `strict` | only key ids you added by hand | CI, consuming other people's skills, audits |
| `tofu` | trust on first use, then pinned — SSH host keys | a single developer, the default |
| `open` | signatures checked, trust not enforced | local development only |

Public keys travel inside the ledger in `ledger.key-trusted` entries, so the
file is self-describing: hand somebody the ledger and one trusted key id and
they can check the whole thing.

### Revocation asks a question most tools skip

```bash
attestry ledger revoke <keyid> --reason "rotated" --invalidates after
attestry ledger revoke <keyid> --reason "leaked"  --invalidates all
```

Rotation means everything signed beforehand is still good. Compromise means you
cannot believe anything it ever signed, because whoever held the key could have
backdated entries. Getting this wrong in either direction is harmful, so
Attestry refuses to guess and makes the flag required.

### Proving one entry without revealing the others

```bash
attestry ledger checkpoint                     # publish a Merkle root
attestry ledger prove 7 --out proof.json       # ~log2(n) hashes
attestry ledger prove --check proof.json       # anyone, offline
```

You can prove to an auditor that a particular access was recorded when you say
it was, without disclosing everything else the agent touched that week. The
proof re-hashes the entry from its own contents, so it cannot claim inclusion
for contents that were swapped afterwards.

### Syncing and forks

```bash
attestry ledger export shared.jsonl
attestry ledger sync https://example.com/ledger.jsonl
```

Merging is only ever a fast-forward. Incoming entries are verified **before**
they are merged, never after — appending somebody else's file to your own signed
log and checking it later would mean your ledger had already vouched for content
you had not examined. Genuine divergence is reported, not resolved:

```
FORK: ledgers agree up to #3 then diverge: local a3ded7794f4d, incoming cd0bbeff8044

Histories diverge, so no automatic merge is possible. Compare the two
ledgers and decide which history is the real one.
```

Which history is the true one is a question about the world, not about the data.

---

## Cryptography

Ed25519 throughout, with two interchangeable backends:

- **pure Python**, bundled, following the RFC 8032 reference implementation.
  Tested against the RFC's own vectors.
- **`cryptography`**, used automatically when importable (`pip install
  attestry[fast]`): constant-time and roughly 100× faster.

Same key format, same 64-byte signatures. A test signs with each and verifies
with the other.

The bundled implementation ships because a registry whose signatures only verify
after you install a native dependency is not much of a decentralised registry.
It is **not constant-time** — point multiplication branches on secret scalar
bits. For signing your own ledger on your own machine that is an acceptable
trade, and verification touches only public data. On shared hardware, install
the fast backend.

Other choices worth knowing about:

- **Canonical JSON** (close to RFC 8785) before anything is hashed or signed,
  with UTF-16 code-unit key ordering so a JavaScript implementation agrees.
  `NaN`, `Infinity` and non-string keys are rejected rather than coerced.
- **Merkle trees** follow RFC 6962 with domain separation — leaves prefixed
  `0x00`, nodes `0x01` — so an internal node cannot be replayed as a leaf.
  Proofs are tested exhaustively for every tree size from 1 to 33, including
  truncated, padded and wrong-index proofs.
- **Signatures cover the canonical payload**, not the hex hash, so a verifier
  never has to trust the `hash` field it was handed.
- **Chain verification compares recomputed hashes**, so editing a body and
  leaving the `hash` field alone still breaks the links after it.

---

## In CI

```yaml
- run: pip install attestry
- run: attestry ledger verify --require-signatures   # 4 if the log was touched
- run: attestry schema register                       # 1 on escalation/breaking
- run: attestry drift run support                     # 1 moved, 2 broken
```

| Code | Meaning |
|---|---|
| 0 | fine |
| 1 | something moved — drift, or a schema changed |
| 2 | something failed — an expectation broke, a check did not pass |
| 3 | something could not run — provider unreachable, bad arguments |
| 4 | something is untrustworthy — broken chain, bad signature, untrusted key |

Code 4 is deliberately separate. A failing test and a ledger that does not
verify are different emergencies.

---

## Python API

```python
from attestry import Workspace, Ledger, Keyring, TrustStore

ws = Workspace.init(".")
key = Keyring(ws.keys_dir).create("ci")
ledger = Ledger(ws.ledger_path, key=key, trust=TrustStore(ws.trust_path))

# 1. drift
from attestry.drift import Suite, run_suite, get_provider, record_run
run = run_suite(Suite.load("support.suite.json"), get_provider("ollama", "llama3"))
record_run(ledger, run)

# 2. schema
from attestry.schema import ToolSchema, Param, emit, from_callable
payload, notes = emit(from_callable(my_function), "mcp")

# 3. receipts
from attestry.receipts import Recorder, ConsentPolicy
recorder = Recorder(ledger, ConsentPolicy.load(ws.consent_path), enforce=True)

# 4. registry
from attestry.registry import Package, Registry
Registry(ledger, trust, ws.cache_dir).publish(Package.from_dir("./my-skill"))

assert ledger.verify().ok    # covers all four
```

## Layout

```
.attestry/
  ledger.jsonl            the log: one canonical JSON entry per line
  trust.json              keys this machine accepts signatures from
  config.json             workspace settings
  keys/<keyid>.json       private keys, owner-readable, gitignored
  drift/suites/*.json     prompts and expectations
  drift/baselines/*.json  accepted behaviour  <- commit this
  drift/runs/*.json       full outputs, gitignored
  schemas/*.nts.json      neutral tool schemas
  receipts/consent.json   what each agent may touch, and why
  registry/cache/         verified packages, gitignored
```

Commit `.attestry`. The private keys, package cache and raw run logs are
machine-local and the directory carries its own `.gitignore` for them.

The ledger is a plain append-only text file on purpose. You can read it with
`tail`, review it in a pull request, and merge it by concatenation. A database
would have been easier to query and much harder to trust.

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | why one ledger, and how the four subsystems compose |
| [docs/LEDGER.md](docs/LEDGER.md) | the on-disk format, precisely enough to reimplement |
| [docs/NTS.md](docs/NTS.md) | the Neutral Tool Schema spec and per-target mappings |
| [docs/DRIFT.md](docs/DRIFT.md) | suite format, expectation modes, CI patterns |
| [docs/RECEIPTS.md](docs/RECEIPTS.md) | the access model, grants, and the rendering rules |
| [docs/REGISTRY.md](docs/REGISTRY.md) | package format, digests, trust, syncing |

## Limitations, stated plainly

- **Drift similarity is lexical**, not semantic. It will not notice that two
  differently worded answers mean the same thing. For a regression detector that
  is the correct trade: the question is whether the output changed, not whether
  it is still true. It also means no embedding model, no network, and identical
  results on every machine.
- **Receipts are only as honest as their instrumentation.** Attestry records
  what your code tells it. It is a transparency and consent layer, not a sandbox
  — it cannot see an access that never called it. `enforce=True` refuses
  accesses that go through the recorder, and nothing else.
- **No consensus.** Two people appending offline produce two valid ledgers.
  Forks are detected, never silently resolved.
- **No namespace authority** in the registry, by design. Trust decides.
- **The keyring is developer-grade.** Owner-only file permissions where the
  platform supports it; not a hardware token.

## Status

0.1.0. The ledger format is versioned and documented; changes to it will come
with a migration path. 269 tests, no runtime dependencies, Python 3.9+, tested
on Linux, macOS and Windows with both crypto backends.

## License

MIT — Nulfied
