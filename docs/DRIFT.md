# Drift detection

## The failure this catches

A provider updates the model behind a stable name. Your code does not change.
Nothing raises. Outputs get a little longer, a little more hedged, formatted
slightly differently. Downstream parsing starts failing on 2% of requests, then
5%. You find out from a customer, and the git log has nothing in it.

The only defence is to have written down what the old behaviour was, in a form a
machine can re-check tonight.

## Suite format

`.attestry/drift/suites/<name>.suite.json`, committed:

```json
{
  "name": "support",
  "description": "Prompts the support pipeline actually sends.",
  "provider": "anthropic",
  "model": "claude-sonnet-5",
  "params": { "temperature": 0, "max_tokens": 512 },
  "drift_threshold": 0.95,
  "cases": [
    {
      "id": "refund-window",
      "prompt": "How long does a customer have to request a refund?",
      "system": "You are a concise support agent.",
      "expect": { "mode": "contains_all", "value": ["refund", "14 days"] },
      "threshold": 0.98,
      "tags": ["policy"],
      "params": { "max_tokens": 128 },
      "skip": false
    }
  ]
}
```

Case `params` override suite `params`. Case `threshold` overrides
`drift_threshold` for that case.

**Temperature defaults to 0 and `validate()` complains above it.** A suite that
samples measures its own sampling noise as much as the model's behaviour, and the
whole exercise depends on the only variable being the thing upstream.

## Expectation modes

| Mode | `value` | Passes when |
|---|---|---|
| `exact` | string | output is identical |
| `normalized` | string | identical ignoring case and whitespace |
| `contains_all` | string or list | every phrase appears (case-insensitive) |
| `contains_any` | string or list | at least one appears |
| `never_contains` | string or list | none appear |
| `regex` | pattern or list | every pattern matches (`IGNORECASE`, `MULTILINE`) |
| `json_shape` | skeleton | output parses as JSON and has the required shape |
| `numeric` | number | a number within `tolerance` appears |
| `similarity` | string | lexical similarity at or above `threshold` |
| `none` | — | always |

`json_shape` takes a skeleton of keys, with type names (`string`, `integer`,
`number`, `boolean`, `array`, `object`, `any`) or literal values:

```json
{ "mode": "json_shape",
  "value": { "category": "string", "urgency": "integer", "tags": ["string"] } }
```

Extra keys in the output are fine — this checks a contract, not equality. A
fenced ```` ```json ```` block is unwrapped first, because models fence JSON
constantly. A boolean is rejected where an integer is required, even though
Python would accept it.

`numeric` finds the closest number in the output and compares against
`tolerance` (default 0).

## Two verdicts, deliberately

Each case is graded twice:

**Expectation** — a pass/fail assertion against what you said you wanted.

**Movement** — a comparison against the last accepted output for the same prompt:

| Movement | Meaning |
|---|---|
| `new` | no baseline yet; this run becomes the reference |
| `stable` | byte-identical to the baseline |
| `minor` | changed but still at or above the threshold — usually a reworded sentence |
| `drift` | moved enough that you should look |

The case status is the worse of the two, with expectation failure outranking
movement, because a broken assertion is a definite problem while movement is a
signal to investigate.

| Status | Exit | Meaning |
|---|---|---|
| `ok` | 0 | passed, stable |
| `minor` | 0 | passed, slightly reworded |
| `drift` | 1 | passed, but behaviour moved materially |
| `fail` | 2 | expectation broken |
| `error` | 3 | provider unreachable |

A run takes the status of its worst case.

## Similarity is lexical, not semantic

`similarity()` blends two measures and averages them:

- `difflib.SequenceMatcher` ratio — sensitive to arrangement
- Jaccard overlap of lowercased word tokens — sensitive to vocabulary

Sequence ratio alone punishes a reordered sentence far more than a reader would.
Token overlap alone ignores structure entirely and calls a shuffled bag of the
same words identical. Averaging moves when either the wording or the arrangement
moves, which is what a threshold wants to sit on.

No embeddings, deliberately. It will not notice that two differently worded
answers mean the same thing — and for a regression detector that is the right
trade. The question is whether the output *changed*, not whether it is still
true. The payoff is no network, no model, no cost, and identical results on every
machine.

## The model-identity check

Every provider response carries the model string the provider **served**:

| Provider | Source |
|---|---|
| `anthropic` | `model` in the response |
| `openai` | `model`, plus `system_fingerprint` in metadata |
| `ollama` | `model` in the response |
| `echo` | `<model>-variant-<v>` |

Attestry compares the served name against **what the baseline recorded for the
same case** — not against the alias you requested:

```
!! model identity changed: 'claude-sonnet-5' was serving 'claude-sonnet-5-20260301',
   now serves 'claude-sonnet-5-20260715' (3 case(s)). Any movement below is
   explained by this.
```

An alias resolving to a pinned snapshot is normal. That snapshot changing between
runs is precisely the event this subsystem exists to catch, and comparing only
against the alias would miss it. Before a baseline exists, a served name differing
from the requested one is reported as informational.

## Providers

| Name | Cost | Notes |
|---|---|---|
| `echo` | free | deterministic stand-in; `ATTESTRY_ECHO_VARIANT=a|b` changes its behaviour on purpose |
| `ollama` | free | `OLLAMA_HOST`, default `http://localhost:11434` |
| `openai` | metered | `OPENAI_API_KEY`, `OPENAI_BASE_URL` |
| `anthropic` | metered | `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL` |

All over `urllib`; no HTTP dependency. Retries with backoff on 408, 409, 429 and
5xx; other 4xx fail immediately, since retrying a malformed request only wastes
quota. Error bodies are truncated before being raised, because providers
sometimes echo the prompt back in them. **API keys are never written to a run
file, a report or the ledger.**

`echo` exists so the test suite, the examples and a first run all work with no
key and no network — and so drift detection itself can be tested, which requires a
model whose behaviour you can change on purpose.

Adding one: subclass `attestry.drift.Provider`, implement `complete()`, return a
`Response(text, model, latency_ms, meta)`, register it in `PROVIDERS`.

## Baselines

The first run with no baseline creates one, the way snapshot-testing tools do,
and says so. `--no-pin-new` suppresses that.

```bash
attestry drift baseline support      # re-run and accept current behaviour
attestry drift run support --pin     # accept the run you just looked at
```

Errored and skipped cases are **never** written into a baseline. A transient
outage must not quietly become the thing you compare against.

Baselines are committed. The diff that changes accepted behaviour is the thing a
reviewer needs to see, and it belongs next to the diff that changed the prompt.

## Storage

| | Contents | Committed |
|---|---|---|
| ledger `drift.run` | per-case digests, scores, statuses, identity warnings | yes |
| `drift/baselines/<name>.json` | accepted output text | yes |
| `drift/runs/<name>-<ts>.json` | every output from that run | no |

The ledger gets digests, not text. Model outputs echo whatever was in the prompt;
writing them into a signed append-only log that you then push to a shared
repository would take a privacy problem and make it permanent. The digest proves
what was seen without disclosing it.

## History

```bash
attestry drift history support
attestry drift show support refund-window
```

```
entry  when                   output digest  status   served model
#2     2026-09-25T23:54:03Z   f3c959bfa51e   ok       claude-sonnet-5-20260301
#7     2026-10-02T04:11:44Z   f3c959bfa51e   ok       claude-sonnet-5-20260301
#9     2026-10-09T04:10:57Z   560a1b58ecf8   drift    claude-sonnet-5-20260715   <- changed here
```

This is the question that started the whole thing: *when exactly did this stop
behaving the way it used to?* Because the ledger is signed and hash-chained, the
answer is evidence rather than recollection.

## In CI

```yaml
- run: pip install attestry
- run: attestry drift run support --markdown >> $GITHUB_STEP_SUMMARY
```

Exit 1 on drift, 2 on a broken expectation, 3 if the provider was unreachable.
Treat 3 differently from 2 — an outage is not a regression.

Nightly against a real model, and on every pull request against `ollama` or
`echo`, is a reasonable split: the expensive signal runs on a schedule, the free
one gates merges.
