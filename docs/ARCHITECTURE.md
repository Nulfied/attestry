# Architecture

## Why these four things are one project

They look like four tools. They are one, because each of them is a claim that
needs to survive being checked later by somebody who was not there:

- *"this model behaved this way on 25 September"*
- *"this tool declared it only reads, back when you approved it"*
- *"this agent read 42 messages, for this stated purpose"*
- *"this package is what its author published"*

A claim you can edit afterwards is not evidence. So all four write to the same
append-only, hash-chained, signed log, and one command checks the lot:

```
$ attestry ledger verify
OK  12 entries, 12 signed, chain intact
```

Four separate tools would each need their own storage, their own integrity story,
their own key handling, and their own answer to "how do I prove this to an
auditor". Sharing the substrate means one implementation of the hard part and
four subsystems that are mostly domain logic.

## Layers

```
                         CLI  (attestry.cli)
                          |
    +--------------+------+-------+--------------+
    |              |              |              |
  drift         schema        receipts        registry
    |              |              |              |
    +--------------+------+-------+--------------+
                          |
                   ledger  (entries, chain, keys, trust, merkle)
                          |
                    util   (canonical JSON, errors, time)
```

Dependencies point downward only. The `ledger` package knows nothing about drift
runs or mailboxes; it stores entries with a `kind` and an opaque `body`. Each
subsystem knows the ledger, and — with two deliberate exceptions below — not each
other.

| Module | Responsibility |
|---|---|
| `util.canonical` | one byte sequence per value, on every machine, forever |
| `ledger.entry` | the immutable record; what the hash covers |
| `ledger.ed25519` | pure-Python RFC 8032, the zero-dependency fallback |
| `ledger.keys` | key generation, storage, the signature string format |
| `ledger.trust` | which keys you accept; revocation semantics |
| `ledger.merkle` | RFC 6962 trees, checkpoints, inclusion proofs |
| `ledger.chain` | append, verify, checkpoint, merge, fork detection |
| `workspace` | where everything lives |
| `drift` | suites, providers, comparison, runs |
| `schema` | NTS, emitters, parsers, diffing |
| `receipts` | access events, consent policy, plain-English rendering |
| `registry` | packaging, publishing, resolution, installation, syncing |

## Where the subsystems touch

Two crossings, both load-bearing:

**`schema` → `receipts`.** A tool's NTS `consent` block declares which data
classes it touches, for what purpose, and where data may go.
`receipts.event_from_schema` uses that as the default for a recorded access. So a
tool that declared it reads calendar titles and then reads attendee lists produces
a receipt that disagrees with its own declaration. Both sides draw from one
`DATA_CLASSES` vocabulary, so the comparison needs no mapping table.

**`schema` → `registry`.** A package's manifest lists its NTS documents.
`attestry registry show` surfaces their declared effects before you install, which
is the difference between "adds two numbers" and "adds two numbers and posts to
Slack".

Everything else meets only at the ledger, which is how it should be: `drift` does
not import `receipts`, and neither imports `registry`.

## Design decisions and their costs

### A text file, not a database

`ledger.jsonl` diffs in a pull request, merges by concatenation, survives being
copied to a USB stick, and can be verified by a script somebody writes in an
afternoon in another language.

*Cost:* no indexed queries. Reading entries is a linear scan, cached until the
file's mtime or size changes. For the hundreds-to-thousands of entries a project
accumulates this is irrelevant; for millions it would not be, and that is a
different product.

### Digests in the ledger, text on disk

`drift.run` entries carry per-case output digests, never output text. Model
outputs echo whatever was in the prompt; writing them into a signed append-only
log that you then push to a shared repository turns a privacy problem into a
permanent one. Baselines (committed) and run logs (gitignored) hold the text.

The same rule governs receipts: record what was touched, never what it said.

### Pure-Python crypto by default

A registry whose signatures only verify after you install a native dependency is
not much of a decentralised registry. The bundled Ed25519 follows the RFC 8032
reference implementation and is tested against the RFC's own vectors;
`cryptography` is used automatically when importable, and the two are
interchangeable in both directions.

*Cost:* the fallback is not constant-time. Documented, and irrelevant to
verification, which touches only public data.

### Refuse rather than guess

- a fork is reported, never auto-resolved — which history is real is a question
  about the world
- republishing a version with different content is refused, not accepted as an
  update
- `--invalidates` is required on key revocation, because rotation and compromise
  need opposite answers and guessing either way causes harm
- conflicting package names are surfaced, not arbitrated

Each of these is a place where a more convenient default would quietly destroy
the property the tool exists to provide.

### Two verdicts, four severities

`drift` separates "the assertion broke" from "the behaviour moved". `schema`
separates `escalation` from `breaking`. Both distinctions exist because the
merged version is useless: a suite that only reports failures misses the weeks
before your parsing breaks, and a schema diff that only reports signature changes
misses the release where a read-only tool learned to write.

Exit codes carry the distinction out to CI: 1 for moved, 2 for broken, 4 for
untrustworthy.

## Adding to it

**A new entry kind.** Pick `yournamespace.event`, append with `Ledger.append`.
Add it to `KNOWN_KINDS` so verification does not flag it as foreign. Nothing else
needs to change; verification is kind-agnostic.

**A new drift provider.** Subclass `attestry.drift.Provider`, implement
`complete()`, return a `Response`, register it in `PROVIDERS`. Populate
`Response.model` with what the provider actually served — that field is what makes
the identity check work.

**A new schema target.** Add a function to `attestry.schema.emit.wire` (JSON) or
`.code` (source), returning `(payload, notes)`, and register it in `TARGETS`. Put
whatever the target cannot represent into `notes`; those losses are the most
useful thing an emitter reports.

**A new resource scheme for receipts.** Add it to `RESOURCE_NOUNS` for
pluralisation and to `describe_resource` for the phrasing. Unrecognised schemes
already render safely, so this is polish rather than a requirement.

## Testing

269 tests, `unittest`, no plugins.

Each test gets a throwaway workspace with `ATTESTRY_HOME` pointed at it, so a run
can never touch a real ledger. The properties that get the most attention are the
ones everything else rests on:

- canonical JSON is order-independent and rejects what it must
- Merkle proofs verify for every tree size 1..33, and truncated, padded and
  wrong-index proofs are rejected
- Ed25519 matches the RFC 8032 vectors, and the two backends agree
- editing a ledger entry is caught, **and** so is editing one and recomputing its
  hash
- a denied access is never credited with items or egress
- an errored drift run never becomes a baseline
- a tampered archive never reaches the filesystem
- a broken incoming ledger is not partially merged

CI runs on Linux, macOS and Windows, on Python 3.9 and 3.13, with and without
`cryptography` installed, and re-runs the README quickstart to check the
documentation still describes the software.
