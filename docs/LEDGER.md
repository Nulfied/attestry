# The ledger format

Version 1. Specified here precisely enough to write an independent verifier,
which is the point — a transparency log you can only check with the tool that
wrote it is not transparent.

## File

`.attestry/ledger.jsonl`: UTF-8, one JSON object per line, LF line endings,
append-only. Line *n* holds the entry with `seq == n - 1`.

A process killed mid-append can leave a partial final line. A reader must ignore
a malformed **last** line (that entry was never acknowledged to anyone) and treat
a malformed line anywhere else as corruption.

## Entry

```json
{
  "seq": 3,
  "ts": "2026-09-25T23:54:03Z",
  "kind": "receipt.access",
  "subject": "agent:inbox-triage",
  "body": { "...": "kind-specific" },
  "prev": "9013e3f93e800ef1f0e972b15e4742fb7cf07a3dc1bf1cb58f92e4dde586584e",
  "hash": "0edf10907b3ea58671f46413ddd43818d612cf4af019ec2c86154b244a5d4f56",
  "sig": "ed25519:2185f517b640c9c6:1a2b3c..."
}
```

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | position, from 0, contiguous |
| `ts` | string | RFC 3339, UTC, `Z` suffix, second precision |
| `kind` | string | `namespace.event`, lowercase, `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$` |
| `subject` | string | what the entry is about; free-form, namespace-specific |
| `body` | object | kind-specific payload |
| `prev` | hex | `hash` of entry `seq - 1`; 64 zeros for `seq == 0` |
| `hash` | hex | SHA-256 over the canonical payload (below) |
| `sig` | string | optional: `alg:keyid:hexsignature` |

### Canonical payload

`hash` covers exactly these six fields — not `hash`, not `sig`:

```json
{"seq":…,"ts":…,"kind":…,"subject":…,"body":…,"prev":…}
```

serialised as canonical JSON (below), then SHA-256, lowercase hex.

`sig` is made over **those same canonical bytes**, not over the hex hash. A
verifier therefore never has to trust the `hash` field it was handed — it
recomputes from content.

## Canonical JSON

Close to RFC 8785 (JCS), with two deliberate differences.

1. Object keys sorted by **UTF-16 code units**. Within the BMP this matches a
   code-point sort; it differs for astral characters, where a naive code-point
   sort would disagree with a JavaScript implementation of the same spec.
2. No insignificant whitespace. Separators are exactly `,` and `:`.
3. UTF-8 output. Non-ASCII characters are emitted literally, not escaped.
   String escaping is otherwise as JSON requires: `"`, `\` and control
   characters below `0x20` escaped, the short forms `\b \f \n \r \t` preferred.
4. Integers as their shortest decimal form.
5. **Floats keep a decimal point.** `1.0` serialises as `1.0`, not `1`.
   *This diverges from JCS.* It keeps `int` and `float` distinguishable, since a
   drift score of `1.0` and a count of `1` mean different things and a reader of
   the raw ledger should be able to tell without consulting a schema.
6. `NaN` and `Infinity` are **rejected**, not emitted. They are not JSON, and
   they would let two documents that compare equal in a host language hash
   differently.
7. Non-string object keys are **rejected**, not coerced. `{1: "a"}` and
   `{"1": "a"}` are different documents that would otherwise collide.

## Signatures

```
ed25519:<keyid>:<128 hex characters>
```

- `alg` is `ed25519`. It is carried inline so a second algorithm can be added
  without breaking the format.
- `keyid` is `SHA-256("attestry-keyid/v1" || public_key_bytes)`, first 16 hex
  characters. Domain-separated so a key id cannot collide with another SHA-256
  in the system computed over the same 32 bytes.
- The signature is raw Ed25519 (RFC 8032), 64 bytes, hex. `s` must be reduced
  mod the group order; a non-canonical `s` must be rejected, otherwise the same
  message verifies under two different encodings.

A verifier must also check that the `keyid` in the signature matches the key it
is verifying against. Otherwise a valid signature could be replayed while
pointing at somebody else's identity.

### Where public keys come from

`ledger.key-trusted` entries carry them:

```json
{ "keyid": "2185f517b640c9c6", "public": "<64 hex>", "alg": "ed25519", "label": "ci" }
```

Build this table in a **first pass** over the whole file, then verify. An entry
may be signed by a key announced later — which is the genesis case, where the
announcement is itself signed by the key it announces.

## Verification algorithm

```
declared = {}
for entry in entries:
    if entry.kind == "ledger.key-trusted":
        declared.setdefault(entry.body.keyid, entry.body.public)

previous = None
for index, entry in enumerate(entries):
    if entry.seq != index:                      -> error   seq-gap
    if entry.hash != recompute(entry):          -> error   hash-mismatch
    expected = recompute(previous) if previous else ZEROS
    if entry.prev != expected:                  -> error   broken-link
    if previous and entry.ts < previous.ts:      -> warning clock-regression
    verify entry.sig                             -> see below
    previous = entry
```

Two details that matter:

- Compare `prev` against the previous entry's **recomputed** hash, not its
  stored `hash` field. Trusting the stored value would let an attacker who edits
  a body and leaves the hash alone keep the chain looking intact from there on.
- When the previous entry already failed `hash-mismatch`, suppress the
  consequent `broken-link` — one edit should report as one problem.

Signature outcomes:

| Code | Severity | Meaning |
|---|---|---|
| `unsigned` | warning, or error with `--require-signatures` | no `sig` |
| `bad-signature` | error | malformed, or does not verify |
| `unknown-key` | error | public key is in neither the ledger nor the trust store |
| `untrusted-key` | error | verifies, but the key is not one you accept |

`unknown-key` and `untrusted-key` are separate because the fix differs: one is a
missing announcement, the other is a decision you have not made.

## Trust store

`.attestry/trust.json`:

```json
{
  "mode": "tofu",
  "keys":    { "<keyid>": { "public": "<hex>", "label": "", "note": "", "added": "…" } },
  "revoked": { "<keyid>": { "at": "…", "reason": "…", "invalidates": "after" } }
}
```

Modes: `strict` (only listed keys), `tofu` (pin on first sight, reject any later
change to the key behind an id), `open` (verify maths, do not enforce trust).

Revocation:

- `invalidates: "all"` — reject every signature from the key, whenever made.
  Correct for compromise, since the holder could have backdated entries. This
  does not consult timestamps at all.
- `invalidates: "after"` — reject only signatures made after the revocation.
  Correct for routine rotation.

Timestamps have second precision, so a signature made in the same second as an
`after` revocation is ambiguous. It is accepted: this comparison only runs for
rotation, where the old signatures are meant to stay valid, and the case where
timing cannot be trusted is covered by `all`.

## Checkpoints and inclusion proofs

`ledger.checkpoint` body:

```json
{ "size": 11, "root": "<hex>", "covers": "0..10" }
```

`root` is the Merkle root over the `hash` values of entries `0 .. size-1`, as
raw 32-byte digests used directly as leaves. The checkpoint entry is not part of
its own tree.

Merkle construction follows **RFC 6962**:

- leaf hash: `SHA-256(0x00 || data)`
- node hash: `SHA-256(0x01 || left || right)`
- split point: the largest power of two strictly less than the node's leaf count
- a single leaf is its own subtree root (the lone node is promoted)
- the empty tree is `SHA-256("")`

Domain separation is required. Without distinct prefixes an attacker could
present an internal node as a leaf, since both are 32 bytes.

Proof object:

```json
{
  "seq": 7, "leaf": "<hex>", "index": 7, "size": 11,
  "path": ["<hex>", "…"], "root": "<hex>",
  "checkpoint_seq": 11, "entry": { "…": "the full entry" }
}
```

A verifier must re-hash `entry` and compare against `leaf` before checking the
path, so a proof cannot claim inclusion for contents swapped after the fact. A
path with leftover or missing siblings must be rejected, so neither a padded nor
a truncated proof passes.

## Merging

Only fast-forward merges are valid. Given local `A` and incoming `B`:

1. For every `i` below `min(len(A), len(B))`, `A[i].hash` must equal `B[i].hash`.
   The first mismatch is a **fork** — refuse, and report the index.
2. If `len(B) <= len(A)`, nothing to do.
3. Otherwise append `B[len(A):]` verbatim.

Verify the incoming ledger **before** merging. Appending somebody else's entries
to your own signed log and checking later means your ledger has already vouched
for content you have not examined.

## Kinds

| Kind | Subject | Body highlights |
|---|---|---|
| `ledger.genesis` | key label | `tool`, `version` |
| `ledger.key-trusted` | key label | `keyid`, `public`, `alg`, `label` |
| `ledger.key-revoked` | keyid | `reason`, `invalidates` |
| `ledger.checkpoint` | `size=N` | `size`, `root`, `covers` |
| `drift.run` | suite name | `provider`, `model`, `status`, `counts`, `identity_warnings`, `cases[]` with per-case `digest` and scores |
| `drift.baseline` | suite name | `provider`, `model`, `cases` mapping case id to digest |
| `schema.registered` | tool name | `digest`, `schema`, `validation` |
| `schema.changed` | tool name | `from_digest`, `digest`, `severity`, `changes[]`, `schema` |
| `receipt.access` | actor | `event`, `decision`, `flags` |
| `receipt.denied` | actor | same shape; the access did not happen |
| `registry.publish` | `name@version` | `digest`, `manifest`, `files[]`, `bytes`, `sources[]` |
| `registry.install` | `name@version` | `digest`, `source`, `path`, `publisher` |
| `registry.revoke` | `name@version` | `digest`, `reason`, `revoked_at` |

Unknown kinds are permitted — the ledger is meant to be extensible — but a
verifier should surface them as warnings so a typo does not silently become a new
event type.

**`drift.run` never contains model output text**, only digests. Outputs echo
whatever was in the prompt, and a signed append-only log is a bad place to put
data you might later wish you had not committed.

## Concurrency

Appending takes an exclusive lock at `<ledger>.lock`, created with
`O_CREAT | O_EXCL`. A writer must re-read the file inside the lock before
computing `seq` and `prev`; building on a stale head forks the chain locally. A
lock older than 60 seconds is treated as stale and broken.
