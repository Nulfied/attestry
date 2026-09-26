# The skill registry

## The trade being made

A centralised registry gives you provenance, immutability and a consistent view
of what exists — but socially, by running a server you have to trust and somebody
has to pay for. Replace the index with a signed append-only ledger and you get
the same properties cryptographically:

| Property | Centralised registry | Attestry |
|---|---|---|
| provenance | an account on a server | an Ed25519 signature on the entry |
| immutability | the operator's policy | the earlier entry is still in the chain |
| consistency | one database | divergence produces a visible fork |
| availability | the operator's uptime | any file transport: git, URL, drive, USB |
| namespaces | the operator arbitrates | **not solved** — see below |

## Package format

A directory with `skill.json`:

```json
{
  "name": "hello-web",
  "version": "1.0.0",
  "description": "Fetch a URL and return its readable text.",
  "author": "Nulfied",
  "license": "MIT",
  "entry": "skill.py",
  "runtime": "python>=3.9",
  "requires": [],
  "tools": ["fetch_page.nts.json"],
  "keywords": ["http"],
  "homepage": "https://example.com"
}
```

Names are lowercase, optionally scoped `@scope/name`. Versions are semver
(`1.2.3`, `1.2.3-rc.1`). Unknown fields are preserved.

`tools` points at [NTS](NTS.md) documents inside the package. Those declare
`effects` and `consent`, which is what `attestry registry show` surfaces before
you install — so "adds two numbers" cannot quietly also mean "posts to Slack".

## The digest

A Merkle root over the **file tree**, not over the archive bytes.

That distinction is the whole design. Tar and zip embed timestamps, ownership and
member order, so two archives of identical content hash differently on two
machines — and a content address that depends on who ran the build is not a
content address.

```
leaf_i = SHA-256(0x00 || canonical_json({
    "path":   "<POSIX relative path>",
    "digest": "<SHA-256 of the file contents, hex>",
    "exec":   <bool>
}))
```

Leaves sorted by path, then combined with RFC 6962 node hashing
(`SHA-256(0x01 || left || right)`).

Including the path stops two packages with the same files under different names
colliding. Including the executable bit stops a silent `chmod +x` from passing
verification. Paths are always POSIX-style, so a package built on Windows and one
built on Linux produce the same digest.

`Package.inclusion_proof(path)` proves one file belongs to a package without
revealing the others.

### Excluded from the digest

`.git`, `.hg`, `.svn`, `.attestry`, `__pycache__`, `.pytest_cache`,
`.mypy_cache`, `.venv`, `venv`, `node_modules`, `.DS_Store`, `*.pyc`, `*.pyo`,
`*.egg-info`, `*.tar.gz`, plus anything in `.attestryignore` (which is itself
excluded).

Symlinks are **refused**. A package whose content depends on whatever the target
happens to be at install time defeats content addressing.

Limits: 32 MB per file, 128 MB per package. A 200 MB member is either a mistake
or an attempt to fill somebody's disk on install.

### Archives

`attestry registry pack` writes a deterministic `.tar.gz`: members sorted, mtime
0, uid/gid 0, empty owner names, mode 0644 or 0755, gzip mtime zeroed. Byte-identical
for identical content.

Verification uses the tree digest, so nothing depends on this — but reproducible
archives let anyone who repacks the source check the artefact.

## Publishing

```bash
attestry registry publish ./my-skill --source https://example.com/my-skill-1.0.0.tar.gz
```

Writes a signed `registry.publish` entry: name, version, digest, the full
manifest, a per-file digest list, total bytes, and fetch sources.

**Published versions are immutable.** Republishing with different content is
refused:

```
REFUSED: hello-web@1.0.0 was already published as 9013e3f93e80 at entry #1, but
this package hashes to 8a2c1f0b4e91. Published versions are immutable -- release
a new version instead.
```

Without that, a digest recorded in a lockfile stops meaning anything, and every
other guarantee here becomes decorative. Republishing *identical* content is also
refused, as a no-op worth telling you about.

`sources` are hints, not authority. An installer verifies whatever it fetches
against the digest in the ledger, so a compromised mirror cannot substitute
content — it can only fail.

## Resolving

```bash
attestry registry resolve hello-web            # highest trusted version
attestry registry resolve hello-web@1.0.0
attestry registry resolve hello-web@^1.2.0     # same major, at least 1.2.0
attestry registry resolve hello-web@~1.2.0     # same minor, at least 1.2.0
attestry registry resolve hello-web@>=1.2.0
```

Pre-releases sort below the release they precede, so `latest` never quietly
resolves to a release candidate, and numeric pre-release parts sort numerically
(`rc.2` before `rc.10`).

Revoked versions never resolve. Untrusted publishers are excluded unless you pass
`--allow-untrusted`. The three failure messages are distinct, because the fix
differs in each case:

```
nothing published under the name 'pdf-tools'
no version of hello-web satisfies '9.0.0'; available: 1.0.0, 1.2.0
hello-web@1.0.0 was published by af5a0aef8f5ad858, which you do not trust: …
```

## Installing

```bash
attestry registry install hello-web@^1.0.0
```

1. Resolve, honouring trust.
2. Fetch from each recorded source in turn (local path, `file://`, or HTTPS).
3. Parse the archive **in memory**, rejecting members that would escape the
   extraction directory.
4. Recompute the tree digest and compare against the ledger.
5. Check the archive's manifest name and version match the publication.
6. Only then write to disk.
7. Record a signed `registry.install` entry.

Verification happens before a single byte reaches the filesystem. A package whose
content does not hash to what the ledger says gets nowhere near it:

```
attestry: hello-web@1.0.0 does not match the ledger: expected 9013e3f93e80, the
fetched archive hashes to d0c17f2c8281. The source has been altered since
publication.
```

Path traversal is handled explicitly rather than relying on `TarFile.extractall`,
which on older Pythons will happily write a member named
`../../.ssh/authorized_keys`. Installing a stranger's skill is exactly where that
matters.

### Afterwards

```bash
attestry registry verify ./installed hello-web@1.0.0
```

```
MISMATCH: on disk hashes to d0c17f2c8281, ledger says 9013e3f93e80
```

## Revoking

```bash
attestry registry revoke hello-web@1.0.0 --reason "leaked an API key in 1.0.0"
```

Appends `registry.revoke`. The original publication **stays in the chain** — it
just stops resolving. An append-only log does not get to forget; what it can do is
record a later statement that supersedes an earlier one, which is also the honest
description of what a revocation is.

## Distribution

```bash
attestry ledger export shared.jsonl
attestry registry remote add upstream https://example.com/ledger.jsonl
attestry ledger sync upstream
```

Syncing is fetching a text file and fast-forwarding. Incoming entries are verified
first — sequence numbers, hashes, links, and signatures against keys the incoming
file declares. If the incoming ledger is unsound, **nothing** is merged; a partial
merge of a broken log is worse than no merge.

Genuine divergence is reported, not resolved:

```
FORK: ledgers agree up to #3 then diverge: local a3ded7794f4d, incoming cd0bbeff8044
```

Two independently initialised ledgers have different genesis entries, so they fork
by construction. A shared registry works by everyone syncing from a common
ancestor — most naturally a ledger committed to a git repository, where the
existing review and merge machinery does the social part.

## Trust

Trust modes are described in [LEDGER.md](LEDGER.md). For a registry:

- **`strict`** for anything consuming other people's skills. Only keys you added.
- **`tofu`** pins a publisher on first sight and rejects any later change to the
  key behind that id.
- **`open`** for local development only.

Public keys travel in the ledger, so a synced ledger is self-describing: you need
the file and the key ids you decided to trust.

## The part that is not solved

Namespace arbitration. Two people can publish `pdf-tools` from different keys and
no amount of hashing decides who deserves the name.

```
$ attestry registry conflicts
pdf-tools@1.0.0 was published 2 times with different content:
  #14    2026-09-20T09:12:03Z  digest 9013e3f93e80  by 2185f517b640c9c6
  #31    2026-09-24T17:40:55Z  digest 61ba0c7d4e12  by af5a0aef8f5ad858
```

Attestry surfaces this and stops. Trust settles it: you install from keys you
chose. That is roughly how you already decide whose code to run, and claiming a
cryptographic answer to a social question would be the dishonest kind of
"decentralised".
