# Changelog

All notable changes to Attestry are recorded here. Versions follow
[semantic versioning](https://semver.org). The ledger format is versioned
separately and documented in [docs/LEDGER.md](docs/LEDGER.md); a change to it
will come with a migration path.

## [0.1.0] - 2026-09-26

First release. Four subsystems over one signed, append-only, hash-chained ledger.

### Ledger

- Append-only JSONL log, one canonical JSON entry per line
- SHA-256 hash chaining; signatures cover the canonical payload rather than the
  hex hash, so a verifier never has to trust the `hash` field it was handed
- Ed25519, with a bundled pure-Python RFC 8032 implementation and automatic use
  of `cryptography` when it is importable
- Trust store with `strict`, `tofu` and `open` modes, and key revocation that
  distinguishes rotation (`--invalidates after`) from compromise (`all`)
- RFC 6962 Merkle checkpoints and inclusion proofs, so one entry can be proven
  without disclosing the rest of the log
- Fast-forward merging with fork detection; incoming ledgers are verified before
  anything is merged
- Canonical JSON close to RFC 8785, with UTF-16 code-unit key ordering

### Drift detection

- Suites as committed JSON; nine expectation modes including `json_shape`,
  `never_contains` and `numeric`
- Expectation failure and behavioural movement reported separately, with distinct
  exit codes
- Model-identity checking against the served model recorded in the baseline,
  which catches an alias repointing at a new snapshot
- Providers: `echo` (free, deterministic), `ollama`, `openai`, `anthropic`, all
  over the standard library
- Digests in the ledger, output text in gitignored run logs
- Per-case digest timelines: when exactly did this change?

### Tool schemas

- The Neutral Tool Schema, with `effects` and `consent` declarations that no
  target format carries
- Ten emit targets: `mcp`, `openai`, `ollama`, `anthropic`, `gemini`,
  `json-schema`, `langchain`, `autogen`, `crewai`, `pydantic`
- Every emitter reports what the translation dropped
- Format auto-detection when importing, plus derivation from a Python callable
  with Google, NumPy and reST docstring support
- Diffing with four severities, including `escalation` for a tool that gained
  side effects without changing its signature
- Interface digests that ignore prose, so rewording is not a change

### Consent receipts

- Access events that record what was touched, never what it said
- Consent grants where the declared purpose is part of the permission
- Nine violation codes; enforcement that refuses before the body runs
- Plain-English rendering, a grouped digest, and a self-contained HTML page
- Unusual-access flags derived from recorded history
- Denied attempts counted but never credited with items or egress

### Registry

- Content addressing by Merkle root over the file tree, not the archive bytes,
  so digests are reproducible across machines
- Deterministic `.tar.gz` archives
- Immutable published versions; republishing altered content is refused
- Signed provenance, trust-aware resolution, semver ranges
- Installation verified entirely in memory before anything is written, with
  explicit path-traversal rejection
- Revocation that supersedes rather than erases
- Syncing over any file transport, with conflict reporting

### Project

- No runtime dependencies; Python 3.9+
- 269 tests, run on Linux, macOS and Windows with both crypto backends
- CI re-runs the README quickstart, so the documentation stays true
