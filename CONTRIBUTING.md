# Contributing

## Running things

```bash
git clone https://github.com/Nulfied/attestry
cd attestry
pip install -e ".[dev]"

python -m unittest discover -s tests -t . -v
python -m pyflakes attestry tests
```

No test plugins, no config files. `unittest` and `pyflakes` are the whole
toolchain.

To exercise the pure-Python crypto path, uninstall `cryptography` and run the
suite again — CI does both.

```bash
python -c "import attestry.ledger as l; print(l.BACKEND)"
```

## What the tests are for

The suite is not chasing a coverage number. It exists to hold down the properties
everything else rests on, and a change that weakens one of these should fail
loudly:

- canonical JSON is order-independent, and rejects `NaN`, infinities and
  non-string keys rather than coercing them
- Merkle proofs verify for every tree size, and truncated, padded and
  wrong-index proofs are rejected
- Ed25519 matches the RFC 8032 vectors, and both backends agree byte for byte
- editing a ledger entry is caught, **and** so is editing one and recomputing its
  hash
- a denied access is never credited with items or egress
- an errored drift run never becomes a baseline
- a tampered archive never reaches the filesystem
- a broken incoming ledger is not partially merged

If you add a feature, add the test that would catch its absence.

## House style

- Standard library only in `attestry/`. `cryptography` is the single optional
  extra, and everything must work without it.
- Python 3.9 compatible. `from __future__ import annotations` at the top of every
  module.
- Comments explain *why*, not *what*. The reasoning that is hard to recover from
  the code is worth writing down; a narration of the next line is not.
- Error messages say what went wrong and what to do about it. `"no such suite"`
  is a worse message than `"no suite 'nope'; available: support, billing"`.
- Refuse rather than guess, wherever guessing could destroy the property the tool
  exists to provide.

## Adding to a subsystem

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the extension points: a new
entry kind, a drift provider, a schema target, a receipt resource scheme.

The one rule that is not negotiable: **do not put model output text or personal
data into a ledger entry.** Digests prove what was seen without disclosing it.
Entries are signed, append-only, and usually pushed to a shared repository, so
anything written there is permanent.

## Changing the ledger format

The format is a published spec that other implementations may rely on. A change
needs: a version bump in the spec, a reader that still accepts version 1, and a
note in the changelog describing the migration.
