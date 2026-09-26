"""Pillar four: a skill registry with no server in the middle.

Packages are content-addressed by a Merkle root over their file tree, and every
publication is a signed entry in the ledger. The ledger *is* the index, so
distribution is whatever moves a text file: git, a URL, a shared drive.

::

    from attestry.registry import Package, Registry

    package = Package.from_dir("./my-skill")
    registry = Registry(ledger, trust, cache_dir)
    registry.publish(package, sources=["https://example.com/my-skill-1.0.0.tar.gz"])

    publication, path = registry.install("my-skill@^1.0.0")

Installing verifies the fetched archive against the digest in the ledger before
writing anything, and refuses publishers you have not trusted.
"""

from .index import Conflict, Publication, Registry, fetch_source, parse_spec, version_key
from .package import (
    MANIFEST_NAME,
    Manifest,
    Package,
    safe_extract,
    tree_digest,
)
from .remotes import Remotes, check_incoming, export_ledger, parse_ledger_text, sync

__all__ = [
    "Package",
    "Manifest",
    "MANIFEST_NAME",
    "tree_digest",
    "safe_extract",
    "Registry",
    "Publication",
    "Conflict",
    "parse_spec",
    "version_key",
    "fetch_source",
    "Remotes",
    "sync",
    "parse_ledger_text",
    "check_incoming",
    "export_ledger",
]
