"""Merkle trees, RFC 6962 style, for compact checkpoints and inclusion proofs.

The hash chain alone proves the log was not edited, but only to somebody willing
to read the whole thing. Checkpoints give the cheap version: publish one 32-byte
root, and anyone can later prove a single entry was included using about log2(n)
hashes, without being handed the rest of the log.

That matters most for receipts. You can prove to an auditor that a particular
access was recorded at the time you claim, without disclosing every other thing
the agent touched that week.

Domain separation follows RFC 6962: leaves are hashed with a 0x00 prefix and
internal nodes with 0x01. Without it an attacker could present an internal node
as if it were a leaf, since at that point both are just 32 bytes.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence

__all__ = [
    "leaf_hash",
    "node_hash",
    "merkle_root",
    "audit_path",
    "verify_audit_path",
    "root_hex",
    "path_hex",
    "verify_path_hex",
]

_LEAF_PREFIX = bytes([0x00])
_NODE_PREFIX = bytes([0x01])
_EMPTY = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    """Hash of a leaf's raw contents, with the leaf domain prefix."""
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash of an internal node, with the node domain prefix."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _split(size: int) -> int:
    """Largest power of two strictly less than ``size``, the RFC 6962 split."""
    k = 1
    while k * 2 < size:
        k *= 2
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Root over already-hashed leaves. An empty tree is SHA-256 of nothing."""
    if not leaves:
        return _EMPTY
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(leaves: Sequence[bytes], index: int) -> List[bytes]:
    """Sibling hashes proving ``leaves[index]`` sits under the root."""
    if not 0 <= index < len(leaves):
        raise IndexError(
            "leaf index %d out of range for %d leaves" % (index, len(leaves))
        )
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return audit_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return audit_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_audit_path(
    leaf: bytes,
    index: int,
    size: int,
    path: Sequence[bytes],
    root: bytes,
) -> bool:
    """Recompute the root from a leaf and its path, then compare.

    This walks bottom-up, consuming the path in the order :func:`audit_path`
    produces it (deepest sibling first). The index and tree size together decide
    whether each sibling goes on the left or the right, which is why a proof
    only means anything alongside the size it was made against.

    ``sn`` tracks the index of the last leaf at the current level, which is what
    makes the lone right-hand node of an unbalanced tree promote correctly
    instead of being paired with a phantom sibling. A path with leftover or
    missing siblings is rejected rather than ignored, so neither a padded nor a
    truncated proof can be passed off as a valid one.
    """
    if not 0 <= index < size:
        return False
    if size == 1:
        return not path and leaf == root

    node = leaf
    fn, sn = index, size - 1
    for sibling in path:
        if sn == 0:
            return False  # more siblings offered than the tree has levels
        if (fn & 1) or fn == sn:
            node = node_hash(sibling, node)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and node == root


# -- hex conveniences, for anything that crosses a JSON boundary --------
#
# Entry hashes are already SHA-256 digests, so they are used directly as leaves
# rather than being run through leaf_hash a second time.


def root_hex(leaf_hexes: Sequence[str]) -> str:
    """Merkle root over leaves given as hex digests, returned as hex."""
    return merkle_root([bytes.fromhex(h) for h in leaf_hexes]).hex()


def path_hex(leaf_hexes: Sequence[str], index: int) -> List[str]:
    """Audit path for one leaf, in and out as hex."""
    return [
        node.hex()
        for node in audit_path([bytes.fromhex(h) for h in leaf_hexes], index)
    ]


def verify_path_hex(
    leaf: str, index: int, size: int, path: Sequence[str], root: str
) -> bool:
    """Hex-in, bool-out wrapper around :func:`verify_audit_path`."""
    try:
        return verify_audit_path(
            bytes.fromhex(leaf),
            index,
            size,
            [bytes.fromhex(node) for node in path],
            bytes.fromhex(root),
        )
    except ValueError:
        return False
