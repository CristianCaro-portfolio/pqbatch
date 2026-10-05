"""Merkle tree with the RFC 9162 (Certificate Transparency v2) layout.

Leaves and inner nodes are hashed with different prefixes so a leaf can never
be confused with an inner node. Trees of any size are supported and the shape
is fully determined by the number of leaves.
"""
from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _h(hash_name: str, data: bytes) -> bytes:
    return hashlib.new(hash_name, data).digest()


def leaf_hash(data: bytes, hash_name: str = "sha256") -> bytes:
    return _h(hash_name, LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes, hash_name: str = "sha256") -> bytes:
    return _h(hash_name, NODE_PREFIX + left + right)


def build_levels(leaves: list[bytes], hash_name: str = "sha256") -> list[list[bytes]]:
    """Return every level of the tree, leaves first and the root last.

    An unpaired node at the end of a level is carried up unchanged, which gives
    exactly the tree RFC 9162 defines by splitting at the largest power of two.
    """
    if not leaves:
        raise ValueError("a Merkle tree needs at least one leaf")
    levels = [leaves]
    current = leaves
    while len(current) > 1:
        nxt = [
            node_hash(current[i], current[i + 1], hash_name)
            for i in range(0, len(current) - 1, 2)
        ]
        if len(current) % 2:
            nxt.append(current[-1])
        levels.append(nxt)
        current = nxt
    return levels


def root(leaves: list[bytes], hash_name: str = "sha256") -> bytes:
    return build_levels(leaves, hash_name)[-1][0]


def inclusion_path(levels: list[list[bytes]], index: int) -> list[bytes]:
    """Sibling hashes needed to rebuild the root from the leaf at `index`."""
    if not 0 <= index < len(levels[0]):
        raise IndexError("leaf index out of range")
    path = []
    for level in levels[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            path.append(level[sibling])
        index >>= 1
    return path


def root_from_path(
    leaf: bytes, index: int, tree_size: int, path: list[bytes], hash_name: str = "sha256"
) -> bytes | None:
    """Rebuild the root from an inclusion path (RFC 9162, section 2.1.3.2).

    Returns None when the path does not fit a tree of `tree_size` leaves.
    """
    if not 0 <= index < tree_size:
        return None
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(p, r, hash_name)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p, hash_name)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    path: list[bytes],
    expected_root: bytes,
    hash_name: str = "sha256",
) -> bool:
    return root_from_path(leaf, index, tree_size, path, hash_name) == expected_root
