import hashlib
import os

import pytest

from pqbatch import merkle


def rfc9162_root(leaves):
    """Direct transcription of the recursive definition, used as an oracle."""
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + rfc9162_root(leaves[:k]) + rfc9162_root(leaves[k:])).digest()


@pytest.mark.parametrize("n", list(range(1, 40)) + [255, 256, 257, 1000])
def test_root_and_every_proof(n):
    data = [os.urandom(20) for _ in range(n)]
    leaves = [merkle.leaf_hash(d) for d in data]
    levels = merkle.build_levels(leaves)
    root = levels[-1][0]
    assert root == rfc9162_root(data)
    for i in range(n):
        path = merkle.inclusion_path(levels, i)
        assert merkle.verify_inclusion(leaves[i], i, n, path, root)
        assert not merkle.verify_inclusion(leaves[i], (i + 1) % n, n, path, root) or n == 1
        assert not merkle.verify_inclusion(merkle.leaf_hash(b"other"), i, n, path, root)


def test_empty_tree_is_rejected():
    with pytest.raises(ValueError):
        merkle.build_levels([])


def test_leaf_cannot_pose_as_node():
    a, b = merkle.leaf_hash(b"a"), merkle.leaf_hash(b"b")
    assert merkle.root([a, b]) != merkle.leaf_hash(a + b)
