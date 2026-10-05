"""Readers for each signing scheme. They raise `Tampered` on any mismatch."""
from __future__ import annotations

import hashlib

from . import merkle
from .keys import VerifyKey
from .records import Anchor, BatchHeader, Checkpoint, ProofAttach, Seal
from .signers import chain_head, checkpoint_leaf, checkpoint_message, seal_message, v1_message


class Tampered(Exception):
    pass


def verify_event(key: VerifyKey, payload: bytes, sig: bytes) -> None:
    if not key.verify(sig, payload):
        raise Tampered("event signature does not match")


class FixedBatchVerifier:
    """v1 reader for one stream: events with their proofs, then the batch header."""

    def __init__(self, stream: str, key: VerifyKey, hash_name: str = "sha256"):
        self.stream, self.key, self.hash_name = stream, key, hash_name
        self._pending: list[tuple[bytes, ProofAttach]] = []
        self._seq = 0
        self.verified = 0

    def event(self, payload: bytes, proof: ProofAttach) -> None:
        self._pending.append((merkle.leaf_hash(payload, self.hash_name), proof))

    def header(self, header: BatchHeader) -> None:
        if header.seq != self._seq or header.count != len(self._pending):
            raise Tampered("batch is missing, repeated or has the wrong number of events")
        if not self.key.verify(header.sig, v1_message(self.stream, header.seq, header.count, header.root)):
            raise Tampered("batch signature does not match")
        for leaf, proof in self._pending:
            if not merkle.verify_inclusion(leaf, proof.index, header.count, proof.path, header.root, self.hash_name):
                raise Tampered("event is not part of the signed batch")
        self.verified += len(self._pending)
        self._pending = []
        self._seq += 1


class CheckpointLog:
    """Shared by all stream readers so each checkpoint signature is checked once."""

    def __init__(self, key: VerifyKey, hash_name: str = "sha256"):
        self.key, self.hash_name = key, hash_name
        self._records: dict[int, Checkpoint] = {}
        self._roots: dict[int, bytes] = {}

    def add(self, checkpoint: Checkpoint) -> None:
        self._records[checkpoint.checkpoint_id] = checkpoint

    def accepts(self, checkpoint_id: int, root: bytes) -> bool:
        """True when `root` is the one the post-quantum key signed for this checkpoint."""
        known = self._roots.get(checkpoint_id)
        if known is not None:
            return known == root
        ckpt = self._records.get(checkpoint_id)
        if ckpt is None:
            return False
        message = checkpoint_message(ckpt.checkpoint_id, ckpt.time_ms, ckpt.tree_size, ckpt.prev, root)
        if not self.key.verify(ckpt.sig, message):
            return False
        self._roots[checkpoint_id] = root
        return True

    def check_chain(self) -> None:
        """Every checkpoint must commit to the one before it (full log readers)."""
        prev = bytes(hashlib.new(self.hash_name).digest_size)
        for ckpt_id in sorted(self._records):
            ckpt = self._records[ckpt_id]
            root = self._roots.get(ckpt_id)
            if ckpt.prev != prev or root is None:
                raise Tampered("checkpoint log is broken or has unverified entries")
            message = checkpoint_message(ckpt.checkpoint_id, ckpt.time_ms, ckpt.tree_size, ckpt.prev, root)
            prev = hashlib.new(self.hash_name, message).digest()


class SealVerifier:
    """v2 reader for one stream.

    `seal_key` is the key expected on seals: the post-quantum key in direct mode,
    the fast classical key in anchored mode, or None when seals are unsigned.
    `final_events` counts events covered by a post-quantum signature.
    """

    def __init__(
        self,
        stream: str,
        seal_key: VerifyKey | None,
        checkpoints: CheckpointLog | None = None,
        hash_name: str = "sha256",
    ):
        self.stream, self.seal_key, self.checkpoints, self.hash_name = stream, seal_key, checkpoints, hash_name
        self._leaves: list[bytes] = []
        self._seq = 0
        self._head = bytes(hashlib.new(hash_name).digest_size)
        self._heads: dict[int, bytes] = {}
        self._counts: dict[int, int] = {}
        self._final_upto = -1
        self.sealed_events = 0
        self.final_events = 0

    def event(self, payload: bytes) -> None:
        self._leaves.append(merkle.leaf_hash(payload, self.hash_name))

    def seal(self, seal: Seal) -> None:
        if seal.seq != self._seq or seal.count != len(self._leaves) or not self._leaves:
            raise Tampered("batch is missing, repeated or has the wrong number of events")
        root = merkle.root(self._leaves, self.hash_name)
        head = chain_head(self.stream, seal.seq, seal.count, self._head, root, self.hash_name)
        if self.seal_key is not None:
            if seal.alg != self.seal_key.alg or not self.seal_key.verify(seal.sig, seal_message(head)):
                raise Tampered("seal signature does not match")
        elif seal.alg is not None:
            raise Tampered("unexpected seal signature")
        self._head = head
        self._heads[seal.seq] = head
        self._counts[seal.seq] = seal.count
        self.sealed_events += seal.count
        if self.checkpoints is None:
            self.final_events += seal.count
        self._leaves = []
        self._seq += 1

    def anchor(self, anchor: Anchor) -> None:
        head = self._heads.get(anchor.upto_seq)
        if head is None or self.checkpoints is None:
            raise Tampered("anchor points to a batch this reader has not seen")
        leaf = checkpoint_leaf(self.stream, anchor.upto_seq, head, self.hash_name)
        root = merkle.root_from_path(leaf, anchor.index, anchor.tree_size, anchor.path, self.hash_name)
        if root is None or not self.checkpoints.accepts(anchor.checkpoint_id, root):
            raise Tampered("anchor does not lead to a signed checkpoint")
        for seq in range(self._final_upto + 1, anchor.upto_seq + 1):
            self.final_events += self._counts.pop(seq)
            self._heads.pop(seq)
        self._final_upto = max(self._final_upto, anchor.upto_seq)

    def finish(self) -> None:
        if self._leaves:
            raise Tampered("events at the end of the stream have no seal")


def prove_event(payloads: list[bytes], index: int, hash_name: str = "sha256") -> list[bytes]:
    """Inclusion proof for one event of a sealed batch.

    Anyone holding the batch can produce it later, so proofs never need to be
    stored or shipped with the stream.
    """
    leaves = [merkle.leaf_hash(p, hash_name) for p in payloads]
    return merkle.inclusion_path(merkle.build_levels(leaves, hash_name), index)


def verify_single_event(
    stream: str,
    payload: bytes,
    index: int,
    path: list[bytes],
    prev_head: bytes,
    seal: Seal,
    seal_key: VerifyKey | None = None,
    anchor: Anchor | None = None,
    checkpoints: CheckpointLog | None = None,
    hash_name: str = "sha256",
) -> None:
    """Audit one event in isolation: proof, previous chain head, seal and, in
    anchored mode, the anchor of that same batch plus its checkpoint."""
    leaf = merkle.leaf_hash(payload, hash_name)
    root = merkle.root_from_path(leaf, index, seal.count, path, hash_name)
    if root is None:
        raise Tampered("event is not part of the sealed batch")
    head = chain_head(stream, seal.seq, seal.count, prev_head, root, hash_name)
    if seal_key is not None and not seal_key.verify(seal.sig, seal_message(head)):
        raise Tampered("seal signature does not match")
    if anchor is not None:
        ckpt_leaf = checkpoint_leaf(stream, anchor.upto_seq, head, hash_name)
        ckpt_root = merkle.root_from_path(ckpt_leaf, anchor.index, anchor.tree_size, anchor.path, hash_name)
        if anchor.upto_seq != seal.seq or ckpt_root is None or not checkpoints.accepts(anchor.checkpoint_id, ckpt_root):
            raise Tampered("anchor does not lead to a signed checkpoint")
    elif seal_key is None:
        raise Tampered("nothing signed covers this event")
