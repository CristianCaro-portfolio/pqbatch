"""Three ways to sign an event stream.

PerEventSigner   one signature per event. Ed25519 is what teams run today,
                 ML-DSA is the direct post-quantum swap.
FixedBatchSigner v1: one ML-DSA signature per N events, every event carries its
                 Merkle inclusion proof.
Sealer           v2: batches close by size or by deadline, no proofs travel with
                 the events, batches of a stream are hash chained, and one ML-DSA
                 checkpoint can cover every stream at once.

Every signer returns a list of `(stream, record, time_ms)` tuples. `stream` is
None for records that belong to the shared checkpoint log.
"""
from __future__ import annotations

import hashlib
import struct
from collections import deque

from . import merkle
from .keys import SignKey
from .records import Anchor, BatchHeader, Checkpoint, ProofAttach, Seal

V1_DOMAIN = b"pqbatch/v1/batch"
HEAD_DOMAIN = b"pqbatch/v2/head"
SEAL_DOMAIN = b"pqbatch/v2/seal"
CKPT_DOMAIN = b"pqbatch/v2/ckpt"


def _name(stream: str) -> bytes:
    raw = stream.encode()
    return struct.pack(">H", len(raw)) + raw


def v1_message(stream: str, seq: int, count: int, root: bytes) -> bytes:
    return V1_DOMAIN + _name(stream) + struct.pack(">QI", seq, count) + root


def chain_head(stream: str, seq: int, count: int, prev: bytes, root: bytes, hash_name: str) -> bytes:
    """Hash that commits to this batch and, through `prev`, to all earlier ones."""
    data = HEAD_DOMAIN + _name(stream) + struct.pack(">QI", seq, count) + prev + root
    return hashlib.new(hash_name, data).digest()


def seal_message(head: bytes) -> bytes:
    return SEAL_DOMAIN + head


def checkpoint_leaf(stream: str, upto_seq: int, head: bytes, hash_name: str) -> bytes:
    return merkle.leaf_hash(_name(stream) + struct.pack(">Q", upto_seq) + head, hash_name)


def checkpoint_message(ckpt_id: int, time_ms: int, size: int, prev: bytes, root: bytes) -> bytes:
    return CKPT_DOMAIN + struct.pack(">QQI", ckpt_id, time_ms, size) + prev + root


class PerEventSigner:
    def __init__(self, key: SignKey):
        self.key = key

    def add(self, stream: str, payload: bytes, now_ms: float):
        return [(stream, self.key.sign(payload), now_ms)]

    def flush(self, now_ms: float):
        return []


class FixedBatchSigner:
    """v1. Waits for exactly `batch_size` events per stream, however long it takes."""

    def __init__(self, key: SignKey, batch_size: int = 256, hash_name: str = "sha256"):
        self.key = key
        self.batch_size = batch_size
        self.hash_name = hash_name
        self._open: dict[str, list[bytes]] = {}
        self._seq: dict[str, int] = {}

    def add(self, stream: str, payload: bytes, now_ms: float):
        leaves = self._open.setdefault(stream, [])
        leaves.append(merkle.leaf_hash(payload, self.hash_name))
        if len(leaves) >= self.batch_size:
            return self._close(stream, now_ms)
        return []

    def _close(self, stream: str, now_ms: float):
        leaves = self._open.pop(stream)
        seq = self._seq.get(stream, 0)
        self._seq[stream] = seq + 1
        levels = merkle.build_levels(leaves, self.hash_name)
        root = levels[-1][0]
        out = [
            (stream, ProofAttach(i, merkle.inclusion_path(levels, i)), now_ms)
            for i in range(len(leaves))
        ]
        sig = self.key.sign(v1_message(stream, seq, len(leaves), root))
        out.append((stream, BatchHeader(seq, len(leaves), root, sig), now_ms))
        return out

    def flush(self, now_ms: float):
        out = []
        for stream in list(self._open):
            out += self._close(stream, now_ms)
        return out


class Sealer:
    """v2.

    checkpoint_ms == 0  every batch is signed with the post-quantum key.
    checkpoint_ms  > 0  every batch gets a cheap seal (signed with `fast_key`
                        when given) and a post-quantum checkpoint covering all
                        streams with new batches is issued at most once per
                        `checkpoint_ms`.
    """

    def __init__(
        self,
        pq_key: SignKey,
        fast_key: SignKey | None = None,
        *,
        deadline_ms: float = 100,
        max_batch: int = 1024,
        checkpoint_ms: float = 0,
        hash_name: str = "sha256",
    ):
        self.pq_key = pq_key
        self.fast_key = fast_key if checkpoint_ms else None
        self.deadline_ms = deadline_ms
        self.max_batch = max_batch
        self.checkpoint_ms = checkpoint_ms
        self.hash_name = hash_name
        self._zero = bytes(hashlib.new(hash_name).digest_size)
        self._open: dict[str, list[bytes]] = {}
        self._due: deque[tuple[float, str, int]] = deque()
        self._seq: dict[str, int] = {}
        self._head: dict[str, bytes] = {}
        self._dirty: dict[str, tuple[int, bytes]] = {}
        self._next_ckpt: float | None = None
        self._ckpt_id = 0
        self._ckpt_prev = self._zero

    def add(self, stream: str, payload: bytes, now_ms: float):
        out = self.poll(now_ms)
        leaves = self._open.get(stream)
        if leaves is None:
            leaves = self._open[stream] = []
            self._due.append((now_ms + self.deadline_ms, stream, self._seq.get(stream, 0)))
        leaves.append(merkle.leaf_hash(payload, self.hash_name))
        if len(leaves) >= self.max_batch:
            out += self._close(stream, now_ms)
        return out

    def poll(self, now_ms: float):
        """Close every batch and checkpoint whose time has come, in time order."""
        out = []
        while True:
            batch_due = self._due[0][0] if self._due else float("inf")
            ckpt_due = self._next_ckpt if self._next_ckpt is not None else float("inf")
            if min(batch_due, ckpt_due) > now_ms:
                return out
            if batch_due <= ckpt_due:
                due, stream, seq = self._due.popleft()
                if stream in self._open and self._seq.get(stream, 0) == seq:
                    out += self._close(stream, due)
            else:
                out += self._checkpoint(ckpt_due)

    def flush(self, now_ms: float):
        out = []
        for stream in list(self._open):
            out += self._close(stream, now_ms)
        self._due.clear()
        if self._dirty:
            out += self._checkpoint(now_ms)
        return out

    def _close(self, stream: str, now_ms: float):
        leaves = self._open.pop(stream)
        seq = self._seq.get(stream, 0)
        self._seq[stream] = seq + 1
        root = merkle.root(leaves, self.hash_name)
        prev = self._head.get(stream, self._zero)
        head = chain_head(stream, seq, len(leaves), prev, root, self.hash_name)
        self._head[stream] = head
        if not self.checkpoint_ms:
            seal = Seal(seq, len(leaves), self.pq_key.alg, self.pq_key.sign(seal_message(head)))
            return [(stream, seal, now_ms)]
        if self.fast_key:
            seal = Seal(seq, len(leaves), self.fast_key.alg, self.fast_key.sign(seal_message(head)))
        else:
            seal = Seal(seq, len(leaves), None)
        self._dirty[stream] = (seq, head)
        if self._next_ckpt is None:
            self._next_ckpt = now_ms + self.checkpoint_ms
        return [(stream, seal, now_ms)]

    def _checkpoint(self, now_ms: float):
        streams = sorted(self._dirty)
        leaves = [checkpoint_leaf(s, *self._dirty[s], self.hash_name) for s in streams]
        levels = merkle.build_levels(leaves, self.hash_name)
        ckpt_id = self._ckpt_id
        message = checkpoint_message(ckpt_id, int(now_ms), len(leaves), self._ckpt_prev, levels[-1][0])
        ckpt = Checkpoint(
            ckpt_id, int(now_ms), len(leaves), self._ckpt_prev, self.pq_key.alg,
            self.pq_key.sign(message),
        )
        out = [(None, ckpt, now_ms)]
        for i, stream in enumerate(streams):
            anchor = Anchor(ckpt_id, self._dirty[stream][0], i, len(leaves), merkle.inclusion_path(levels, i))
            out.append((stream, anchor, now_ms))
        self._ckpt_prev = hashlib.new(self.hash_name, message).digest()
        self._ckpt_id += 1
        self._dirty = {}
        self._next_ckpt = None
        return out
