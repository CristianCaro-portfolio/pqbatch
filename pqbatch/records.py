"""Wire records. `encode()` is the real byte layout, so `len(encode())` is the
overhead a stream pays, with no estimates involved."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .keys import ALG_IDS, ALG_NAMES, ALGORITHMS

NO_SIG = 255
T_PROOF, T_HEADER, T_SEAL, T_ANCHOR, T_CHECKPOINT = 1, 2, 3, 4, 5


def _split_path(blob: bytes, n: int) -> list[bytes]:
    if n == 0:
        return []
    size = len(blob) // n
    return [blob[i * size : (i + 1) * size] for i in range(n)]


@dataclass
class ProofAttach:
    """v1: travels with every event so it can be checked against its batch header."""

    index: int
    path: list[bytes]

    def encode(self) -> bytes:
        return struct.pack(">BIB", T_PROOF, self.index, len(self.path)) + b"".join(self.path)


@dataclass
class BatchHeader:
    """v1: one signed Merkle root per fixed-size batch."""

    seq: int
    count: int
    root: bytes
    sig: bytes

    def encode(self) -> bytes:
        return struct.pack(">BQI", T_HEADER, self.seq, self.count) + self.root + self.sig


@dataclass
class Seal:
    """v2: closes a batch. The root is not sent, the reader recomputes it."""

    seq: int
    count: int
    alg: str | None
    sig: bytes = b""

    def encode(self) -> bytes:
        alg_id = NO_SIG if self.alg is None else ALG_IDS[self.alg]
        return struct.pack(">BQIB", T_SEAL, self.seq, self.count, alg_id) + self.sig


@dataclass
class Anchor:
    """v2: links a stream's chain head to a post-quantum checkpoint."""

    checkpoint_id: int
    upto_seq: int
    index: int
    tree_size: int
    path: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        return struct.pack(
            ">BQQIIB", T_ANCHOR, self.checkpoint_id, self.upto_seq, self.index,
            self.tree_size, len(self.path),
        ) + b"".join(self.path)


@dataclass
class Checkpoint:
    """v2: one post-quantum signature over the heads of every active stream."""

    checkpoint_id: int
    time_ms: int
    tree_size: int
    prev: bytes
    alg: str
    sig: bytes

    def encode(self) -> bytes:
        return struct.pack(
            ">BQQIB", T_CHECKPOINT, self.checkpoint_id, self.time_ms, self.tree_size,
            ALG_IDS[self.alg],
        ) + self.prev + self.sig


def decode(blob: bytes, hash_len: int = 32):
    tag = blob[0]
    if tag == T_PROOF:
        _, index, n = struct.unpack_from(">BIB", blob)
        return ProofAttach(index, _split_path(blob[6:], n))
    if tag == T_HEADER:
        _, seq, count = struct.unpack_from(">BQI", blob)
        return BatchHeader(seq, count, blob[13 : 13 + hash_len], blob[13 + hash_len :])
    if tag == T_SEAL:
        _, seq, count, alg_id = struct.unpack_from(">BQIB", blob)
        alg = None if alg_id == NO_SIG else ALG_NAMES[alg_id]
        return Seal(seq, count, alg, blob[14:])
    if tag == T_ANCHOR:
        _, ckpt, upto, index, size, n = struct.unpack_from(">BQQIIB", blob)
        return Anchor(ckpt, upto, index, size, _split_path(blob[26:], n))
    if tag == T_CHECKPOINT:
        _, ckpt, time_ms, size, alg_id = struct.unpack_from(">BQQIB", blob)
        alg = ALG_NAMES[alg_id]
        sig_len = ALGORITHMS[alg][1]
        return Checkpoint(ckpt, time_ms, size, blob[22 : len(blob) - sig_len], alg, blob[-sig_len:])
    raise ValueError(f"unknown record tag {tag}")
