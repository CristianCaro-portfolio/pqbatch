import random

import pytest

from pqbatch import (
    CheckpointLog, FixedBatchSigner, FixedBatchVerifier, Sealer, SealVerifier,
    SignKey, Tampered, prove_event, verify_single_event,
)
from pqbatch.records import Anchor, BatchHeader, Checkpoint, ProofAttach, Seal, decode
from pqbatch.signers import chain_head
from pqbatch import merkle

PQ = SignKey.generate("mldsa65")
FAST = SignKey.generate("ed25519")


def make_events(n=300, streams=("a", "b", "c"), seed=1):
    rng = random.Random(seed)
    t, events = 0.0, []
    for i in range(n):
        t += rng.expovariate(1 / 15)
        events.append((rng.choice(streams), f"event-{i}-{rng.random()}".encode(), t))
    return events


def seal_all(sealer, events):
    """Return the interleaved log a broker would hold: events and records."""
    log = []
    for stream, payload, t in events:
        log += [(s, r) for s, r, _ in sealer.add(stream, payload, t)]
        log.append((stream, payload))
    log += [(s, r) for s, r, _ in sealer.flush(events[-1][2] + 1)]
    return log


def read_all(log, seal_key, anchored):
    ckpts = CheckpointLog(PQ.public()) if anchored else None
    readers = {}
    for stream, item in log:
        if isinstance(item, Checkpoint):
            ckpts.add(item)
            continue
        reader = readers.setdefault(stream, SealVerifier(stream, seal_key, ckpts))
        if isinstance(item, bytes):
            reader.event(item)
        elif isinstance(item, Seal):
            reader.seal(item)
        elif isinstance(item, Anchor):
            reader.anchor(item)
    for reader in readers.values():
        reader.finish()
    if ckpts:
        ckpts.check_chain()
    return readers


CONFIGS = {
    "direct": (dict(deadline_ms=50, max_batch=16), lambda: PQ.public(), False),
    "anchored": (dict(deadline_ms=50, max_batch=16, checkpoint_ms=400), lambda: FAST.public(), True),
    "anchored-unsigned-seals": (dict(deadline_ms=50, max_batch=16, checkpoint_ms=400), lambda: None, True),
}


def build(name):
    kwargs, seal_key, anchored = CONFIGS[name]
    fast = FAST if name == "anchored" else None
    log = seal_all(Sealer(PQ, fast, **kwargs), make_events())
    return log, seal_key(), anchored


@pytest.mark.parametrize("name", CONFIGS)
def test_clean_stream_verifies_and_is_fully_covered(name):
    log, seal_key, anchored = build(name)
    readers = read_all(log, seal_key, anchored)
    assert sum(r.sealed_events for r in readers.values()) == 300
    assert sum(r.final_events for r in readers.values()) == 300


@pytest.mark.parametrize("name", CONFIGS)
@pytest.mark.parametrize("attack", ["edit", "drop", "swap", "inject", "cross-stream"])
def test_attacks_are_detected(name, attack):
    log, seal_key, anchored = build(name)
    events = [i for i, (_, item) in enumerate(log) if isinstance(item, bytes)]
    i = events[len(events) // 2]
    stream, payload = log[i]
    if attack == "edit":
        log[i] = (stream, payload[:-1] + bytes([payload[-1] ^ 1]))
    elif attack == "drop":
        del log[i]
    elif attack == "swap":
        j = next(k for k in events if k > i and log[k][0] == stream and log[k][1] != payload)
        log[i], log[j] = log[j], log[i]
    elif attack == "inject":
        log.insert(i, (stream, b"forged event"))
    elif attack == "cross-stream":
        log[i] = ("b" if stream != "b" else "c", payload)
    with pytest.raises(Tampered):
        read_all(log, seal_key, anchored)


@pytest.mark.parametrize("name", CONFIGS)
def test_dropping_a_whole_batch_is_detected(name):
    log, seal_key, anchored = build(name)
    first_seal = next(i for i, (s, item) in enumerate(log) if s == "a" and isinstance(item, Seal))
    kept = [
        (s, item) for i, (s, item) in enumerate(log)
        if not (s == "a" and i <= first_seal and isinstance(item, (bytes, Seal)))
    ]
    with pytest.raises(Tampered):
        read_all(kept, seal_key, anchored)


def test_forged_checkpoint_is_rejected():
    log, seal_key, anchored = build("anchored")
    other = SignKey.generate("mldsa65")
    forged = []
    for stream, item in log:
        if isinstance(item, Checkpoint):
            item = Checkpoint(item.checkpoint_id, item.time_ms, item.tree_size, item.prev, item.alg,
                              other.sign(b"anything"))
        forged.append((stream, item))
    with pytest.raises(Tampered):
        read_all(forged, seal_key, anchored)


def test_v1_fixed_batches_with_proofs():
    signer = FixedBatchSigner(PQ, batch_size=8)
    events = [(s, p, t) for s, p, t in make_events(100, streams=("a",))]
    payloads, records = [], []
    for stream, payload, t in events:
        payloads.append(payload)
        records += [r for _, r, _ in signer.add(stream, payload, t)]
    records += [r for _, r, _ in signer.flush(0)]

    def read(payloads):
        reader, it = FixedBatchVerifier("a", PQ.public()), iter(payloads)
        for record in records:
            if isinstance(record, ProofAttach):
                reader.event(next(it), record)
            else:
                reader.header(record)
        return reader.verified

    assert read(payloads) == 100
    payloads[40] = b"edited"
    with pytest.raises(Tampered):
        read(payloads)


def test_single_event_audit_with_proof_made_on_demand():
    sealer = Sealer(PQ, FAST, deadline_ms=1000, max_batch=64, checkpoint_ms=5000)
    payloads = [f"row {i}".encode() for i in range(64)]
    out = []
    for i, p in enumerate(payloads):
        out += sealer.add("s", p, i)
    out += sealer.flush(100)
    seal = next(r for _, r, _ in out if isinstance(r, Seal))
    anchor = next(r for _, r, _ in out if isinstance(r, Anchor))
    ckpts = CheckpointLog(PQ.public())
    ckpts.add(next(r for _, r, _ in out if isinstance(r, Checkpoint)))
    path = prove_event(payloads, 17)
    zero = bytes(32)
    verify_single_event("s", payloads[17], 17, path, zero, seal, FAST.public(), anchor, ckpts)
    with pytest.raises(Tampered):
        verify_single_event("s", b"row 99", 17, path, zero, seal, FAST.public(), anchor, ckpts)


def test_records_survive_encoding():
    log, _, _ = build("anchored")
    for _, item in log:
        if not isinstance(item, bytes):
            assert decode(item.encode()) == item
    header = BatchHeader(3, 2, bytes(32), bytes(3309))
    assert decode(header.encode()) == header
    proof = ProofAttach(5, [bytes(32), bytes([1]) * 32])
    assert decode(proof.encode()) == proof
