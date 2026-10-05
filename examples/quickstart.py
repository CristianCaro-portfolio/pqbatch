"""Sign a small live stream and read it back. Run: python examples/quickstart.py"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pqbatch import CheckpointLog, Sealer, SealVerifier, SignKey, Tampered
from pqbatch.records import Anchor, Checkpoint, Seal

pq_key = SignKey.generate("mldsa65")     # post-quantum, signs one checkpoint per period
fast_key = SignKey.generate("ed25519")   # classical, seals every batch right away
sealer = Sealer(pq_key, fast_key, deadline_ms=100, max_batch=1024, checkpoint_ms=2000)

# Producer side: what would be written to the topic, in order.
topic = []
for i in range(500):
    now_ms = i * 7                        # one event every 7 ms
    payload = f'{{"order": {i}, "amount": {i * 3}}}'.encode()
    topic += [record for _, record, _ in sealer.poll(now_ms)]
    topic.append(payload)
    topic += [record for _, record, _ in sealer.add("orders", payload, now_ms)]
topic += [record for _, record, _ in sealer.flush(500 * 7 + 100)]

extra = sum(len(r.encode()) for r in topic if not isinstance(r, bytes))
print(f"500 events, {extra} bytes of signatures in total, {extra / 500:.1f} per event")
print("one ML-DSA-65 signature per event would have added", 500 * 3309, "bytes")


def read(items):
    checkpoints = CheckpointLog(pq_key.public())
    reader = SealVerifier("orders", fast_key.public(), checkpoints)
    for item in items:
        if isinstance(item, bytes):
            reader.event(item)
        elif isinstance(item, Seal):
            reader.seal(item)
        elif isinstance(item, Checkpoint):
            checkpoints.add(item)
        elif isinstance(item, Anchor):
            reader.anchor(item)
    reader.finish()
    return reader.final_events


print("events covered by a post-quantum signature:", read(topic))

tampered = list(topic)
position = next(i for i, item in enumerate(tampered) if isinstance(item, bytes) and b'"order": 250' in item)
tampered[position] = tampered[position].replace(b"750", b"999")
try:
    read(tampered)
except Tampered as problem:
    print("edited copy rejected:", problem)
