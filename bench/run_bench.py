"""Replay one hour of real GitHub events through every signing scheme.

Measures, with real signatures and real bytes:
  overhead bytes per event, signing and verifying CPU, and how long events
  wait for their signature, for three ways of splitting the same traffic into
  streams and at the original speed and a compressed (faster) replay.

    python bench/run_bench.py            # full run, about 10 minutes
    python bench/run_bench.py --limit 20000   # quick look
"""
from __future__ import annotations

import argparse
import calendar
import gzip
import json
import pathlib
import sys
import time
from collections import Counter, defaultdict, deque

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from download import DEFAULT_HOUR, download  # noqa: E402
from pqbatch import (  # noqa: E402
    CheckpointLog, FixedBatchSigner, FixedBatchVerifier, PerEventSigner, Sealer,
    SealVerifier, SignKey, prove_event, verify_event, verify_single_event,
)
from pqbatch.advisor import predict  # noqa: E402
from pqbatch.records import Anchor, BatchHeader, Checkpoint, ProofAttach, Seal  # noqa: E402

PARTITIONS = ("firehose", "type", "tenant")


def load_events(path, limit=None):
    """Return (rows, duration_ms). A row is (time_ms, event type, tenant, payload).

    GH Archive timestamps have one second resolution, so events sharing a second
    are spread evenly inside it in file order.
    """
    raw = []
    with gzip.open(path, "rb") as fh:
        for line in fh:
            payload = line.rstrip(b"\n")
            event = json.loads(payload)
            repo = (event.get("repo") or {}).get("name") or ""
            tenant = repo.split("/")[0] if "/" in repo else (event.get("actor") or {}).get("login", "unknown")
            second = calendar.timegm(time.strptime(event["created_at"], "%Y-%m-%dT%H:%M:%SZ"))
            raw.append((second, event["type"], tenant, payload))
            if limit and len(raw) >= limit:
                break
    raw.sort(key=lambda r: r[0])
    per_second = Counter(r[0] for r in raw)
    start, seen, rows = raw[0][0], Counter(), []
    for second, kind, tenant, payload in raw:
        offset = (seen[second] + 0.5) / per_second[second]
        seen[second] += 1
        rows.append(((second - start + offset) * 1000.0, kind, tenant, payload))
    return rows, (raw[-1][0] - start + 1) * 1000.0


def as_stream(rows, partition):
    index = {"firehose": None, "type": 1, "tenant": 2}[partition]
    return [("all" if index is None else r[index], r[3], r[0]) for r in rows]


def percentile(sorted_values, q):
    return sorted_values[min(len(sorted_values) - 1, int(q * len(sorted_values)))]


def sign_pass(signer, events, speed):
    """Timed pass. Returns the broker log and the CPU seconds spent signing."""
    poll = getattr(signer, "poll", None)
    log = []
    cpu = time.process_time()
    for stream, payload, t in events:
        now = t / speed
        if poll:
            pre = poll(now)
            if pre:
                log.append(("records", pre))
        post = signer.add(stream, payload, now)
        log.append(("event", (stream, payload, now)))
        if post:
            log.append(("records", post))
    tail = signer.flush(events[-1][2] / speed + getattr(signer, "deadline_ms", 0))
    if tail:
        log.append(("records", tail))
    return log, time.process_time() - cpu


def account(log, per_event):
    """Bytes by record type, signature counts and waiting times."""
    sizes, counts = Counter(), Counter()
    arrivals = defaultdict(deque)        # stream -> arrival times not sealed yet
    sealed = defaultdict(deque)          # stream -> (seq, arrival times) not final yet
    wait, pq_wait = [], []
    checkpoint_len = 0
    for kind, item in log:
        if kind == "event":
            arrivals[item[0]].append(item[2])
            continue
        for stream, record, t in item:
            if per_event:
                sizes["signature"] += len(record)
                counts["signature"] += 1
                arrivals[stream].popleft()
                wait.append(0.0)
                continue
            name = type(record).__name__
            sizes[name] += len(record.encode())
            counts[name] += 1
            if isinstance(record, (Seal, BatchHeader)):
                times = [arrivals[stream].popleft() for _ in range(record.count)]
                wait += [t - a for a in times]
                sealed[stream].append((record.seq, times))
            elif isinstance(record, Anchor):
                queue = sealed[stream]
                while queue and queue[0][0] <= record.upto_seq:
                    pq_wait += [t - a for a in queue.popleft()[1]]
            elif isinstance(record, Checkpoint):
                checkpoint_len = len(record.encode())
    assert not any(arrivals.values()), "some events were never sealed"
    return sizes, counts, sorted(wait), sorted(pq_wait), checkpoint_len


def verify_pass(log, scheme, keys):
    """Timed pass over the broker log as a reader would do it. Returns CPU seconds."""
    pq_pub, fast_pub = keys["pq"].public(), keys["fast"].public()
    n_events = sum(1 for kind, _ in log if kind == "event")
    cpu = time.process_time()
    if scheme["kind"] == "event":
        key = keys[scheme["key"]].public()
        pending = defaultdict(deque)
        done = 0
        for kind, item in log:
            if kind == "event":
                pending[item[0]].append(item[1])
            else:
                for stream, sig, _ in item:
                    verify_event(key, pending[stream].popleft(), sig)
                    done += 1
    elif scheme["kind"] == "v1":
        readers, pending = {}, defaultdict(deque)
        for kind, item in log:
            if kind == "event":
                pending[item[0]].append(item[1])
                continue
            for stream, record, _ in item:
                reader = readers.get(stream) or readers.setdefault(stream, FixedBatchVerifier(stream, pq_pub))
                if isinstance(record, ProofAttach):
                    reader.event(pending[stream].popleft(), record)
                else:
                    reader.header(record)
        done = sum(r.verified for r in readers.values())
    else:
        anchored = scheme["checkpoint_ms"] > 0
        ckpts = CheckpointLog(pq_pub) if anchored else None
        seal_key = pq_pub if not anchored else (fast_pub if scheme["fast"] else None)
        readers = {}
        for kind, item in log:
            if kind == "event":
                stream = item[0]
                reader = readers.get(stream) or readers.setdefault(stream, SealVerifier(stream, seal_key, ckpts))
                reader.event(item[1])
                continue
            for stream, record, _ in item:
                if isinstance(record, Checkpoint):
                    ckpts.add(record)
                elif isinstance(record, Seal):
                    readers[stream].seal(record)
                else:
                    readers[stream].anchor(record)
        for reader in readers.values():
            reader.finish()
        if ckpts:
            ckpts.check_chain()
        done = sum(r.final_events for r in readers.values())
    elapsed = time.process_time() - cpu
    assert done == n_events, f"only {done} of {n_events} events verified"
    return elapsed


def make_signer(scheme, keys):
    if scheme["kind"] == "event":
        return PerEventSigner(keys[scheme["key"]])
    if scheme["kind"] == "v1":
        return FixedBatchSigner(keys["pq"], batch_size=scheme["batch"])
    return Sealer(
        keys["pq"], keys["fast"] if scheme.get("fast") else None,
        deadline_ms=scheme["deadline_ms"], max_batch=scheme["max_batch"],
        checkpoint_ms=scheme["checkpoint_ms"],
    )


def run(label, scheme, events, speed, duration_ms, payload_bytes, keys, verify=True):
    log, sign_cpu = sign_pass(make_signer(scheme, keys), events, speed)
    sizes, counts, wait, pq_wait, checkpoint_len = account(log, scheme["kind"] == "event")
    n = len(events)
    overhead = sum(sizes.values())
    anchored = scheme.get("checkpoint_ms", 0) > 0
    if scheme["kind"] == "event":
        pq_signs = counts["signature"] if scheme["key"] != "ed" else 0
        pq_wait = wait if pq_signs else []
    elif anchored:
        pq_signs = counts["Checkpoint"]
    else:
        pq_signs = counts["Seal"] + counts["BatchHeader"]
        pq_wait = wait
    wall_s = duration_ms / 1000 / speed
    row = {
        "label": label, "speed": speed, "events": n,
        "overhead_bytes_per_event": overhead / n,
        "overhead_pct_of_payload": 100 * overhead / payload_bytes,
        "bytes_by_record": dict(sizes), "records": dict(counts),
        "pq_signatures": pq_signs,
        "sign_cpu_s": sign_cpu, "sign_events_per_core_s": n / sign_cpu,
        "sign_cores_needed": sign_cpu / wall_s,
        "wait_ms_p50": percentile(wait, 0.5), "wait_ms_p99": percentile(wait, 0.99), "wait_ms_max": wait[-1],
    }
    if pq_wait:
        row.update(pq_wait_ms_p50=percentile(pq_wait, 0.5), pq_wait_ms_p99=percentile(pq_wait, 0.99))
    if anchored:
        # A reader that follows a single stream also downloads each checkpoint it is anchored to.
        isolated = overhead + counts["Anchor"] * checkpoint_len
        row["overhead_bytes_per_event_single_stream_reader"] = isolated / n
    if verify:
        verify_cpu = verify_pass(log, scheme, keys)
        row.update(verify_cpu_s=verify_cpu, verify_events_per_core_s=n / verify_cpu)
    print(
        f"  {label:34} x{speed:<5} {row['overhead_bytes_per_event']:9.1f} B/ev "
        f"{row['overhead_pct_of_payload']:7.2f}%  pq signs {pq_signs:6d}  "
        f"sign {row['sign_events_per_core_s']:9.0f} ev/s  wait p99 {row['wait_ms_p99']:10.0f} ms",
        flush=True,
    )
    return row, log


def audit_example(log, keys):
    """Verify one event on its own, with a proof built on demand, and size the bundle."""
    payloads, prev_head, heads = [], bytes(32), {}
    reader = SealVerifier("all", keys["fast"].public(), None)
    ckpts = CheckpointLog(keys["pq"].public())
    batches = {}
    for kind, item in log:
        if kind == "event":
            payloads.append(item[1])
            continue
        for stream, record, _ in item:
            if isinstance(record, Seal):
                for p in payloads:
                    reader.event(p)
                before = reader._head
                reader.seal(record)
                batches[record.seq] = (payloads, before, record)
                payloads = []
            elif isinstance(record, Checkpoint):
                ckpts.add(record)
                checkpoint = record
            elif isinstance(record, Anchor):
                batch, prev, seal = batches[record.upto_seq]
                index = len(batch) // 2
                path = prove_event(batch, index)
                verify_single_event("all", batch[index], index, path, prev, seal, keys["fast"].public(), record, ckpts)
                bundle = 32 * len(path) + len(prev) + len(seal.encode()) + len(record.encode()) + len(checkpoint.encode())
                return {"batch_events": len(batch), "proof_hashes": len(path), "bundle_bytes": bundle}
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hour", default=DEFAULT_HOUR)
    ap.add_argument("--limit", type=int, default=None, help="use only the first N events of the file")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    rows, duration_ms = load_events(download(args.hour), args.limit)
    payload_bytes = sum(len(r[3]) for r in rows)
    n = len(rows)
    tenants = Counter(r[2] for r in rows)
    dataset = {
        "source": f"https://data.gharchive.org/{args.hour}.json.gz", "events": n,
        "payload_bytes": payload_bytes, "mean_event_bytes": payload_bytes / n,
        "median_event_bytes": sorted(len(r[3]) for r in rows)[n // 2],
        "duration_s": duration_ms / 1000, "events_per_s": n / (duration_ms / 1000),
        "event_types": len({r[1] for r in rows}), "tenants": len(tenants),
        "tenants_with_one_event": sum(1 for c in tenants.values() if c == 1),
    }
    print(json.dumps(dataset, indent=1))
    keys = {"pq": SignKey.generate("mldsa65"), "pq44": SignKey.generate("mldsa44"), "fast": SignKey.generate("ed25519")}
    keys["ed"] = keys["fast"]
    results = {"dataset": dataset, "per_event": [], "batched": [], "sweep": [], "model": []}

    print("\nper event signatures (same result for any stream layout)")
    firehose = as_stream(rows, "firehose")
    for label, key in (("ed25519/event (today)", "ed"), ("mldsa44/event", "pq44"), ("mldsa65/event (direct swap)", "pq")):
        row, _ = run(label, {"kind": "event", "key": key}, firehose, 1, duration_ms, payload_bytes, keys)
        results["per_event"].append(row)

    schemes = {
        "v1 fixed 256 + proofs": {"kind": "v1", "batch": 256},
        "v2 direct 100ms": {"kind": "v2", "deadline_ms": 100, "max_batch": 1024, "checkpoint_ms": 0},
        "v2 anchored 100ms/10s": {"kind": "v2", "deadline_ms": 100, "max_batch": 1024, "checkpoint_ms": 10_000, "fast": True},
        "v2 anchored 100ms/10s, pq only": {"kind": "v2", "deadline_ms": 100, "max_batch": 1024, "checkpoint_ms": 10_000, "fast": False},
    }
    audit = None
    for partition in PARTITIONS:
        events = as_stream(rows, partition)
        counts = Counter(e[0] for e in events)
        for speed in (1, 100):
            print(f"\n{partition}: {len(counts)} streams, replay x{speed}")
            for label, scheme in schemes.items():
                row, log = run(label, scheme, events, speed, duration_ms, payload_bytes, keys)
                row["partition"] = partition
                results["batched"].append(row)
                if partition == "firehose" and speed == 100 and label == "v2 anchored 100ms/10s":
                    audit = audit_example(log, keys)
            rates = [c / (duration_ms / 1000) * speed for c in counts.values()]
            model = predict(rates, deadline_ms=100, checkpoint_ms=10_000)
            for label, key in (("v2 direct 100ms", "v2 direct"), ("v2 anchored 100ms/10s", "v2 anchored")):
                measured = next(r for r in results["batched"] if r["label"] == label and r["partition"] == partition and r["speed"] == speed)
                results["model"].append({
                    "partition": partition, "speed": speed, "label": label,
                    "predicted_bytes_per_event": model[key]["bytes_per_event"],
                    "measured_bytes_per_event": measured["overhead_bytes_per_event"],
                })
    results["single_event_audit"] = audit

    print("\nsweep: anchored mode on tenant streams at x1 (deadline ms / checkpoint s)")
    events = as_stream(rows, "tenant")
    for deadline in (10, 100, 1000):
        for checkpoint_s in (1, 10, 60):
            scheme = {"kind": "v2", "deadline_ms": deadline, "max_batch": 1024, "checkpoint_ms": checkpoint_s * 1000, "fast": True}
            row, _ = run(f"anchored {deadline}ms/{checkpoint_s}s", scheme, events, 1, duration_ms, payload_bytes, keys, verify=False)
            row.update(partition="tenant", deadline_ms=deadline, checkpoint_s=checkpoint_s)
            results["sweep"].append(row)

    out = pathlib.Path(args.out)
    out.mkdir(exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=1))
    print(f"\nwrote {out / 'results.json'}")


if __name__ == "__main__":
    main()
