"""Sizing calculator: what each signing scheme would cost for a given workload.

The model assumes Poisson arrivals per stream. Real traffic is burstier, which
makes batches larger than predicted, so the numbers here lean pessimistic. The
benchmark reports how far the model lands from a replay of real events.

    python -m pqbatch.advisor --rate 2000 --streams 50 --event-bytes 400 \
        --latency-ms 100 --finality-s 10
"""
from __future__ import annotations

import argparse
import math
import os
import time

from .keys import ALGORITHMS, SignKey

SEAL_BYTES = 14        # Seal record without its signature
ANCHOR_BYTES = 26      # Anchor record without its path
CHECKPOINT_BYTES = 22  # Checkpoint record without previous hash and signature
# Seconds per signature on the machine that produced results/results.json.
DEFAULT_SIGN_COST = {"ed25519": 4.4e-5, "mldsa44": 7.3e-4, "mldsa65": 1.03e-3, "mldsa87": 1.44e-3}


def calibrate(algs=("ed25519", "mldsa65"), seconds: float = 0.5) -> dict[str, float]:
    """Measure seconds per signature on this machine."""
    costs = {}
    message = os.urandom(64)
    for alg in algs:
        key = SignKey.generate(alg)
        n, start = 0, time.perf_counter()
        while time.perf_counter() - start < seconds:
            key.sign(message)
            n += 1
        costs[alg] = (time.perf_counter() - start) / n
    return costs


def zipf_rates(total_rate: float, streams: int, skew: float) -> list[float]:
    weights = [1 / (rank ** skew) for rank in range(1, streams + 1)]
    scale = total_rate / sum(weights)
    return [w * scale for w in weights]


def _batching(rates, deadline_s, max_batch):
    """Expected batches per second across all streams."""
    return sum(r / min(max_batch, 1 + r * deadline_s) for r in rates if r > 0)


def predict(
    rates: list[float],
    *,
    deadline_ms: float = 100,
    max_batch: int = 1024,
    checkpoint_ms: float = 10_000,
    pq_alg: str = "mldsa65",
    fast_alg: str | None = "ed25519",
    hash_len: int = 32,
    sign_cost: dict[str, float] | None = None,
) -> dict[str, dict[str, float]]:
    """Overhead bytes per event, signing cores and latency bound for each scheme."""
    cost = {**DEFAULT_SIGN_COST, **(sign_cost or {})}
    total = sum(rates)
    deadline_s, ckpt_s = deadline_ms / 1000, checkpoint_ms / 1000
    pq_sig = ALGORITHMS[pq_alg][1]
    fast_sig = ALGORITHMS[fast_alg][1] if fast_alg else 0
    batches = _batching(rates, deadline_s, max_batch)

    out = {
        "ed25519/event (today)": {
            "bytes_per_event": 64, "sign_cores": total * cost["ed25519"],
            "wait_ms": 0, "pq_wait_ms": math.inf,
        },
        f"{pq_alg}/event (direct swap)": {
            "bytes_per_event": pq_sig, "sign_cores": total * cost[pq_alg],
            "wait_ms": 0, "pq_wait_ms": 0,
        },
        "v2 direct": {
            "bytes_per_event": batches * (SEAL_BYTES + pq_sig) / total,
            "sign_cores": batches * cost[pq_alg],
            "wait_ms": deadline_ms, "pq_wait_ms": deadline_ms,
        },
    }
    # A checkpoint cycle starts with the first batch closed after the last one.
    cycle_s = ckpt_s + 1 / batches
    active = sum(1 - math.exp(-r * cycle_s) for r in rates)
    path = math.ceil(math.log2(active)) if active > 1 else 0
    per_cycle = active * (ANCHOR_BYTES + hash_len * path) + CHECKPOINT_BYTES + hash_len + pq_sig
    out["v2 anchored"] = {
        "bytes_per_event": (batches * (SEAL_BYTES + fast_sig) + per_cycle / cycle_s) / total,
        "sign_cores": batches * (cost[fast_alg] if fast_alg else 0) + cost[pq_alg] / cycle_s,
        "wait_ms": deadline_ms, "pq_wait_ms": deadline_ms + checkpoint_ms,
    }
    return out


def recommend(prediction: dict[str, dict[str, float]], core_budget: float = 1.0) -> str:
    """Cheapest quantum-safe option in bytes that fits the signing CPU budget."""
    options = {k: v for k, v in prediction.items() if k != "ed25519/event (today)"}
    fitting = {k: v for k, v in options.items() if v["sign_cores"] <= core_budget} or options
    return min(fitting, key=lambda k: fitting[k]["bytes_per_event"])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rate", type=float, required=True, help="events per second, all streams together")
    ap.add_argument("--streams", type=int, default=1, help="topics, partitions or tenants signed separately")
    ap.add_argument("--skew", type=float, default=0.0, help="Zipf exponent of traffic across streams, 0 is even")
    ap.add_argument("--event-bytes", type=float, default=500)
    ap.add_argument("--latency-ms", type=float, default=100, help="longest an event may wait for its batch")
    ap.add_argument("--finality-s", type=float, default=10, help="longest wait for the post-quantum signature")
    ap.add_argument("--max-batch", type=int, default=1024)
    ap.add_argument("--pq-alg", default="mldsa65", choices=["mldsa44", "mldsa65", "mldsa87"])
    ap.add_argument("--cores", type=float, default=1.0, help="CPU cores you can spend on signing")
    ap.add_argument("--calibrate", action="store_true", help="measure signing speed on this machine first")
    args = ap.parse_args()

    costs = calibrate(("ed25519", args.pq_alg)) if args.calibrate else None
    rates = zipf_rates(args.rate, args.streams, args.skew)
    prediction = predict(
        rates, deadline_ms=args.latency_ms, max_batch=args.max_batch,
        checkpoint_ms=args.finality_s * 1000, pq_alg=args.pq_alg, sign_cost=costs,
    )
    print(f"{'scheme':30} {'bytes/event':>12} {'overhead':>9} {'sign cores':>11} {'wait ms':>8} {'PQ wait ms':>11}")
    for name, row in prediction.items():
        pq_wait = "never" if math.isinf(row["pq_wait_ms"]) else f"{row['pq_wait_ms']:.0f}"
        print(
            f"{name:30} {row['bytes_per_event']:12.1f} {row['bytes_per_event'] / args.event_bytes:9.1%} "
            f"{row['sign_cores']:11.3f} {row['wait_ms']:8.0f} {pq_wait:>11}"
        )
    print(f"\nsuggested: {recommend(prediction, args.cores)}")


if __name__ == "__main__":
    main()
