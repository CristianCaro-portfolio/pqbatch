"""Turn results/results.json into the tables in results/results.md."""
import json
import pathlib
import sys

folder = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "results")
r = json.loads((folder / "results.json").read_text())
d = r["dataset"]
lines = [
    "# Results",
    "",
    f"Data: {d['source']}",
    f"{d['events']} events in {d['duration_s']:.0f} s ({d['events_per_s']:.1f} per second), "
    f"mean {d['mean_event_bytes']:.0f} bytes, median {d['median_event_bytes']} bytes, "
    f"{d['event_types']} event types, {d['tenants']} tenants ({d['tenants_with_one_event']} with a single event).",
    "",
    "Overhead is every byte added to the stream by signing. Throughput is events per second on one core.",
    "",
    "## One signature per event",
    "",
    "| scheme | bytes/event | % of payload | sign ev/s | verify ev/s |",
    "|---|---:|---:|---:|---:|",
]
for row in r["per_event"]:
    lines.append(
        f"| {row['label']} | {row['overhead_bytes_per_event']:.0f} | {row['overhead_pct_of_payload']:.1f} | "
        f"{row['sign_events_per_core_s']:.0f} | {row['verify_events_per_core_s']:.0f} |"
    )
lines += [
    "",
    "## Batched schemes",
    "",
    "x1 is the real traffic, x100 the same events replayed 100 times faster. "
    "`lone reader` is the cost when every reader follows one stream and downloads each checkpoint it needs.",
    "",
    "| streams | replay | scheme | bytes/event | % of payload | lone reader bytes/event | PQ signatures | sign ev/s | verify ev/s | wait p50 ms | wait p99 ms | PQ wait p99 ms |",
    "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for row in r["batched"]:
    lone = row.get("overhead_bytes_per_event_single_stream_reader", row["overhead_bytes_per_event"])
    lines.append(
        f"| {row['partition']} | x{row['speed']} | {row['label']} | {row['overhead_bytes_per_event']:.1f} | "
        f"{row['overhead_pct_of_payload']:.2f} | {lone:.1f} | {row['pq_signatures']} | "
        f"{row['sign_events_per_core_s']:.0f} | {row['verify_events_per_core_s']:.0f} | "
        f"{row['wait_ms_p50']:.0f} | {row['wait_ms_p99']:.0f} | {row.get('pq_wait_ms_p99', float('nan')):.0f} |"
    )
lines += [
    "",
    "## Anchored mode on tenant streams, real speed",
    "",
    "| batch deadline ms | checkpoint s | bytes/event | PQ signatures |",
    "|---:|---:|---:|---:|",
]
for row in r["sweep"]:
    lines.append(f"| {row['deadline_ms']} | {row['checkpoint_s']} | {row['overhead_bytes_per_event']:.1f} | {row['pq_signatures']} |")
lines += [
    "",
    "## Sizing model against the replay",
    "",
    "| streams | replay | scheme | predicted bytes/event | measured | error |",
    "|---|---|---|---:|---:|---:|",
]
for row in r["model"]:
    error = row["predicted_bytes_per_event"] / row["measured_bytes_per_event"] - 1
    lines.append(
        f"| {row['partition']} | x{row['speed']} | {row['label']} | {row['predicted_bytes_per_event']:.1f} | "
        f"{row['measured_bytes_per_event']:.1f} | {error:+.0%} |"
    )
a = r.get("single_event_audit")
if a:
    lines += [
        "",
        "## Auditing one event on its own",
        "",
        f"Batch of {a['batch_events']} events, proof of {a['proof_hashes']} hashes built on demand: "
        f"{a['bundle_bytes']} bytes in total (proof, previous chain head, seal, anchor and checkpoint).",
    ]
(folder / "results.md").write_text("\n".join(lines) + "\n")
print(f"wrote {folder / 'results.md'}")
