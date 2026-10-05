"""Seal a JSON Lines file with a sidecar and verify it later.

    python -m pqbatch.cli keygen --dir keys
    python -m pqbatch.cli seal events.jsonl --keys keys --stream-field type
    python -m pqbatch.cli verify events.jsonl --keys keys

The data file is never modified. The sidecar `<file>.pqseal` holds one classical
seal per batch and a single post-quantum checkpoint for the whole file.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import pathlib
import sys

from .keys import SignKey, load_sign_key, load_verify_key
from .records import Anchor, Checkpoint, Seal, decode
from .signers import Sealer
from .verifiers import CheckpointLog, SealVerifier, Tampered

NEVER = float("inf")


def _lines(path: pathlib.Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        for line in fh:
            yield line.rstrip(b"\r\n")


def _stream_of(line: bytes, field: str | None) -> str:
    return "all" if field is None else str(json.loads(line).get(field))


def keygen(args) -> None:
    folder = pathlib.Path(args.dir)
    folder.mkdir(parents=True, exist_ok=True)
    for name, alg in (("pq", args.pq_alg), ("fast", "ed25519")):
        key = SignKey.generate(alg)
        (folder / f"{name}_private.pem").write_bytes(key.to_pem())
        (folder / f"{name}_public.pem").write_bytes(key.public().to_pem())
    print(f"wrote {args.pq_alg} and ed25519 key pairs to {folder}/ (keep the private files out of git)")


def seal(args) -> None:
    keys = pathlib.Path(args.keys)
    sealer = Sealer(
        load_sign_key((keys / "pq_private.pem").read_bytes()),
        load_sign_key((keys / "fast_private.pem").read_bytes()),
        deadline_ms=NEVER, max_batch=args.batch, checkpoint_ms=NEVER,
    )
    data = pathlib.Path(args.file)
    sidecar = pathlib.Path(str(data) + ".pqseal")
    n = size = 0
    with open(sidecar, "w") as out:
        out.write(json.dumps({"format": "pqbatch-sidecar-1", "stream_field": args.stream_field}) + "\n")

        def emit(records, after):
            nonlocal size
            for stream, record, _ in records:
                blob = record.encode()
                size += len(blob)
                out.write(json.dumps({"after": after, "stream": stream, "rec": base64.b64encode(blob).decode()}) + "\n")

        for line in _lines(data):
            n += 1
            emit(sealer.add(_stream_of(line, args.stream_field), line, n), n)
        emit(sealer.flush(n), n)
    print(f"sealed {n} lines, {size} bytes of seals ({size / max(n, 1):.1f} per line) -> {sidecar}")


def verify(args) -> None:
    keys = pathlib.Path(args.keys)
    data = pathlib.Path(args.file)
    with open(str(data) + ".pqseal") as fh:
        header = json.loads(fh.readline())
        entries = [json.loads(line) for line in fh]
    field = header["stream_field"]
    checkpoints = CheckpointLog(load_verify_key((keys / "pq_public.pem").read_bytes()))
    fast = load_verify_key((keys / "fast_public.pem").read_bytes())
    readers: dict[str, SealVerifier] = {}
    position = n = 0

    def apply(upto):
        nonlocal position
        while position < len(entries) and entries[position]["after"] <= upto:
            entry = entries[position]
            record = decode(base64.b64decode(entry["rec"]))
            if isinstance(record, Checkpoint):
                checkpoints.add(record)
            elif entry["stream"] not in readers:
                raise Tampered("seal for a stream with no lines")
            else:
                try:
                    reader = readers[entry["stream"]]
                    reader.seal(record) if isinstance(record, Seal) else reader.anchor(record)
                except Tampered as problem:
                    where = f"stream {entry['stream']!r}, batch ending at line {entry['after']}"
                    raise Tampered(f"{problem} ({where})") from None
            position += 1

    try:
        for line in _lines(data):
            n += 1
            stream = _stream_of(line, field)
            if stream not in readers:
                readers[stream] = SealVerifier(stream, fast, checkpoints)
            readers[stream].event(line)
            apply(n)
        apply(NEVER)
        for reader in readers.values():
            reader.finish()
        checkpoints.check_chain()
        final = sum(r.final_events for r in readers.values())
        if final != n:
            raise Tampered(f"only {final} of {n} lines are covered by the post-quantum signature")
    except Tampered as problem:
        print(f"TAMPERED: {problem}")
        sys.exit(1)
    print(f"OK: {n} lines in {len(readers)} streams, all covered by the post-quantum signature")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("keygen")
    p.add_argument("--dir", default="keys")
    p.add_argument("--pq-alg", default="mldsa65", choices=["mldsa44", "mldsa65", "mldsa87"])
    p.set_defaults(run=keygen)
    for name, run in (("seal", seal), ("verify", verify)):
        p = sub.add_parser(name)
        p.add_argument("file", help="JSON Lines file, plain or .gz")
        p.add_argument("--keys", default="keys")
        if name == "seal":
            p.add_argument("--stream-field", default=None, help="JSON field that splits the file into streams")
            p.add_argument("--batch", type=int, default=1024, help="lines per sealed batch")
        p.set_defaults(run=run)
    args = ap.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
