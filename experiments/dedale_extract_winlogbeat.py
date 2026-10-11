"""
experiments/dedale_extract_winlogbeat.py

One-time parallel pass over DEDALE's Windows logs (Phase 2, 2026-10-11): every
hourly member is streamed, records are reduced with dedale.winlogbeat.compact,
and each hour is written as gzip JSONL plus per-hour counts of every
(channel, event id) seen:

    python -m experiments.dedale_extract_winlogbeat [--workers 16] [--only 2025-01-06T10]
    -> <data root>/dedale/derived/winlogbeat/<YYYY-MM-DDTHH>.jsonl.gz
       <data root>/dedale/derived/winlogbeat/<YYYY-MM-DDTHH>.counts.json

Existing hour files are skipped, so an interrupted pass can be resumed.  Labels
are not read (they stay with the scorer).
"""
from __future__ import annotations

import argparse
import collections
import gzip
import json
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

from dedale import data_dir
from dedale.winlogbeat import compact_line, hour_of, iter_lines, line_kind, members

OUT = data_dir() / "derived" / "winlogbeat"


def extract(member: str, out_dir=None) -> tuple[str, int, int, float]:
    t0 = time.perf_counter()
    out_dir = out_dir or OUT
    hour = hour_of(member)
    counts: collections.Counter[str] = collections.Counter()
    kept = 0
    tmp = out_dir / f"{hour}.jsonl.gz.part"
    with gzip.open(tmp, "wt", encoding="utf-8") as out:
        n = 0
        for line in iter_lines(member):
            n += 1
            kind = line_kind(line)
            counts[f"{kind[0]}|{kind[1]}"] += 1
            e = compact_line(line, kind)
            if e is not None:
                out.write(json.dumps(e, separators=(",", ":")) + "\n")
                kept += 1
    (out_dir / f"{hour}.counts.json").write_text(json.dumps({"records": n, "kept": kept, "counts": counts}),
                                                 encoding="utf-8")
    os.replace(tmp, out_dir / f"{hour}.jsonl.gz")
    return hour, n, kept, time.perf_counter() - t0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--only", default=None, help="one hour, e.g. 2025-01-06T10")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    todo = [m for m in members() if (args.only is None or hour_of(m) == args.only)
            and not (OUT / f"{hour_of(m)}.jsonl.gz").exists()]
    print(f"{len(todo)} hours to extract with {args.workers} workers", flush=True)
    t0, total, total_kept = time.perf_counter(), 0, 0
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for i, fut in enumerate(as_completed([pool.submit(extract, m) for m in todo]), 1):
            hour, n, kept, secs = fut.result()
            total += n
            total_kept += kept
            print(f"[{i}/{len(todo)}] {hour}: {n:,} records, {kept:,} kept, {secs:.0f} s", flush=True)
    print(f"done: {total:,} records, {total_kept:,} kept, {time.perf_counter() - t0:.0f} s", flush=True)


if __name__ == "__main__":
    main()
