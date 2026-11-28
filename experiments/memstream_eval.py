"""
experiments/memstream_eval.py

Checklist A7 (2026-11-28; design experiments/A7_MEMSTREAM_DESIGN.md): MemStream (experiments/memstream.py) on
DEDALE's host events, the same detector-keyed events the keyed store sees.  Offline, CPU only.

    python -m experiments.memstream_eval score --beta 0.1 [--init first|sample] [--plant test|slow] [--tag T]
        -> <data>/runs/a7_memstream/<tag>.npz (+ .json): per detector-keyed event in replay order from the stream
           start: host, channel, record id, time, score, whether it entered memory
    python -m experiments.memstream_eval curve
        -> experiments/dedale_results/a7_memstream_curve.json: per score file, labelled attack events alerted
           against benign events alerted per day as the threshold varies, beside the keyed store's runs

The stream starts 24 h before the test period (or before the first plant): MemStream's FIFO memory takes far more
than N updates a day, so the memory it holds at the start of the test period does not depend on the weeks before
(design, "Stream").  Events come in exactly the replay's order (dedale_host_replay.iter_events, plants merged in time
order), so a replay can read the scores in sequence (experiments/memstream_loop.py).
"""
from __future__ import annotations

import argparse
import gzip
import heapq
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

from dedale import data_dir
from experiments.dedale_host_replay import EVENTS, TRAINING_END, TRAINING_START, _t
from experiments.memstream import DIM, MemStream, detector_keys, features
from perception.host_detection import malformed_host_event

OUT_DIR = data_dir().parent / "runs" / "a7_memstream"
CURVE = Path(__file__).resolve().parent / "dedale_results" / "a7_memstream_curve.json"
TEST_DAYS = 14
WARM = timedelta(hours=24)


def iter_from(start: datetime):
    """dedale_host_replay.iter_events restricted to the hours from `start` (same order)."""
    first = start.replace(minute=0, second=0, microsecond=0)
    for path in sorted(EVENTS.glob("*.jsonl.gz")):
        hour = _t(path.name.split(".")[0] + ":00:00Z")
        if hour < first:
            continue
        with gzip.open(path, "rt", encoding="utf-8") as f:
            events = [json.loads(line) for line in f]
        events.sort(key=lambda e: e["t"])
        for e in events:
            at = _t(e["t"])
            if at >= start:
                yield at, e


def keyed(stream):
    """(time, event, detector keys) for the events some detector keys (malformed events are refused, as the loop does)."""
    for at, e in stream:
        if malformed_host_event(e):
            continue
        keys = detector_keys(e)
        if keys:
            yield at, e, keys


def init_records(how: str, n: int, seed: int) -> np.ndarray:
    """The N records the autoencoder is trained on and the memory starts from: the first N training records (as the
    reference code), or a uniform sample of the training weeks (a stronger baseline)."""
    rows = []
    if how == "first":
        for at, e, keys in keyed(iter_from(TRAINING_START)):
            rows.append(features(keys, at))
            if len(rows) == n:
                break
    else:
        rng, seen = random.Random(seed), 0
        for at, e, keys in keyed(iter_from(TRAINING_START)):
            if at >= TRAINING_END:
                break
            seen += 1
            if len(rows) < n:
                rows.append(features(keys, at))
            elif (j := rng.randrange(seen)) < n:
                rows[j] = features(keys, at)
    return np.stack(rows)


def score(args) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tag = args.tag or f"b{args.beta:g}_{args.init}" + (f"_{args.plant}" if args.plant else "")
    t0 = time.perf_counter()
    ms = MemStream(init_records(args.init, args.n, args.seed), beta=args.beta, k=3, gamma=0.0, seed=args.seed)
    t_train = time.perf_counter() - t0
    planted = []
    if args.plant:
        from experiments.dedale_plant import PLANTABLE, plants
        planted = plants(args.plant, PLANTABLE)
    start = min([TRAINING_END, *(p[0] for p in planted)]) - WARM
    stream = iter_from(start)
    if planted:
        stream = heapq.merge(stream, [p for p in planted if p[0] >= start], key=lambda x: x[0])
    hosts, host_ix = [], {}
    cols = {k: [] for k in ("host", "ch", "rid", "t", "score", "admitted")}
    chans = {"sysmon": 0, "security": 1, "powershell": 2}
    for at, e, keys in keyed(stream):
        s, upd = ms.step(features(keys, at))
        h = host_ix.setdefault(e["host"], len(hosts))
        if h == len(hosts):
            hosts.append(e["host"])
        cols["host"].append(h)
        cols["ch"].append(chans.get(e["ch"], 3))
        cols["rid"].append(int(e["rid"]))
        cols["t"].append(at.timestamp())
        cols["score"].append(s)
        cols["admitted"].append(upd)
    np.savez_compressed(OUT_DIR / f"{tag}.npz", host=np.array(cols["host"], np.int16), ch=np.array(cols["ch"], np.int8),
                        rid=np.array(cols["rid"], np.int64), t=np.array(cols["t"], np.float64),
                        score=np.array(cols["score"], np.float32), admitted=np.array(cols["admitted"], bool))
    meta = {"tag": tag, "beta": args.beta, "init": args.init, "n": args.n, "k": 3, "gamma": 0.0, "dim": DIM,
            "seed": args.seed, "plant": args.plant, "stream_from": start.isoformat(), "hosts": hosts,
            "channels": chans, "records": len(cols["score"]), "memory_updates": ms.updates,
            "train_loss": ms.train_loss, "train_s": round(t_train, 1), "runtime_s": round(time.perf_counter() - t0, 1)}
    (OUT_DIR / f"{tag}.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(json.dumps(meta | {"hosts": len(hosts)}, indent=1))


def _keyed_points(labels: dict) -> dict:
    """Event-level operating points of recorded keyed-store runs: labelled attack events and benign events alerted."""
    runs = data_dir().parent / "runs"
    out = {}
    for name in ("frozen_F_frozen", "gated_F_gated", "gated_analyst_F_d4"):
        p = runs / f"dedale_host_{name}" / "alerts.jsonl.gz"
        if not p.exists():
            continue
        refs = set()
        with gzip.open(p, "rt", encoding="utf-8") as f:
            for _case, host, ch, rid in map(json.loads, f):
                refs.add((host, ch, rid))
        attack = sum(1 for r in refs if labels.get(r) == 1)
        out[name] = {"attack_events": attack, "benign_per_day": round((len(refs) - attack) / TEST_DAYS, 1)}
    return out


def curve(args) -> None:
    from experiments.dedale_host_novelty import load_host_labels
    labels = load_host_labels()
    chans = {0: "sysmon", 1: "security", 2: "powershell"}
    test_start = TRAINING_END.timestamp()
    out = {"keyed_store": _keyed_points(labels), "memstream": {}}
    for meta_path in sorted(OUT_DIR.glob("*.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("plant"):
            continue
        z = np.load(OUT_DIR / f"{meta['tag']}.npz")
        test = z["t"] >= test_start
        hosts = meta["hosts"]
        is_attack = np.array([labels.get((hosts[h], chans.get(c, "?"), int(r))) == 1
                              for h, c, r in zip(z["host"][test], z["ch"][test], z["rid"][test])])
        s = z["score"][test].astype(np.float64)
        train_s = z["score"][~test].astype(np.float64)
        pts = []
        for q in np.unique(np.concatenate([np.logspace(-5, np.log10(0.5), 60), [1e-3]])):
            tau = float(np.quantile(s, 1 - q))
            alert = s > tau
            pts.append({"tau": tau, "share_alerted": round(float(alert.mean()), 6),
                        "attack_events": int((alert & is_attack).sum()),
                        "benign_per_day": round(float((alert & ~is_attack).sum()) / TEST_DAYS, 1)})
        out["memstream"][meta["tag"]] = {
            "beta": meta["beta"], "init": meta["init"], "attack_events_total": int(is_attack.sum()),
            "test_records": int(test.sum()), "admitted_test": int(z["admitted"][test].sum()),
            "tau_train_p999": float(np.quantile(train_s, 0.999)) if train_s.size else None, "points": pts}
    CURVE.write_text(json.dumps(out, indent=1), encoding="utf-8")
    for name, p in out["keyed_store"].items():
        print(f"keyed {name:22s} attack events {p['attack_events']:4} | benign alerted/day {p['benign_per_day']}")
    for tag, m in out["memstream"].items():
        ref = out["keyed_store"].get("gated_F_gated", {}).get("benign_per_day")
        best = max((pt for pt in m["points"] if ref is None or pt["benign_per_day"] <= ref),
                   key=lambda pt: pt["attack_events"], default=None)
        print(f"memstream {tag:22s} attack events at <= gated's benign rate: {best and best['attack_events']} "
              f"(of {m['attack_events_total']}; {best and best['benign_per_day']} benign/day) | admitted "
              f"{m['admitted_test']}/{m['test_records']}")
    print(f"-> {CURVE}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("score")
    s.add_argument("--beta", type=float, required=True)
    s.add_argument("--init", default="first", choices=["first", "sample"])
    s.add_argument("--n", type=int, default=2048)
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--plant", default=None, choices=["test", "slow"])
    s.add_argument("--tag", default=None)
    sub.add_parser("curve")
    args = ap.parse_args()
    {"score": score, "curve": curve}[args.cmd](args)


if __name__ == "__main__":
    main()
