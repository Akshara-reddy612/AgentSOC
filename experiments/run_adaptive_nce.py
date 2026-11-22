"""
experiments/run_adaptive_nce.py

Tier 2, T2.3 (experiments/TIER2_PLAN.md, decision P11, 2026-11-22), live part: NCE (gemini-3.1-flash-lite)
on the adaptive contaminated twins written by experiments/adaptive_payloads.py.  One call per twin
(about 300); the clean twins' answers are the recorded ones.  Reuses the live runner of
agent/run_v2_eval.py by import (no edit), so the record format is the same.  API CALLS: approved budget.

    python -m experiments.run_adaptive_nce [--workers 8] [--limit N]
    -> agent/v2_results/v2_dev_adaptive_live_results.json (+ _api_log.jsonl); resumes; stops on daily quota (exit 3)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent.run_v2_eval import MODEL, _public, _run_parallel, run_downstream, serialize_hypothesis
from perception.knowledge_graph import KnowledgeStoreGraph

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "GUIDE_Dataset" / "processed" / "v2" / "guide_v2_dev_adaptive.json"
OUT = ROOT / "agent" / "v2_results" / "v2_dev_adaptive_live_results.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()
    alerts = json.loads(ALERTS.read_text(encoding="utf-8"))
    done = {r["alert_id"]: r for r in json.loads(OUT.read_text(encoding="utf-8"))} if OUT.exists() else {}
    todo = [a for a in alerts if not (a["alert_id"] in done and "outcome" in done[a["alert_id"]])]
    if args.limit is not None:
        todo = todo[: args.limit]
    by_id = {a["alert_id"]: a for a in todo}
    from experiments.run_paired_clean_eval_B_parallel import _atomic_checkpoint_write
    kg = KnowledgeStoreGraph()

    def finish(aid: str, result) -> None:
        hyps, err, raw, n_calls = result
        a = by_id[aid]
        rec = {"alert_id": aid, "pair_id": a["_pair_id"], "variant": "adaptive", "nce_mode": "live", "model": MODEL,
               "nce_raw_response": raw, "nce_api_calls": n_calls, "era_level": a["_adaptive"]["era_after"]}
        if hyps is None:
            rec["nce_error"] = err
        else:
            rec["nce_hypotheses"] = [serialize_hypothesis(h) for h in hyps]
            rec.update(run_downstream(hyps, _public(a), kg, era_level=a["_adaptive"]["era_after"]))
        done[aid] = rec
        _atomic_checkpoint_write(done, OUT)

    stopped = _run_parallel(todo, args.workers, finish, OUT.with_name("v2_dev_adaptive_live_api_log.jsonl"), model=MODEL)
    if stopped:
        print(f"STOPPED: daily quota reached on every key; {len(done)} stored -> {OUT}", flush=True)
        sys.exit(3)
    print(f"{len(todo)} alerts processed; {len(done)} stored -> {OUT}")


if __name__ == "__main__":
    main()
