"""
experiments/dedale_replay.py

Phase 1 replay (design step S8, 2026-10-11): DEDALE's Suricata alerts through
the store-backed SOC loop (perception/soc_loop.py), fully offline (NCE off, no
API calls).  One run per learning mode:

    python -m experiments.dedale_replay --mode gated [--overwrite] [--until 2025-01-08]
                                        [--unreasoned review|no_actionable]

Writes outside the repo (data root = $AGENTSOC_DATA_DIR, default <repo>/../agentsoc_data):
    ks/dedale_<run>.sqlite           the run's Knowledge Store (design decision D4)
    runs/dedale_<run>/cases.jsonl    one record per closed case (what the scorer reads)
    runs/dedale_<run>/watches.jsonl  outcome-monitor watches
    runs/dedale_<run>/summary.json   counts and timing
where <run> is the mode, plus "_noact" for --unreasoned no_actionable and
"_analyst" for --analyst oracle (then also runs/dedale_<run>/analyst.jsonl).
Ground truth (labels, attack timeline) is read only by the scorer, and by the
simulated analyst of the separate --analyst oracle condition.
Training window: 2024-12-23 .. 2025-01-05, the weeks the dataset documents as
benign and recommends for training; the test window starts 2025-01-06 00:00 UTC.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

from dedale import data_dir
from dedale.environment import DEDALE_PROFILE, seed_store
from dedale.suricata import alert_time, iter_alerts
from perception.case_builder import Case
from perception.knowledge_db import KnowledgeDB
from perception.soc_loop import LEARNING_MODES, SocLoop
from perception.triage_gate import Decision

TRAINING_START = datetime(2024, 12, 23, tzinfo=timezone.utc)
TRAINING_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
CHUNK = 50_000


def _iso(t: datetime | None) -> str | None:
    return t.isoformat().replace("+00:00", "Z") if t else None


def case_record(case: Case, decision: Decision | None, training: bool) -> dict:
    a = case.first_alert
    rec = {
        "case_id": case.case_id, "training": training, "opened": _iso(case.opened),
        "last_seen": _iso(case.last_seen), "closed": _iso(case.closed),
        "close_reason": case.close_reason, "alert_count": case.alert_count, "sensors": sorted(case.sensors),
        "signature_id": a["signature_id"], "signature": a["signature"], "priority": a["priority"],
        "protocol": a["protocol"], "src_ip": a["src_ip"], "dst_ip": a["dst_ip"], "dst_port": a["dst_port"],
        "source_host": a["source_host"], "target_host": a["target_host"], "destination_ip": a["destination_ip"],
    }
    if decision is not None:
        rec.update(
            decided=_iso(decision.at), path=decision.path, outcome=decision.outcome,
            pipeline_outcome=decision.pipeline_outcome, nce=decision.nce, reasons=decision.reasons,
            store_seq=decision.store_seq,
            actions=[{"technique": h.get("technique_id"), "sse": h.get("sse_verdict"), "action": h.get("top_action"),
                      "target": h.get("top_target_host") or h.get("top_target_account"),
                      "status": h.get("playbook_status")} for h in decision.hypotheses])
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", required=True, choices=LEARNING_MODES)
    ap.add_argument("--unreasoned", default="review", choices=["review", "no_actionable"])
    ap.add_argument("--analyst", default="none", choices=["none", "oracle"],
                    help="oracle: simulated analyst that reads ground truth (separate condition, open decision D1)")
    ap.add_argument("--until", default=None, help="stop before this UTC date (YYYY-MM-DD), for quick runs")
    ap.add_argument("--overwrite", action="store_true", help="replace this run's store and records")
    args = ap.parse_args()

    run = (args.mode + ("_noact" if args.unreasoned == "no_actionable" else "")
           + ("_analyst" if args.analyst == "oracle" else ""))
    root = data_dir().parent
    store_path = root / "ks" / f"dedale_{run}.sqlite"
    run_dir = root / "runs" / f"dedale_{run}"
    if store_path.exists() and not args.overwrite:
        raise SystemExit(f"{store_path} exists (a persistent store); pass --overwrite to replace it")
    for p in (store_path, Path(f"{store_path}-wal"), Path(f"{store_path}-shm")):
        p.unlink(missing_ok=True)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    until = datetime.fromisoformat(args.until).replace(tzinfo=timezone.utc) if args.until else None

    t0 = time.perf_counter()
    db = KnowledgeDB(store_path, DEDALE_PROFILE, created_at=TRAINING_START)
    seed_store(db, TRAINING_START)
    outcomes: Counter[str] = Counter()
    truth, analyst = None, None
    if args.analyst == "oracle":       # the only place the replay touches ground truth (separate condition)
        from experiments.dedale_score import GroundTruth, analyst_oracle, load_label_times
        truth = GroundTruth(load_label_times())
        analyst = analyst_oracle(truth)
    with open(run_dir / "cases.jsonl", "w", encoding="utf-8") as out:
        def on_case(case: Case, decision: Decision | None, training: bool) -> None:
            out.write(json.dumps(case_record(case, decision, training)) + "\n")
            if decision is not None:
                outcomes[decision.outcome] += 1
            if training and truth is not None:
                truth.add_training_key(case.key)

        loop = SocLoop(db, mode=args.mode, training_end=TRAINING_END, on_case=on_case,
                       gate_options={"unreasoned": args.unreasoned}, analyst=analyst)
        alerts = iter_alerts(end=until)
        last = TRAINING_START
        while chunk := list(islice(alerts, CHUNK)):
            with db.batch():
                for alert in chunk:
                    last = alert_time(alert)
                    loop.process(alert, last)
        with db.batch():
            loop.finish(last)

    with open(run_dir / "watches.jsonl", "w", encoding="utf-8") as out:
        for w in loop.monitor.finished:
            out.write(json.dumps({"watch_id": w.watch_id, "case_id": w.case_id, "action": w.action,
                                  "target": w.target, "target_kind": w.target_kind, "since": _iso(w.since),
                                  "until": _iso(w.until), "hits": w.hits, "would_block": w.would_block}) + "\n")
    with open(run_dir / "analyst.jsonl", "w", encoding="utf-8") as out:
        for case_id, at, verdict in loop.verdicts:
            out.write(json.dumps({"case_id": case_id, "at": _iso(at), "verdict": verdict}) + "\n")
    summary = {
        "run": run, "mode": args.mode, "unreasoned": args.unreasoned, "analyst": args.analyst,
        "analyst_verdicts": dict(Counter(v for _, _, v in loop.verdicts)), "until": args.until,
        "training_end": _iso(TRAINING_END), "counts": dict(loop.counts), "test_outcomes": dict(outcomes),
        "nce_backlog": loop.gate.backlog,
        "gate_pending_at_end": loop.updater.pending if loop.updater else None,
        "gate_dropped": loop.updater.dropped if loop.updater else None,
        "edges_by_type_and_provenance": {f"{t}|{lf}": n for (t, lf), n in sorted(db.edge_counts().items())},
        "store_log_entries": db.last_seq(), "watches": len(loop.monitor.finished),
        "runtime_s": round(time.perf_counter() - t0, 1), "store": str(store_path),
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    db.close()
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
