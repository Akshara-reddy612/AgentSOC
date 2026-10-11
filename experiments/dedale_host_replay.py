"""
experiments/dedale_host_replay.py

Phase 2 replay (2026-10-11): DEDALE's Windows host events (extracted by
experiments/dedale_extract_winlogbeat.py) through the store-backed SOC loop,
fully offline (NCE off, no API calls).  Training weeks: every detector key is
learned (shadow mode).  Test weeks: an event whose key the store has not learned
becomes a host alert -> cases -> triage gate -> gated learning.

    python -m experiments.dedale_host_replay --mode gated [--analyst oracle]
            [--nce live --max-calls N] [--detectors lineage logon lsass_access] [--until 2025-01-08]
            [--tag NAME] [--case-store] --overwrite

Writes outside the repo (data root = $AGENTSOC_DATA_DIR, default <repo>/../agentsoc_data):
    ks/dedale_host_<run>.sqlite                the run's Knowledge Store
    runs/dedale_host_<run>/cases.jsonl         one record per closed case
    runs/dedale_host_<run>/alerts.jsonl.gz     (case id, event reference) per host alert, for the scorer
    runs/dedale_host_<run>/{watches,analyst}.jsonl, summary.json
    runs/dedale_host_<run>/cases.sqlite        with --case-store: the review loop's case store
Events of one hour are replayed in time order; an event stamped earlier than
the previous one (files are per hour, shipping is asynchronous) is processed
at the previous event's time.  Labels are never read here, except by the
simulated analyst of the separate --analyst oracle condition.
"""
from __future__ import annotations

import argparse
import gzip
import json
import time
from collections import Counter
from contextlib import nullcontext
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

from dedale import data_dir
from dedale.environment import DEDALE_PROFILE, seed_store
from perception.case_builder import Case
from perception.case_store import CaseStore
from perception.host_detection import DETECTORS
from perception.knowledge_db import KnowledgeDB
from perception.soc_loop import LEARNING_MODES, SocLoop
from perception.triage_gate import Decision

TRAINING_START = datetime(2024, 12, 23, tzinfo=timezone.utc)
TRAINING_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
EVENTS = data_dir() / "derived" / "winlogbeat"
CHUNK = 50_000


def _iso(t: datetime | None) -> str | None:
    return t.isoformat().replace("+00:00", "Z") if t else None


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def iter_events(until: datetime | None = None):
    """(time, event) over all extracted hours, in time order within each hour."""
    for path in sorted(EVENTS.glob("*.jsonl.gz")):
        hour = path.name.split(".")[0]
        if until and _t(hour + ":00:00Z") >= until:
            break
        with gzip.open(path, "rt", encoding="utf-8") as f:
            events = [json.loads(line) for line in f]
        events.sort(key=lambda e: e["t"])
        for e in events:
            yield _t(e["t"]), e


def case_record(case: Case, decision: Decision | None) -> dict:
    a = case.first_alert
    rec = {"case_id": case.case_id, "opened": _iso(case.opened), "last_seen": _iso(case.last_seen),
           "closed": _iso(case.closed), "close_reason": case.close_reason, "alert_count": case.alert_count,
           "detector": a.get("detector"), "detector_key": a.get("detector_key"), "host": a.get("target_host"),
           "source_host": a.get("source_host"), "user": a.get("source_user"),
           "process_name": a.get("process_name"), "parent_process": a.get("parent_process"),
           "command_line": (a.get("command_line") or "")[:300] or None}
    if decision is not None:
        rec.update(decided=_iso(decision.at), path=decision.path, outcome=decision.outcome,
                   pipeline_outcome=decision.pipeline_outcome, nce=decision.nce, reasons=decision.reasons,
                   hypotheses=[{k: h.get(k) for k in ("technique_id", "sse_verdict", "entity_binding", "top_action",
                                                      "playbook_status")} for h in decision.hypotheses])
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", required=True, choices=LEARNING_MODES)
    ap.add_argument("--analyst", default="none", choices=["none", "oracle"])
    ap.add_argument("--nce", default="off", choices=["off", "live"],
                    help="live: Gemini NCE on cases reaching the pipeline (API calls; cached; needs budget approval)")
    ap.add_argument("--max-calls", type=int, default=950, help="hard cap on live NCE calls in this run")
    ap.add_argument("--detectors", nargs="+", default=list(DETECTORS), choices=list(DETECTORS))
    ap.add_argument("--until", default=None, help="stop before this UTC date (YYYY-MM-DD)")
    ap.add_argument("--tag", default=None, help="suffix for the run name (keeps earlier runs of the same condition)")
    ap.add_argument("--case-store", action="store_true", help="also record cases in a case store (review loop)")
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()

    run = args.mode + ("_nce" if args.nce == "live" else "") + ("_analyst" if args.analyst == "oracle" else "")
    run += f"_{args.tag}" if args.tag else ""
    root = data_dir().parent
    store_path = root / "ks" / f"dedale_host_{run}.sqlite"
    run_dir = root / "runs" / f"dedale_host_{run}"
    if store_path.exists() and not args.overwrite:
        raise SystemExit(f"{store_path} exists (a persistent store); pass --overwrite to replace it")
    for p in (store_path, Path(f"{store_path}-wal"), Path(f"{store_path}-shm")):
        p.unlink(missing_ok=True)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    until = datetime.fromisoformat(args.until).replace(tzinfo=timezone.utc) if args.until else None

    analyst = None
    if args.analyst == "oracle":       # the only place the replay touches ground truth (separate condition)
        from experiments.dedale_host_score import host_oracle
        analyst = host_oracle()

    case_store = None
    if args.case_store:
        cs_path = run_dir / "cases.sqlite"
        for p in (cs_path, Path(f"{cs_path}-wal"), Path(f"{cs_path}-shm")):
            p.unlink(missing_ok=True)
        case_store = CaseStore(cs_path, created_at=TRAINING_START)

    t0 = time.perf_counter()
    db = KnowledgeDB(store_path, DEDALE_PROFILE, created_at=TRAINING_START)
    seed_store(db, TRAINING_START)
    outcomes: Counter[str] = Counter()
    with open(run_dir / "cases.jsonl", "w", encoding="utf-8") as cases_out, \
            gzip.open(run_dir / "alerts.jsonl.gz", "wt", encoding="utf-8") as alerts_out:
        def on_case(case: Case, decision: Decision | None, training: bool) -> None:
            cases_out.write(json.dumps(case_record(case, decision)) + "\n")
            if decision is not None:
                outcomes[decision.outcome] += 1

        def on_alert(case: Case, alert: dict) -> None:
            alerts_out.write(json.dumps([case.case_id, *alert["event_ref"]]) + "\n")
            if analyst is not None:
                analyst.observe_alert(case, alert)

        gate_options, nce = {}, None
        if args.nce == "live":
            from experiments.dedale_nce import CallCap, LiveNCE
            cap = CallCap(args.max_calls)
            nce = LiveNCE(cap)
            gate_options = {"nce": nce, "budget": cap}
        loop = SocLoop(db, mode=args.mode, training_end=TRAINING_END, on_case=on_case, analyst=analyst,
                       detectors=tuple(args.detectors), on_alert=on_alert, gate_options=gate_options,
                       case_store=case_store)
        last = TRAINING_START
        events = iter_events(until)
        while chunk := list(islice(events, CHUNK)):
            with db.batch(), (case_store.batch() if case_store else nullcontext()):   # one transaction per chunk
                for at, event in chunk:
                    last = max(at, last)
                    loop.process_host_event(event, last)
        with db.batch(), (case_store.batch() if case_store else nullcontext()):
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
        "run": run, "mode": args.mode, "analyst": args.analyst, "detectors": args.detectors, "until": args.until,
        "nce": args.nce, "nce_live_calls": nce.live_calls if nce else 0, "nce_cache_hits": nce.cache_hits if nce else 0,
        "counts": dict(loop.counts), "test_outcomes": dict(outcomes),
        "analyst_verdicts": dict(Counter(v for _, _, v in loop.verdicts)),
        "gate_pending_at_end": loop.updater.pending if loop.updater else None,
        "gate_dropped": loop.updater.dropped if loop.updater else None,
        "edges_by_type_and_provenance": {f"{t}|{lf}": n for (t, lf), n in sorted(db.edge_counts().items())},
        "store_log_entries": db.last_seq(), "runtime_s": round(time.perf_counter() - t0, 1),
        "store": str(store_path),
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    db.close()
    if case_store is not None:
        case_store.close()
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
