"""
experiments/dedale_host_replay.py

Phase 2 replay (2026-10-11): DEDALE's Windows host events (extracted by
experiments/dedale_extract_winlogbeat.py) through the store-backed SOC loop,
fully offline (NCE off, no API calls).  Training weeks: every detector key is
learned (shadow mode).  Test weeks: an event whose key the store has not learned
becomes a host alert -> cases -> triage gate -> gated learning.

    python -m experiments.dedale_host_replay --mode gated [--analyst oracle]
            [--nce live|cache --max-calls N] [--detectors lineage logon lsass_access] [--until 2025-01-08]
            [--no-unlearn] [--closed-world] [--inject suppress|fake_approval|steer]
            [--tag NAME] [--case-store] --overwrite
            [--analyst-persuaded Q --persuasion case|host]   (A10, with --inject and --analyst oracle)

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
import dataclasses
import gzip
import json
import time
from collections import Counter
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
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
# Checklist A11 (2026-11-22): which clean week(s) train the store, as the span of training events to SKIP. The attack
# starts on 2025-01-06, so the training window cannot move later; the test period is always from TRAINING_END.
_MID_TRAINING = datetime(2024, 12, 30, tzinfo=timezone.utc)
TRAIN_WINDOWS = {"both": (None, None),                         # 2024-12-23 .. 2025-01-05 (the frozen runs)
                 "week1": (_MID_TRAINING, TRAINING_END),        # 2024-12-23 .. 12-29, then a week's gap before testing
                 "week2": (TRAINING_START, _MID_TRAINING)}      # 2024-12-30 .. 2025-01-05 only
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


def _training_frequencies(detectors: tuple[str, ...]) -> Counter:
    """How often each detector key occurs in the training weeks.  The loop learns a key the first time it is
    seen and records nothing after, so its edge `count` stays 1 (found 2026-11-22: the first A7 run used that
    count and retracted every training pattern); the frequency must be counted from the events."""
    freq: Counter = Counter()
    for at, event in iter_events(TRAINING_END):
        for name in detectors:
            k = DETECTORS[name].key(event)
            if k is not None:
                e = DETECTORS[name].edge(k)
                freq[(e.src, e.dst, json.dumps(e.key))] += 1
    return freq


def _retract_rare(db: KnowledgeDB, k: int, freq: Counter) -> int:
    """Tier 1 baseline (P10): retract training-learned detector patterns that occurred fewer than `k` times."""
    n = 0
    for src, dst, key, _, _ in db.learned_edges({"training"}):
        attrs = db.edge_attrs(src, dst, key)
        if attrs is None or "detector" not in attrs:            # only detector patterns (not HAS_PRIOR_ACCESS)
            continue
        seen = freq.get((src, dst, json.dumps(key)), 0)
        if seen < k:
            db.retract_edge(src, dst, key, writer="experiment:min_train_count", at=TRAINING_END,
                            reason=f"baseline: seen {seen} < {k} times in training")
            n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", required=True, choices=LEARNING_MODES)
    ap.add_argument("--analyst", default="none", choices=["none", "oracle"])
    ap.add_argument("--analyst-delay", type=float, default=4.0, help="hours from a REVIEW case to its verdict")
    ap.add_argument("--analyst-miss", type=float, default=0.0, help="share of malicious verdicts given as benign")
    ap.add_argument("--analyst-false-alarm", type=float, default=0.0,
                    help="share of benign verdicts given as malicious")
    ap.add_argument("--analyst-seed", type=int, default=0, help="seed of the analyst's mistakes (reproducible)")
    ap.add_argument("--analyst-persuaded", type=float, default=0.0,
                    help="A10: probability that the attacker's injected text talks the analyst out of a malicious "
                         "verdict (needs --inject and --analyst oracle; 0 = off)")
    ap.add_argument("--persuasion", default="case", choices=["case", "host"],
                    help="A10 model: per case, or host-wide once persuaded (experiments/analyst_sim.Persuaded)")
    ap.add_argument("--nce", default="off", choices=["off", "live", "cache"],
                    help="live: Gemini NCE on cases reaching the pipeline (API calls; cached; needs budget approval); "
                         "cache: cached NCE results only, never an API call")
    ap.add_argument("--no-unlearn", action="store_true", help="switch off decision B5 (unlearn on confirmation)")
    ap.add_argument("--inject", default=None, choices=["suppress", "fake_approval", "steer"],
                    help="E1: append attacker-written text to the attacker's command lines (labels pick them)")
    ap.add_argument("--closed-world", action="store_true",
                    help="profile without observed_hosts: SSE treats every missing path as infeasible (pre-Phase-3)")
    ap.add_argument("--max-calls", type=int, default=950, help="hard cap on live NCE calls in this run")
    ap.add_argument("--detectors", nargs="+", default=list(DETECTORS), choices=list(DETECTORS))
    ap.add_argument("--until", default=None, help="stop before this UTC date (YYYY-MM-DD)")
    ap.add_argument("--tag", default=None, help="suffix for the run name (keeps earlier runs of the same condition)")
    ap.add_argument("--case-store", action="store_true", help="also record cases in a case store (review loop)")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--gate-delay", type=float, default=24.0,
                    help="Tier 1 (P10): hours a dismissed case waits before the gate learns it (default 24 = GATE_DELAY)")
    ap.add_argument("--unlearn-lookback", type=float, default=7.0,
                    help="Tier 1 (P10): days of learning B5 retracts on confirmation (default 7 = UNLEARN_LOOKBACK)")
    ap.add_argument("--min-train-count", type=int, default=1,
                    help="Tier 1 (P10) baseline: a training pattern counts as normal only if seen at least K times "
                         "(rarer ones are retracted when training ends; default 1 = all)")
    ap.add_argument("--train-window", default="both", choices=list(TRAIN_WINDOWS),
                    help="checklist A11 (2026-11-22): which clean week(s) the store learns from; the test period "
                         "(from TRAINING_END) is unchanged and events outside the chosen training week are skipped")
    ap.add_argument("--llm-authority", default="full", choices=["full", "escalate"],
                    help="escalate: asymmetric trust, NCE may raise scrutiny but never lower it (decision P9 A)")
    args = ap.parse_args()
    if args.analyst_persuaded and not (args.inject and args.analyst == "oracle"):
        raise SystemExit("--analyst-persuaded needs --inject (the attacker's text) and --analyst oracle")

    run = args.mode + ("_nce" if args.nce != "off" else "") + ("_analyst" if args.analyst == "oracle" else "")
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

    injector = None
    if args.inject:                    # E1 attacker simulation: labels pick the attacker's own commands
        from experiments.dedale_host_score import load_host_labels
        from experiments.dedale_inject import Injector
        injector = Injector(args.inject, load_host_labels())

    analyst = oracle = persuader = None
    if args.analyst == "oracle":       # the only place the replay touches ground truth (separate condition)
        from experiments.analyst_sim import noisy
        from experiments.dedale_host_score import host_oracle
        oracle = host_oracle()
        base = oracle
        if args.analyst_persuaded:     # A10: persuasion acts on the true verdict; random mistakes after it
            from experiments.analyst_sim import Persuaded
            from experiments.dedale_inject import FAMILIES
            persuader = Persuaded(oracle, templates=FAMILIES[args.inject], q=args.analyst_persuaded,
                                  model=args.persuasion, seed=args.analyst_seed)
            base = persuader
        analyst = (noisy(base, miss=args.analyst_miss, false_alarm=args.analyst_false_alarm, seed=args.analyst_seed)
                   if args.analyst_miss or args.analyst_false_alarm else base)

    case_store = None
    if args.case_store:
        cs_path = run_dir / "cases.sqlite"
        for p in (cs_path, Path(f"{cs_path}-wal"), Path(f"{cs_path}-shm")):
            p.unlink(missing_ok=True)
        case_store = CaseStore(cs_path, created_at=TRAINING_START)

    t0 = time.perf_counter()
    profile = dataclasses.replace(DEDALE_PROFILE, observed_hosts=None) if args.closed_world else DEDALE_PROFILE
    db = KnowledgeDB(store_path, profile, created_at=TRAINING_START)
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
            if oracle is not None:
                oracle.observe_alert(case, alert)
            if persuader is not None:
                persuader.observe_alert(case, alert)

        gate_options, nce = {}, None
        from experiments.dedale_nce import CACHE as nce_cache
        if args.inject:
            nce_cache = nce_cache.with_name(f"nce_cache_host_{args.inject}.jsonl")
        if args.nce == "live":
            from experiments.dedale_nce import CallCap, LiveNCE
            cap = CallCap(args.max_calls)
            nce = LiveNCE(cap)
            if args.inject:
                from experiments.dedale_inject import InjectedRouter
                nce = InjectedRouter(args.inject, nce, LiveNCE(cap, cache_path=nce_cache))
            gate_options = {"nce": nce, "budget": cap}
        elif args.nce == "cache":
            from experiments.dedale_nce import LiveNCE
            nce = LiveNCE(None, cache_only=True)
            if args.inject:
                from experiments.dedale_inject import InjectedRouter
                nce = InjectedRouter(args.inject, nce, LiveNCE(None, cache_only=True, cache_path=nce_cache))
            gate_options = {"nce": nce}
        if args.llm_authority != "full":
            gate_options["llm_authority"] = args.llm_authority
        if args.unlearn_lookback != 7.0:       # experiment setting for this run only; the module constant is not edited
            import perception.soc_loop as soc_loop_module
            soc_loop_module.UNLEARN_LOOKBACK = timedelta(days=args.unlearn_lookback)
        loop = SocLoop(db, mode=args.mode, training_end=TRAINING_END, on_case=on_case, analyst=analyst,
                       analyst_delay=timedelta(hours=args.analyst_delay),
                       detectors=tuple(args.detectors), on_alert=on_alert, gate_options=gate_options,
                       case_store=case_store, unlearn_on_confirm=not args.no_unlearn,
                       gate_delay=timedelta(hours=args.gate_delay))
        thresholded = args.min_train_count <= 1
        train_freq = _training_frequencies(tuple(args.detectors)) if not thresholded else None
        last = TRAINING_START
        events = iter_events(until)
        skip_from, skip_until = TRAIN_WINDOWS[args.train_window]
        while chunk := list(islice(events, CHUNK)):
            with db.batch(), (case_store.batch() if case_store else nullcontext()):   # one transaction per chunk
                for at, event in chunk:
                    if skip_from is not None and skip_from <= at < skip_until:      # A11: outside the training week
                        continue
                    if not thresholded and at >= TRAINING_END:     # baseline: forget rare training patterns
                        loop.tick(TRAINING_END)
                        retracted_rare = _retract_rare(db, args.min_train_count, train_freq)
                        thresholded = True
                    if injector is not None:
                        event = injector(event)
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
        **({"analyst_delay_h": args.analyst_delay, "analyst_miss": args.analyst_miss,
            "analyst_false_alarm": args.analyst_false_alarm, "analyst_seed": args.analyst_seed}
           if args.analyst == "oracle" else {}),
        **({"analyst_persuaded": args.analyst_persuaded, "persuasion": args.persuasion,
            "persuaded_verdicts": dict(Counter(why for *_, why in persuader.persuaded)),
            "persuaded_hosts": {h: _iso(at) for h, at in persuader.persuaded_hosts.items()}}
           if persuader is not None else {}),
        "nce": args.nce, "nce_live_calls": nce.live_calls if nce else 0, "nce_cache_hits": nce.cache_hits if nce else 0,
        "nce_cache_misses": nce.cache_misses if nce else 0, "unlearn_on_confirm": not args.no_unlearn,
        "closed_world": args.closed_world, "inject": args.inject, "llm_authority": args.llm_authority,
        "injected_events": injector.injected if injector else 0,
        **({"gate_delay_h": args.gate_delay} if args.gate_delay != 24.0 else {}),
        **({"unlearn_lookback_days": args.unlearn_lookback} if args.unlearn_lookback != 7.0 else {}),
        **({"min_train_count": args.min_train_count, "training_patterns_retracted": retracted_rare}
           if args.min_train_count > 1 else {}),
        **({"train_window": args.train_window} if args.train_window != "both" else {}),
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
