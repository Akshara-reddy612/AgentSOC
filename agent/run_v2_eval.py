"""
agent/run_v2_eval.py

Defended-pipeline evaluation on corpus v2 pairs (Phase 3 step 3.4, 2026-10-11).

    python -m agent.run_v2_eval --nce mock-oracle   [--set dev|heldout] [--limit N]
    python -m agent.run_v2_eval --nce mock-hijacked [--set dev|heldout] [--limit N]
    python -m agent.run_v2_eval --nce live          [--set dev|heldout] [--limit N]   # API calls

NCE modes:
  mock-oracle    no API.  Hypotheses built from the alert's TRUSTED fields
                 (T1078 for the real account/host; T1071 to the real destination
                 when there is one).  Shows how the downstream layers treat a
                 correct NCE.
  mock-hijacked  no API.  Worst case: on contaminated alerts NCE does exactly
                 what the payload wants — suppress families yield no hypothesis;
                 identity_steering names the steered account/host (T1550);
                 destination_spoof names the spoofed destination.  Clean alerts
                 as mock-oracle.  An upper bound on NCE compromise, used to see
                 which attacks the structural/guardrail layers still stop.
  live           Gemini via perception.nce_engine.generate_hypotheses (API
                 quota; needs GEMINI_API_KEYS).  Must be requested explicitly.

Output: mock modes -> logs/v2_<set>_<mode>_results.json (gitignored);
live -> agent/v2_results/v2_<set>_live_results.json (+ _api_log.jsonl in parallel mode).
--workers N (live): N threads, each starting on its own key, every call in a
child process with a 60 s hard timeout, 3 attempts with backoff + key rotation
(helpers reused from experiments/run_paired_clean_eval_B_parallel.py).
An existing output file is resumed (records kept); --allow-overwrite starts fresh.
Resume: alerts with a stored outcome are skipped; NCE failures are stored
unscored (nce_error, no outcome) and retried on the next run.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from perception.defended_pipeline import run_downstream  # noqa: E402
from perception.entity_binding import trusted_destination_of  # noqa: E402
from perception.knowledge_graph import KnowledgeStoreGraph  # noqa: E402
from perception.nce_contract import NCEHypothesis  # noqa: E402

V2_DIR = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2"
LIVE_DELAY_S = 2.0


def _public(alert: dict) -> dict:
    return {k: v for k, v in alert.items() if not k.startswith("_")}


def _h(tech, acct, src, tgt, conf=0.6) -> NCEHypothesis:
    return NCEHypothesis(technique_id=tech, source_account=acct or "", source_host=src or "",
                         target_host=tgt or "", nce_confidence=conf, supporting_evidence_refs=["raw_log_line"])


def serialize_hypothesis(h: NCEHypothesis) -> dict:
    return {"technique_id": h.technique_id, "source_account": h.source_account, "source_host": h.source_host,
            "target_host": h.target_host, "nce_confidence": h.nce_confidence,
            "supporting_evidence_refs": list(h.supporting_evidence_refs),
            "missing_context_flags": [f.value for f in h.missing_context_flags]}


def mock_oracle(alert: dict) -> list[NCEHypothesis]:
    hyps = [_h("T1078", alert["source_user"], alert["source_host"], alert["target_host"])]
    dest = trusted_destination_of(alert)
    if dest:
        hyps.append(_h("T1071", alert["source_user"], alert["source_host"], dest))
    return hyps


def mock_hijacked(alert: dict) -> list[NCEHypothesis]:
    fam = alert.get("_ground_truth_injection_category")
    if not alert.get("_ground_truth_is_contaminated"):
        return mock_oracle(alert)
    if fam == "identity_steering":
        user, host = alert["_steered_entities"]
        return [_h("T1550", user, alert["source_host"], host, 0.9)]
    if fam == "destination_spoof":
        trusted = (trusted_destination_of(alert) or "").lower()
        spoofed = [d for d in re.findall(r"[a-z0-9.-]+\.example", alert["raw_log_line"] + " " + alert["command_line"])
                   if d.lower() != trusted]
        return [_h("T1071", alert["source_user"], alert["source_host"], spoofed[-1] if spoofed else "unknown", 0.9)]
    return []  # suppression families: NCE fully talked out of any hypothesis


def live_nce(alert: dict, model: str = "gemini-3.1-flash-lite",
             groq_keys: list[str] | None = None) -> tuple[list[NCEHypothesis] | None, str | None, str | None, int]:
    from perception.nce_engine import alert_to_nce_input, generate_hypotheses
    if groq_keys:   # runs in the worker's child process: start the Groq pool on this worker's key
        import os
        os.environ["GROQ_API_KEYS"] = ",".join(groq_keys)
    res = generate_hypotheses(alert_to_nce_input(_public(alert)), model=model, apply_evidentiary_filter=True)
    if res.success and res.output is not None:
        return list(res.output.hypotheses), None, res.raw_response, res.api_call_count
    return None, res.error or "NCE failed", res.raw_response, res.api_call_count


CALL_TIMEOUT_S = 60
MAX_ATTEMPTS = 3
RETRY_BACKOFF = [5, 10, 20]
MODEL = "gemini-3.1-flash-lite"


def _is_groq(model: str) -> bool:
    return model.startswith("groq:")


def _is_daily_quota(err: str | None) -> bool:
    from agent.llm_utils import DAILY_QUOTA_MARKER
    return bool(err) and DAILY_QUOTA_MARKER in err


def _run_parallel(todo: list[dict], workers: int, finish_live, api_log: Path, model: str = MODEL,
                  call_fn=None) -> bool:
    """
    One thread per worker, each starting on its own key; every NCE call runs in
    a child process with a hard timeout.  Reuses the tested helpers of the
    Experiment 1 parallel harness (experiments/run_paired_clean_eval_B_parallel.py).
    On failure a worker retries with backoff and rotates to the next key.
    Records are finished and written by the main thread only.
    If every key has hit its DAILY quota (2026-10-11), all workers stop taking
    work and nothing is retried; returns True in that case (caller exits 3).
    """
    import queue
    import threading
    from agent.key_pool import load_gemini_pool, load_groq_pool
    from experiments.run_paired_clean_eval_B_parallel import _call_with_timeout, _log_api_call

    call_fn = call_fn or live_nce   # any top-level fn(alert, model=..., groq_keys=...) -> (result|None, err, raw, n_calls)
    groq = _is_groq(model)
    keys = (load_groq_pool() if groq else load_gemini_pool()).keys
    if not keys:
        raise SystemExit(f"No {'GROQ' if groq else 'GEMINI'}_API_KEYS configured")
    work: queue.Queue = queue.Queue()
    for a in todo:
        work.put(a)
    results: queue.Queue = queue.Queue()
    stop = threading.Event()
    DONE = object()

    def worker(wid: int) -> None:
        try:
            _work(wid)
        finally:
            results.put(DONE)

    def _work(wid: int) -> None:
        k = wid % len(keys)
        last = 0.0
        while not stop.is_set():
            try:
                alert = work.get_nowait()
            except queue.Empty:
                return
            res, err = None, None
            for attempt in range(MAX_ATTEMPTS):
                if stop.is_set():
                    break
                wait = LIVE_DELAY_S - (time.time() - last)
                if wait > 0:
                    time.sleep(wait)
                t0 = last = time.time()
                try:
                    if groq:
                        out, _ = _call_with_timeout(call_fn, alert, model=model, groq_keys=keys[k:] + keys[:k],
                                                    timeout=CALL_TIMEOUT_S)
                        last4 = keys[k][-4:]
                    else:
                        out, last4 = _call_with_timeout(call_fn, alert, model=model, active_key=keys[k],
                                                        all_keys=keys, timeout=CALL_TIMEOUT_S)
                    _log_api_call(api_log, alert_id=alert["alert_id"], model=model, key_index=k,
                                  child_key_last4=last4, success=out[0] is not None, api_call_count=out[3],
                                  error=out[1], wall_clock_s=round(time.time() - t0, 2))
                    res = out
                    if out[0] is not None:
                        break
                    err = out[1]
                    if _is_daily_quota(err):
                        stop.set()          # retrying cannot help for hours
                        break
                except Exception as exc:  # noqa: BLE001  (timeout or child failure)
                    err = f"{type(exc).__name__}: {exc}"
                    _log_api_call(api_log, alert_id=alert["alert_id"], model=model, key_index=k,
                                  child_key_last4="", success=False, api_call_count=0, error=err,
                                  wall_clock_s=round(time.time() - t0, 2))
                if attempt < MAX_ATTEMPTS - 1:
                    k = (k + 1) % len(keys)
                    time.sleep(RETRY_BACKOFF[attempt])
            results.put((alert["alert_id"], res if res is not None else (None, err, None, 0)))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(workers)]
    for t in threads:
        t.start()
    n = finished = 0
    while finished < len(threads):
        item = results.get()
        if item is DONE:
            finished += 1
            continue
        aid, res = item
        finish_live(aid, res)
        n += 1
        if n % 20 == 0 or n == len(todo):
            print(f"  {n}/{len(todo)} done", flush=True)
    for t in threads:
        t.join()
    return stop.is_set()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nce", required=True, choices=["mock-oracle", "mock-hijacked", "live"])
    ap.add_argument("--set", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--limit", type=int, default=None, help="process at most N new alerts")
    ap.add_argument("--model", default=MODEL,
                    help="live only: Gemini model name, or groq:<model> (e.g. groq:openai/gpt-oss-20b)")
    ap.add_argument("--workers", type=int, default=1,
                    help="live only: parallel NCE workers (one per key; per-call timeout, retries)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--allow-overwrite", action="store_true")
    args = ap.parse_args()

    if args.out:
        out = Path(args.out)
    elif args.nce == "live":
        tag = "" if args.model == MODEL else "_" + args.model.replace("groq:", "groq-").replace("/", "-")
        out = PROJECT_ROOT / "agent" / "v2_results" / f"v2_{args.set}_live{tag}_results.json"
    else:
        out = PROJECT_ROOT / "logs" / f"v2_{args.set}_{args.nce}_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    alerts = json.loads((V2_DIR / f"guide_v2_{args.set}.json").read_text(encoding="utf-8"))
    done: dict[str, dict] = {}
    if out.exists() and not args.allow_overwrite:   # resume; stored records are never discarded
        done = {r["alert_id"]: r for r in json.loads(out.read_text(encoding="utf-8"))}
    todo = [a for a in alerts if not (a["alert_id"] in done and "outcome" in done[a["alert_id"]])]
    if args.limit is not None:
        todo = todo[: args.limit]
    by_id = {a["alert_id"]: a for a in todo}
    from experiments.run_paired_clean_eval_B_parallel import _atomic_checkpoint_write
    kg = KnowledgeStoreGraph()

    def base(alert: dict) -> dict:
        return {"alert_id": alert["alert_id"], "pair_id": alert["_pair_id"],
                "variant": alert["_variant"], "nce_mode": args.nce,
                "model": args.model if args.nce == "live" else None}

    def finish_live(aid: str, result) -> None:
        hyps, err, raw, n_calls = result
        alert = by_id[aid]
        rec = base(alert) | {"nce_raw_response": raw, "nce_api_calls": n_calls}
        if hyps is None:
            rec["nce_error"] = err          # stored unscored; retried on the next run
        else:
            rec["nce_hypotheses"] = [serialize_hypothesis(h) for h in hyps]   # raw NCE output, for offline re-scoring
            rec.update(run_downstream(hyps, _public(alert), kg))
        done[aid] = rec
        _atomic_checkpoint_write(done, out)

    stopped_by_quota = False
    if args.nce != "live":
        for alert in todo:
            hyps = mock_oracle(alert) if args.nce == "mock-oracle" else mock_hijacked(alert)
            done[alert["alert_id"]] = base(alert) | run_downstream(hyps, _public(alert), kg)
        out.write_text(json.dumps(list(done.values()), indent=1), encoding="utf-8")
    elif args.workers <= 1:
        for alert in todo:
            res = live_nce(alert, model=args.model)
            finish_live(alert["alert_id"], res)
            if res[0] is None and _is_daily_quota(res[1]):
                stopped_by_quota = True
                break
            time.sleep(LIVE_DELAY_S)
    else:
        stopped_by_quota = _run_parallel(todo, args.workers, finish_live,
                                         out.with_name(out.stem.replace("_results", "") + "_api_log.jsonl"),
                                         model=args.model)
    if stopped_by_quota:
        print(f"STOPPED: every key is at its daily quota. {len(done)} records stored -> {out}. "
              f"Resume later with the same command (stored alerts are skipped, NCE errors retried).", flush=True)
        sys.exit(3)
    print(f"{len(todo)} new alerts processed; {len(done)} stored -> {out}")


if __name__ == "__main__":
    main()
