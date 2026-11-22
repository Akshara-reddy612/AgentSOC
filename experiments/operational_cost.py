"""
experiments/operational_cost.py

Checklist B5 (2026-11-22): latency, token cost and review-queue growth, from recorded data only (no API call).

1. Latency: wall-clock seconds of successful calls in the recorded API logs (agent/v2_results/*_api_log.jsonl).
   This is the end-to-end time per call as measured by the runner, so it includes network time and the free
   tier's queueing. Calls logged on 2026-11-22, when Gemini was overloaded, are reported apart from the rest.
2. Tokens (ESTIMATE, 4 characters per token; the runs did not log token counts):
   - NCE prompt = the fixed instructions + the evidence fields as NCE sees them (512 characters per field,
     2,048 in total), computed from the GUIDE dev alerts;
   - NCE response = the recorded raw responses (agent/v2_results/v2_dev_live_results.json).
3. NCE calls per day on DEDALE: from the run summaries (cache hits + live calls; 14 test days).
4. Review queue: cases opened and not yet answered by the simulated analyst, from cases.jsonl (opened) and
   analyst.jsonl (verdict time), per analyst delay; without an analyst every review stays open.

    python -m experiments.operational_cost  -> prints; writes experiments/dedale_results/operational_cost.json
"""
from __future__ import annotations

import json
import statistics
from datetime import datetime
from pathlib import Path

from dedale import data_dir

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "agent" / "v2_results"
OUT = ROOT / "experiments" / "dedale_results" / "operational_cost.json"
CHARS_PER_TOKEN = 4
TEST_DAYS = 14


def _pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]


def latency() -> dict:
    out = {}
    for path in sorted(RES.glob("*_api_log.jsonl")):
        normal, overloaded = [], []
        for line in path.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r.get("success") and r.get("wall_clock_s") is not None:
                (overloaded if r["timestamp"].startswith("2026-11-22") else normal).append(r["wall_clock_s"])
        for label, xs in (("", normal), ("_2026-11-22", overloaded)):
            if len(xs) >= 20:
                out[path.name.replace("_api_log.jsonl", "") + label] = {
                    "calls": len(xs), "median_s": round(statistics.median(xs), 2),
                    "p90_s": round(_pct(xs, 0.9), 2), "p99_s": round(_pct(xs, 0.99), 2)}
    return out


def tokens() -> dict:
    from perception.nce_engine import _NCE_EVIDENCE_FIELD_NAMES
    from prompt_construction.nce_prompt_builder import nce_instructions
    from risk_assessment.config import MAX_PROMPT_FIELD_LENGTH, MAX_TOTAL_PROMPT_LENGTH
    alerts = json.loads((ROOT / "GUIDE_Dataset" / "processed" / "v2" / "guide_v2_dev.json").read_text(encoding="utf-8"))
    instr = len(nce_instructions())
    prompts = []
    for a in alerts:
        ev = sum(min(len(str(a[f])), MAX_PROMPT_FIELD_LENGTH) for f in _NCE_EVIDENCE_FIELD_NAMES if a.get(f))
        prompts.append(instr + min(ev, MAX_TOTAL_PROMPT_LENGTH))
    resp = [len(r["nce_raw_response"]) for r in json.loads((RES / "v2_dev_live_results.json").read_text(encoding="utf-8"))
            if r.get("nce_raw_response")]
    pin, pout = statistics.mean(prompts) / CHARS_PER_TOKEN, statistics.mean(resp) / CHARS_PER_TOKEN
    return {"estimate": f"{CHARS_PER_TOKEN} characters per token", "instructions_chars": instr,
            "prompt_tokens_mean": round(pin), "prompt_tokens_max": round(max(prompts) / CHARS_PER_TOKEN),
            "response_tokens_mean": round(pout), "responses": len(resp), "tokens_per_call_mean": round(pin + pout)}


def nce_calls_per_day() -> dict:
    out = {}
    for run in ("gated_nce_A_nce", "gated_nce_analyst_A_nce_d4", "gated_nce_F_nce", "gated_nce_analyst_F_nce_d4"):
        p = data_dir().parent / "runs" / f"dedale_host_{run}" / "summary.json"
        if p.exists():
            s = json.loads(p.read_text(encoding="utf-8"))
            calls = s.get("nce_cache_hits", 0) + s.get("nce_live_calls", 0)
            out[run] = {"nce_calls": calls, "per_day": round(calls / TEST_DAYS, 1), "test_cases": s["counts"]["cases_test"]}
    return out


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def queue() -> dict:
    out = {}
    for run in ("gated_analyst_F_d1", "gated_analyst_F_d4", "gated_analyst_F_d24", "gated_analyst_F_d72", "frozen_F_frozen"):
        d = data_dir().parent / "runs" / f"dedale_host_{run}"
        if not (d / "cases.jsonl").exists():
            continue
        opened = {}
        for line in (d / "cases.jsonl").read_text(encoding="utf-8").splitlines():
            c = json.loads(line)
            if c.get("outcome") == "REVIEW" or c.get("final_outcome") == "REVIEW" or c.get("path"):
                opened[c["case_id"]] = _t(c["decided"] if c.get("decided") else c["opened"])
        answered = {}
        ap = d / "analyst.jsonl"
        if ap.exists():
            for line in ap.read_text(encoding="utf-8").splitlines():
                v = json.loads(line)
                answered.setdefault(v["case_id"], _t(v["at"]))
        events = sorted([(t, 1) for t in opened.values()] + [(t, -1) for cid, t in answered.items() if cid in opened])
        q = peak = 0
        for _, step in events:
            q += step
            peak = max(peak, q)
        waits = [(answered[c] - opened[c]).total_seconds() / 3600 for c in opened if c in answered]
        out[run] = {"reviews": len(opened), "answered": len(waits), "peak_open_reviews": peak,
                    "open_at_end": q, "median_wait_h": round(statistics.median(waits), 2) if waits else None}
    return out


def main() -> None:
    res = {"latency": latency(), "tokens": tokens(), "nce_calls_per_day": nce_calls_per_day(), "queue": queue()}
    print(json.dumps(res, indent=1))
    OUT.write_text(json.dumps(res, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
