"""
experiments/dedale_nce.py

Live NCE for DEDALE host alerts (Phase 3, 2026-10-11): Gemini via
perception.nce_engine.generate_hypotheses with the full technique vocabulary
(design decision D6), a persistent cache and a hard cap on live calls.

  - Cache: <data root>/runs/nce_cache_host.jsonl, one line per alert id
    (hypotheses or error).  A replay that meets the same alert again (another
    learning mode, a rerun) reuses it, so the API budget is spent once.
  - API log: <data root>/runs/nce_api_log_host.jsonl, append-only, one line per
    live call (monitor runs with this file, never with result files).
  - Cap: after `max_calls` live calls, `budget.available()` is False and the
    triage gate marks further cases "budget_exhausted" (unreasoned -> review).
  - Cache-only (`cache_only=True`, M1 reproduction): no live call is ever
    made; an alert missing from the cache raises, the gate records NCE
    "error" (unreasoned -> review), and `cache_misses` counts it.
API keys are never printed or logged.
"""
from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from dedale import data_dir
from perception.nce_contract import MissingContextFlag, NCEHypothesis
from perception.sse import TECHNIQUE_TABLE

MODEL = "gemini-3.1-flash-lite"
CACHE = data_dir().parent / "runs" / "nce_cache_host.jsonl"
# The answers recorded for the paper, kept in the repository (2026-10-20, handover).  A machine whose data
# folder has no cache yet starts from a copy of them; live answers are only ever appended to that copy.
RECORDED = Path(__file__).resolve().parent / "dedale_results" / "nce_cache"
API_LOG = data_dir().parent / "runs" / "nce_api_log_host.jsonl"


def _ser(h: NCEHypothesis) -> dict:
    return {"technique_id": h.technique_id, "source_account": h.source_account, "source_host": h.source_host,
            "target_host": h.target_host, "nce_confidence": h.nce_confidence,
            "supporting_evidence_refs": list(h.supporting_evidence_refs),
            "missing_context_flags": [f.value for f in h.missing_context_flags]}


def _de(d: dict) -> NCEHypothesis:
    return NCEHypothesis(technique_id=d["technique_id"], source_account=d["source_account"] or "",
                         source_host=d["source_host"] or "", target_host=d["target_host"] or "",
                         nce_confidence=float(d["nce_confidence"]),
                         supporting_evidence_refs=list(d["supporting_evidence_refs"] or ["raw_log_line"]),
                         missing_context_flags=[MissingContextFlag(f) for f in d["missing_context_flags"]])


class CallCap:
    """The gate's budget interface over a total number of live calls (not per day)."""

    def __init__(self, max_calls: int) -> None:
        self.max_calls = max_calls
        self.used = 0

    def available(self, at=None) -> bool:
        return self.used < self.max_calls

    def take(self, at=None) -> bool:
        return self.available(at)          # the call itself counts, in LiveNCE


class LiveNCE:
    """Callable for TriageGate(nce=...): cached results first, otherwise one live call (counted against the cap)."""

    def __init__(self, cap: CallCap | None, model: str = MODEL, *, cache_only: bool = False,
                 cache_path: Path = CACHE) -> None:
        if cap is None and not cache_only:
            raise ValueError("live NCE needs a call cap")
        self.cap = cap
        self.model = model
        self.cache_only = cache_only
        self.cache_misses = 0
        self.cache_path = cache_path         # E1: one cache per payload family (same alert ids, other text)
        if not cache_path.exists() and (RECORDED / cache_path.name).exists():
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(RECORDED / cache_path.name, cache_path)
        self.cache: dict[str, dict] = {}
        if cache_path.exists():
            with open(cache_path, encoding="utf-8") as f:
                for line in f:
                    rec = json.loads(line)
                    self.cache[rec["alert_id"]] = rec
        self.live_calls = 0
        self.cache_hits = 0

    def __call__(self, alert: dict) -> list[NCEHypothesis]:
        rec = self.cache.get(alert["alert_id"])
        if rec is None and self.cache_only:
            self.cache_misses += 1
            raise RuntimeError("alert not in the NCE cache (cache-only mode)")
        if rec is None:
            if not self.cap.available():
                raise RuntimeError("live NCE call cap reached")
            rec = self._live(alert)
        else:
            self.cache_hits += 1
        if rec.get("error"):
            raise RuntimeError(rec["error"])
        return [_de(h) for h in rec["hypotheses"]]

    def _live(self, alert: dict) -> dict:
        from perception.nce_engine import alert_to_nce_input, generate_hypotheses

        t0 = time.time()
        res = generate_hypotheses(alert_to_nce_input(alert), model=self.model, techniques=sorted(TECHNIQUE_TABLE))
        self.cap.used += 1
        self.live_calls += 1
        ok = res.success and res.output is not None
        rec = {"alert_id": alert["alert_id"], "model": self.model,
               "hypotheses": [_ser(h) for h in res.output.hypotheses] if ok else [],
               "error": None if ok else (res.error or "NCE failed"), "api_call_count": res.api_call_count}
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        with open(API_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "alert_id": alert["alert_id"],
                                "model": self.model, "success": ok, "api_call_count": res.api_call_count,
                                "error": rec["error"], "wall_clock_s": round(time.time() - t0, 2)}) + "\n")
        self.cache[alert["alert_id"]] = rec
        return rec
