import json
import random
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_FILES = [
    _PROJECT_ROOT / "agent" / "nce7_scale_results.json",
    _PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runA.json",
    _PROJECT_ROOT / "agent" / "nce8_clean_fp_results.json",
]

_POOL: list[dict] = []

def _load_pool() -> None:
    global _POOL
    if _POOL:
        return

    for p in _FILES:
        if not p.exists():
            continue
        try:
            with p.open(encoding="utf-8") as f:
                data = json.load(f)
            for rec in data:
                if "sse_results" not in rec or "structural_defense_success" not in rec:
                    continue
                _POOL.append(rec)
        except Exception as exc:
            import logging
            logging.warning("Could not load %s: %s", p, exc)

def get_random_demo_alerts(k: int = 5) -> list[dict]:
    """
    Draw a random sample of `k` alerts from the precomputed pool.
    Returns them in the shape expected by the MonitoringWorker / ReplaySource.
    """
    _load_pool()
    if not _POOL:
        # Fallback to curated if pool failed to load (should not happen)
        from monitoring.demo_alerts import CURATED_DEMO_ALERTS
        return random.sample(CURATED_DEMO_ALERTS, min(k, len(CURATED_DEMO_ALERTS)))

    sample = random.sample(_POOL, min(k, len(_POOL)))
    out = []
    for rec in sample:
        aid = rec.get("alert_id", "unknown")
        hyps = rec.get("nce_hypotheses", [])
        
        # Best effort extraction of context
        user = "unknown"
        shost = "unknown"
        thost = "unknown"
        
        if hyps and isinstance(hyps, list) and isinstance(hyps[0], dict):
            user = hyps[0].get("source_account", "unknown")
            shost = hyps[0].get("source_host", "unknown")
            thost = hyps[0].get("target_host", "unknown")
            
        out.append({
            "alert_id": aid,
            "source_system": "EDR",
            "event_type": "process_create",
            "timestamp": "2026-07-24T10:00:00+00:00",
            "source_user": user,
            "source_host": shost,
            "target_host": thost,
            "severity": "medium",
            "process_name": "process.exe",
            "command_line": "process.exe",
            "parent_process": "explorer.exe",
        })
    return out
