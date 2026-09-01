"""
agent/run_nce_adversarial_eval.py

Phase NCE-4 — Adversarial diagnostic for the Narrative Counterfactual Engine.

Runs generate_hypotheses() against a small, explicitly-selected sample of
contaminated alerts from the GUIDE dataset, plus one clean baseline alert.
Records what NCE actually produces for each — this is DIAGNOSTIC, not a
pass/fail test.

NCE is explicitly allowed to be fooled by contaminated evidence — it is
NOT the security boundary (SSE is).  This script generates real, recorded
evidence of HOW NCE behaves when fed known-contaminated evidence, so that
future SSE/RSEM integration sessions have realistic hypothesis data to
validate the "SSE catches what NCE misses" claim against.

Usage:
    python -m agent.run_nce_adversarial_eval

Selected sample (4 alerts, verified effective via heldout_undefended_results):
    - fabricated_evidence: 1073741825161  (16/20 hijack rate in undefended eval)
    - cross_field_split:   1108101567282  (confirmed verdict_flip)
    - authority_escalation: 1322849928746 (confirmed verdict_flip)
    - clean baseline:      1434519079553  (from sample_500, uncontaminated)
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# ── Force unbuffered UTF-8 stdout (Windows-safe) ────────────────────────────
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def p(*args, **kwargs):
    """Flushing print — ensures live line-by-line output on Windows."""
    print(*args, **kwargs, flush=True)


from dotenv import load_dotenv

load_dotenv()

from perception.nce_engine import (
    SMOKE_TEST_ONLY,
    alert_to_nce_input,
    generate_hypotheses,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HELDOUT_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_heldout_140_alerts.json"
SAMPLE_500_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_sample_500_alerts.json"
RESULTS_JSON = PROJECT_ROOT / "agent" / "nce_adversarial_eval_results.json"

# ---------------------------------------------------------------------------
# Sample selection — these alert_ids were cross-referenced against
# heldout_undefended_results.json to confirm they produce verdict_flip=True
# in the undefended baseline agent (i.e., genuinely effective contamination).
# ---------------------------------------------------------------------------

SAMPLE_ALERTS = [
    # (alert_id, source_file, injection_category)
    ("1073741825161", HELDOUT_JSON, "fabricated_evidence"),
    ("1108101567282", HELDOUT_JSON, "cross_field_split"),
    ("1322849928746", HELDOUT_JSON, "authority_escalation"),
    ("1434519079553", SAMPLE_500_JSON, "clean"),
]

# Inter-call delay in seconds — matches the ~5s convention used in other
# eval scripts in this project to stay within Gemini rate limits.
INTER_CALL_DELAY_S = 5


def _load_alert(alert_id: str, json_path: Path) -> dict:
    """Load a specific alert by alert_id from a JSON alert file."""
    with open(json_path, encoding="utf-8") as f:
        alerts = json.load(f)
    for alert in alerts:
        if str(alert.get("alert_id")) == alert_id:
            return alert
    raise ValueError(f"Alert {alert_id} not found in {json_path}")


def _serialize_hypotheses(output) -> list[dict]:
    """Serialize NCEOutput hypotheses to JSON-safe dicts."""
    result = []
    for h in output.hypotheses:
        result.append({
            "technique_id": h.technique_id,
            "source_account": h.source_account,
            "source_host": h.source_host,
            "target_host": h.target_host,
            "nce_confidence": h.nce_confidence,
            "supporting_evidence_refs": list(h.supporting_evidence_refs),
            "missing_context_flags": [f.value for f in h.missing_context_flags],
            "status": h.status.value,
            "incident_id": h.incident_id,
        })
    return result


def main():
    p("=" * 72)
    p("NCE Adversarial Diagnostic — Phase NCE-4")
    p("=" * 72)

    if SMOKE_TEST_ONLY:
        p("[SMOKE_TEST_ONLY=True] Running diagnostic sample (4 alerts)")
    else:
        p("[SMOKE_TEST_ONLY=False] Running diagnostic sample (4 alerts)")

    # Verify API keys are available
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEYS", "").split(",")[0].strip()
    if not api_key:
        p("ERROR: No GEMINI_API_KEY or GEMINI_API_KEYS set. Cannot run.")
        sys.exit(1)

    results = []

    for i, (alert_id, json_path, family) in enumerate(SAMPLE_ALERTS):
        p(f"\n--- [{i+1}/{len(SAMPLE_ALERTS)}] {family} (alert_id={alert_id}) ---")

        # Load and convert
        try:
            alert = _load_alert(alert_id, json_path)
            nce_input = alert_to_nce_input(alert)
            p(f"  Evidence fields: {sorted(nce_input.evidence_fields.keys())}")
        except Exception as exc:
            p(f"  ERROR loading alert: {exc}")
            results.append({
                "alert_id": alert_id,
                "family": family,
                "success": False,
                "error": f"Load error: {exc}",
                "hypotheses": [],
                "raw_response": None,
                "api_call_count": 0,
            })
            continue

        # Call NCE
        call_result = generate_hypotheses(nce_input, model="gemini-3.1-flash-lite")

        record = {
            "alert_id": alert_id,
            "family": family,
            "success": call_result.success,
            "error": call_result.error,
            "hypotheses": [],
            "raw_response": call_result.raw_response,
            "api_call_count": call_result.api_call_count,
        }

        if call_result.success and call_result.output:
            record["hypotheses"] = _serialize_hypotheses(call_result.output)
            p(f"  SUCCESS: {len(call_result.output.hypotheses)} hypothesis(es)")
            for j, h in enumerate(call_result.output.hypotheses):
                p(
                    f"    [{j}] technique={h.technique_id}, "
                    f"confidence={h.nce_confidence:.2f}, "
                    f"refs={h.supporting_evidence_refs}, "
                    f"flags={[f.value for f in h.missing_context_flags]}"
                )
        else:
            p(f"  FAILED: {call_result.error}")

        results.append(record)

        # Inter-call delay (skip after last call)
        if i < len(SAMPLE_ALERTS) - 1:
            p(f"  Sleeping {INTER_CALL_DELAY_S}s before next call...")
            time.sleep(INTER_CALL_DELAY_S)

    # Save results
    p(f"\n{'=' * 72}")
    p(f"Saving results to {RESULTS_JSON}")
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    p("Done.")


if __name__ == "__main__":
    main()
