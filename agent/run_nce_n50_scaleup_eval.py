"""
agent/run_nce_n50_scaleup_eval.py

Phase NCE-N50-SCALEUP — Scaled contaminated structural defense evaluation
from n=10 to n=50 per family (80 -> 400 total).

Runs the full NCE (gemini-3.1-flash-lite) -> SSE -> RSEM pipeline on all 320
new alerts from GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json.

Key features:
  - Dynamic round-robin key rotation across all 5 GEMINI_API_KEYS
  - Per-alert incremental checkpointing to agent/nce_n50_scaleup_results.json
  - Safe resume: skips any alert_id already completed
  - JSONL API audit logging to agent/nce_n50_scaleup_api_call_log.jsonl
  - Dual SSE evaluation: captures both pre-filter baseline (apply_evidentiary_filter=False)
    and post-filter (_apply_t1071_evidentiary_filter) from the exact same LLM call.

CRITICAL INVARIANTS:
  - Does NOT modify or overwrite agent/nce7_scale_results.json
  - nce_confidence is NEVER used as an input to SSE or RSEM
"""
from __future__ import annotations

import json
import logging
import os
import random
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

# Force unbuffered UTF-8 stdout (Windows-safe)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def p(*args, **kwargs):
    """Flushing print."""
    print(*args, **kwargs, flush=True)


from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import (
    HypothesisStatus,
    MissingContextFlag,
    NCEHypothesis,
    NCEOutput,
)
from perception.nce_engine import (
    _apply_t1071_evidentiary_filter,
    alert_to_nce_input,
    generate_hypotheses,
)
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.nce_sse_integration import (
    ValidatedHypothesis,
    validate_hypothesis_with_sse,
)
from perception.rsem import (
    ActionType,
    ProposedAction,
    RiskWeights,
)
from perception.sse import StructuralSimulationEngine

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

SCALEUP_ALERTS_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_n50_scaleup_320_alerts.json"
RESULTS_JSON = PROJECT_ROOT / "agent" / "nce_n50_scaleup_results.json"
API_CALL_LOG = PROJECT_ROOT / "agent" / "nce_n50_scaleup_api_call_log.jsonl"

INTER_CALL_DELAY_S = 2.0  # Reduced delay with 5 rotating keys
PROGRESS_INTERVAL = 10

TARGET_FAMILIES = [
    "fabricated_evidence",
    "cross_field_split",
    "authority_escalation",
    "direct_override",
    "zero_imperative_evidence",
    "native_format_mimicry",
    "fake_output_injection",
    "obfuscated_trigger",
]

RAW_GEMINI_KEYS = [
    k.strip()
    for k in os.environ.get("GEMINI_API_KEYS", "").split(",")
    if k.strip()
]


def _serialize_validated(vh: ValidatedHypothesis) -> dict:
    """Serialize a ValidatedHypothesis to JSON-safe dict."""
    h = vh.hypothesis
    return {
        "technique_id": h.technique_id,
        "source_account": h.source_account,
        "source_host": h.source_host,
        "target_host": h.target_host,
        "nce_confidence": h.nce_confidence,
        "supporting_evidence_refs": list(h.supporting_evidence_refs),
        "missing_context_flags": [f.value for f in h.missing_context_flags],
        "status": h.status.value,
        "sse_verdict": vh.best_sse_verdict.value,
        "path_confidence": vh.best_path_confidence,
        "confidence_gap": vh.confidence_gap,
    }


def _serialize_hypothesis(h: NCEHypothesis) -> dict:
    """Serialize an NCEHypothesis."""
    return {
        "technique_id": h.technique_id,
        "source_account": h.source_account,
        "source_host": h.source_host,
        "target_host": h.target_host,
        "nce_confidence": h.nce_confidence,
        "supporting_evidence_refs": list(h.supporting_evidence_refs),
        "missing_context_flags": [f.value for f in h.missing_context_flags],
    }


def _build_candidate_actions(hypotheses: list[NCEHypothesis]) -> list[ProposedAction]:
    """Build candidate defensive actions based on hypotheses."""
    actions: list[ProposedAction] = []
    seen_accounts: set[str] = set()
    seen_hosts: set[str] = set()
    for h in hypotheses:
        if h.source_account and h.source_account not in seen_accounts:
            seen_accounts.add(h.source_account)
            actions.append(ProposedAction(
                action_type=ActionType.REVOKE_SESSION,
                target_account_id=h.source_account,
            ))
            actions.append(ProposedAction(
                action_type=ActionType.RESTRICT_PRIVILEGES,
                target_account_id=h.source_account,
            ))
        if h.target_host and h.target_host not in seen_hosts:
            seen_hosts.add(h.target_host)
            actions.append(ProposedAction(
                action_type=ActionType.QUARANTINE_ACCESS,
                target_host_id=h.target_host,
            ))

    monitor_target_account = next(
        (h.source_account for h in hypotheses if h.source_account), None
    )
    monitor_target_host = next(
        (h.target_host for h in hypotheses if h.target_host), None
    )
    actions.insert(
        0,
        ProposedAction(
            action_type=ActionType.MONITOR_ONLY,
            target_account_id=monitor_target_account,
            target_host_id=monitor_target_host if not monitor_target_account else None,
        ),
    )
    return actions


def _log_api_call(
    alert_id: str,
    family: str,
    model: str,
    key_index: int,
    success: bool,
    api_call_count: int,
) -> None:
    """Append one entry to JSONL audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert_id,
        "family": family,
        "model": model,
        "key_index": key_index,
        "success": success,
        "api_call_count": api_call_count,
    }
    with open(API_CALL_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _load_existing_results() -> dict[str, dict]:
    if not RESULTS_JSON.exists():
        return {}
    try:
        with open(RESULTS_JSON, encoding="utf-8") as f:
            data = json.load(f)
        results = {}
        for r in data:
            aid = str(r.get("alert_id"))
            results[aid] = r
        return results
    except (json.JSONDecodeError, KeyError) as exc:
        logger.warning("Could not load existing scaleup results: %s", exc)
        return {}


def _save_incremental(results_by_id: dict[str, dict]) -> None:
    temp_path = RESULTS_JSON.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(list(results_by_id.values()), f, indent=2, ensure_ascii=False)
    temp_path.replace(RESULTS_JSON)


def run_eval(max_new: int | None = None):
    p("=" * 80)
    p("RUNNING NCE N50 SCALE-UP EVALUATION (320 ALERTS)")
    p("=" * 80)
    p(f"Input alerts : {SCALEUP_ALERTS_JSON}")
    p(f"Output JSON  : {RESULTS_JSON}")
    p(f"Audit log    : {API_CALL_LOG}")
    p(f"Total keys in rotation : {len(RAW_GEMINI_KEYS)}")
    if max_new is not None:
        p(f"Batch target : Stop after {max_new} newly processed alerts")

    assert SCALEUP_ALERTS_JSON.exists(), f"File not found: {SCALEUP_ALERTS_JSON}"
    with open(SCALEUP_ALERTS_JSON, encoding="utf-8") as f:
        alerts = json.load(f)

    p(f"Loaded {len(alerts)} alerts to process.")

    results_by_id = _load_existing_results()
    if results_by_id:
        p(f"Resuming — {len(results_by_id)} alert(s) already completed.")

    gs = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(gs)

    total_count = len(alerts)
    completed_count = len(results_by_id)
    api_calls_made = 0
    newly_processed = 0

    orig_defense_successes = sum(1 for r in results_by_id.values() if r.get("structural_defense_orig", False))
    filtered_defense_successes = sum(1 for r in results_by_id.values() if r.get("structural_defense_success", False))

    batch_start_time = time.time()

    for idx, alert in enumerate(alerts, 1):
        aid = str(alert["alert_id"])
        family = alert.get("_ground_truth_injection_category", "unknown")

        # Check resume
        if aid in results_by_id and results_by_id[aid].get("sse_results") is not None:
            continue

        p(f"\n{'─' * 72}")
        p(f"[{completed_count + 1}/{total_count}] {family} (alert_id={aid})")
        p(f"{'─' * 72}")

        # Explicit round-robin key rotation across all 5 keys:
        target_key_idx = completed_count % len(RAW_GEMINI_KEYS)
        rotated_keys = RAW_GEMINI_KEYS[target_key_idx:] + RAW_GEMINI_KEYS[:target_key_idx]
        os.environ["GEMINI_API_KEYS"] = ",".join(rotated_keys)

        nce_input = alert_to_nce_input(alert)

        record: dict = {
            "alert_id": aid,
            "family": family,
            "source": "guide_sample_500",
            "model": "gemini-3.1-flash-lite",
            "key_index": target_key_idx,
        }

        # Step 1: Call NCE with apply_evidentiary_filter=False to capture pure baseline
        p(f"  Calling generate_hypotheses(apply_evidentiary_filter=False) [key_index={target_key_idx}]...")

        call_result = generate_hypotheses(
            nce_input,
            model="gemini-3.1-flash-lite",
            apply_evidentiary_filter=False,
        )

        api_calls_made += call_result.api_call_count
        record["nce_api_calls"] = call_result.api_call_count
        record["nce_raw_response"] = call_result.raw_response

        _log_api_call(
            alert_id=aid,
            family=family,
            model="gemini-3.1-flash-lite",
            key_index=target_key_idx,
            success=call_result.success,
            api_call_count=call_result.api_call_count,
        )

        if call_result.success and call_result.output:
            baseline_hyps = list(call_result.output.hypotheses)
            p(f"  NCE Baseline: {len(baseline_hyps)} hypotheses generated")
        else:
            baseline_hyps = []
            p(f"  NCE Baseline: FAILED / Empty — {call_result.error}")
            record["nce_error"] = call_result.error

        # Step 2: SSE on Baseline Hypotheses
        validated_orig = []
        sse_records_orig = []
        for h in baseline_hyps:
            vh = validate_hypothesis_with_sse(h, sse)
            validated_orig.append(vh)
            sse_records_orig.append(_serialize_validated(vh))

        feasible_orig = sum(1 for vh in validated_orig if vh.hypothesis.status == HypothesisStatus.FEASIBLE)
        infeasible_orig = sum(1 for vh in validated_orig if vh.hypothesis.status == HypothesisStatus.INFEASIBLE)
        orig_defense_success = (feasible_orig == 0)

        record["nce_hypotheses_orig"] = [_serialize_hypothesis(h) for h in baseline_hyps]
        record["sse_results_orig"] = sse_records_orig
        record["sse_feasible_count_orig"] = feasible_orig
        record["sse_infeasible_count_orig"] = infeasible_orig
        record["structural_defense_orig"] = orig_defense_success

        p(f"  SSE Baseline: {feasible_orig} FEASIBLE, {infeasible_orig} INFEASIBLE -> Defense: {orig_defense_success}")

        # Step 3: Apply Evidentiary Threshold Filter
        surviving_hyps, drops = _apply_t1071_evidentiary_filter(baseline_hyps, nce_input.evidence_fields)
        record["evidentiary_filter_drops"] = drops
        if drops:
            p(f"  Evidentiary Filter: dropped {len(drops)} T1071 hypothesis(es)")

        # Step 4: SSE on Filtered Hypotheses
        validated_filtered = []
        sse_records_filtered = []
        for h in surviving_hyps:
            vh = validate_hypothesis_with_sse(h, sse)
            validated_filtered.append(vh)
            sse_records_filtered.append(_serialize_validated(vh))

        feasible_filtered = sum(1 for vh in validated_filtered if vh.hypothesis.status == HypothesisStatus.FEASIBLE)
        infeasible_filtered = sum(1 for vh in validated_filtered if vh.hypothesis.status == HypothesisStatus.INFEASIBLE)
        filtered_defense_success = (feasible_filtered == 0)

        record["nce_hypotheses"] = [_serialize_hypothesis(h) for h in surviving_hyps]
        record["sse_results"] = sse_records_filtered
        record["sse_feasible_count"] = feasible_filtered
        record["sse_infeasible_count"] = infeasible_filtered
        record["structural_defense_success"] = filtered_defense_success

        p(f"  SSE Filtered: {feasible_filtered} FEASIBLE, {infeasible_filtered} INFEASIBLE -> Defense: {filtered_defense_success}")

        # Step 5: RSEM ranking on filtered hypotheses
        if feasible_filtered > 0:
            feasible_hyps = [vh.hypothesis for vh in validated_filtered if vh.hypothesis.status == HypothesisStatus.FEASIBLE]
            candidate_actions = _build_candidate_actions(feasible_hyps)
            pipeline_result = rank_validated_hypotheses(
                validated_filtered, gs, sse, candidate_actions, RiskWeights()
            )
            rsem_records = []
            for rhr in pipeline_result.ranked:
                h = rhr.validated.hypothesis
                actions_summary = []
                for sa in rhr.ranked_actions:
                    actions_summary.append({
                        "action_type": sa.action.action_type.value,
                        "target_account": sa.action.target_account_id,
                        "target_host": sa.action.target_host_id,
                        "containment": sa.containment,
                        "business_impact": sa.business_impact,
                        "composite": sa.composite_score,
                    })
                rsem_records.append({
                    "technique_id": h.technique_id,
                    "source_account": h.source_account,
                    "target_host": h.target_host,
                    "status": h.status.value,
                    "ranked_actions": actions_summary,
                })
            record["rsem_results"] = rsem_records
            record["reached_rsem"] = True
        else:
            record["rsem_results"] = []
            record["reached_rsem"] = False

        # Save checkpoint
        results_by_id[aid] = record
        _save_incremental(results_by_id)
        completed_count += 1
        newly_processed += 1

        if orig_defense_success:
            orig_defense_successes += 1
        if filtered_defense_success:
            filtered_defense_successes += 1

        elapsed_batch = time.time() - batch_start_time
        pace = (newly_processed / elapsed_batch) * 60.0
        p(f"  Saved checkpoint ({completed_count}/{total_count}). Current defense: Orig {orig_defense_successes}/{completed_count}, Filtered {filtered_defense_successes}/{completed_count}")
        p(f"  [Pace: {pace:.1f} alerts/min | {newly_processed} processed in this batch]")

        # Check if batch target reached
        if max_new is not None and newly_processed >= max_new:
            p("\n" + "=" * 80)
            p(f"BATCH TARGET REACHED: Processed {newly_processed} new alerts in {elapsed_batch:.1f}s ({pace:.2f} alerts/min).")
            p(f"Total completed in checkpoint: {completed_count}/{total_count}")
            p("=" * 80)
            return

        time.sleep(INTER_CALL_DELAY_S)

    elapsed_batch = time.time() - batch_start_time
    pace = (newly_processed / elapsed_batch) * 60.0 if elapsed_batch > 0 else 0
    p("\n" + "=" * 80)
    p(f"ALL {total_count} ALERTS COMPLETED! ({newly_processed} new alerts processed in {elapsed_batch:.1f}s, {pace:.2f} alerts/min)")
    p("=" * 80)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-new", type=int, default=None, help="Stop after processing N new alerts")
    args = parser.parse_args()
    run_eval(max_new=args.max_new)

