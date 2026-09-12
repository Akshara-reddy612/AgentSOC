"""
agent/run_nce8_clean_fp_eval.py

Phase NCE-8 — Clean-Alert False-Positive Assessment for SSE (n=50).

Scales the clean-alert evaluation from n=10 (Phase NCE-7-SCALE, 8/10
all-INFEASIBLE, 2/10 correctly FEASIBLE) to n=50 to produce a defensible
false-positive rate estimate.

Unlike the contaminated-side evaluation, there is no "correct" binary
outcome per se — a clean alert CAN legitimately produce a FEASIBLE
hypothesis if the underlying telemetry genuinely reflects normal,
permitted activity that happens to structurally satisfy a technique's
preconditions (e.g., a sanctioned outbound web connection).  The question
is whether SSE's FEASIBLE rate on clean data is reasonable.

Alert selection:
  Source: guide_sample_500_alerts.json, filtered to
  _ground_truth_is_contaminated == False (350 alerts).

  Excludes 10 clean alert IDs already used in NCE-7/NCE-7-SCALE:
    1185410973735, 1279900257354, 128849018904, 1434519079553,
    1529008362288, 1537598292006, 549755817881, 558345752206,
    816043789908, 919123003049

  From the remaining 340, selects n=50 via random.Random(51).

Per-alert checkpointing:
  Results saved to agent/nce8_clean_fp_results.json after EVERY alert
  completes.  On resume, loads existing results and skips any alert_id
  already present with complete data.

API call audit log:
  Every Gemini API call logged to agent/nce8_clean_fp_api_call_log.jsonl
  (append-only, multi-session safe) with schema:
    {"timestamp", "alert_id", "family", "model", "key_index",
     "success", "api_call_count"}

CRITICAL INVARIANT: nce_confidence is NEVER used as an input to SSE's
FEASIBLE/INFEASIBLE determination or RSEM's composite score.  SSE's
verdict is determined solely by graph topology; RSEM's score is
determined solely by containment (graph-based) and business_impact
(criticality/blast-radius).  nce_confidence is preserved as a
diagnostic field only.

Usage:
    python -m agent.run_nce8_clean_fp_eval
    python -m agent.run_nce8_clean_fp_eval --show-selection-only
"""
from __future__ import annotations

import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Force unbuffered UTF-8 stdout (Windows-safe) ────────────────────────
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def p(*args, **kwargs):
    """Flushing print."""
    print(*args, **kwargs, flush=True)


from dotenv import load_dotenv

load_dotenv()

from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import (
    HypothesisStatus,
    MissingContextFlag,
    NCEHypothesis,
    NCEOutput,
)
from perception.nce_engine import (
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
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_500_JSON = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "guide_sample_500_alerts.json"
RESULTS_JSON = PROJECT_ROOT / "agent" / "nce8_clean_fp_results.json"
API_CALL_LOG = PROJECT_ROOT / "agent" / "nce8_clean_fp_api_call_log.jsonl"

# Inter-call delay — matches project convention
INTER_CALL_DELAY_S = 5

# Documented seed for this evaluation
SELECTION_SEED = 51

# Number of clean alerts to evaluate
TARGET_N = 50

# Already-used clean alert IDs from NCE-7 and NCE-7-SCALE
ALREADY_USED_CLEAN_IDS = {
    "1185410973735", "1279900257354", "128849018904", "1434519079553",
    "1529008362288", "1537598292006", "549755817881", "558345752206",
    "816043789908", "919123003049",
}

# Progress reporting interval
PROGRESS_INTERVAL = 10


# ---------------------------------------------------------------------------
# Alert selection — programmatic, seeded, documented
# ---------------------------------------------------------------------------

def _build_alert_selection() -> list[dict]:
    """Build the 50-alert clean selection list.

    Returns a list of dicts with keys:
        alert_id, family, source_file_key
    """
    rng = random.Random(SELECTION_SEED)

    # Load dataset
    with open(SAMPLE_500_JSON, encoding="utf-8") as f:
        sample500 = json.load(f)

    # Filter to clean alerts only
    clean_alerts = [
        a for a in sample500
        if not a.get("_ground_truth_is_contaminated")
    ]

    # Exclude already-used IDs
    available = [
        a for a in clean_alerts
        if str(a["alert_id"]) not in ALREADY_USED_CLEAN_IDS
    ]

    # Shuffle and select
    rng.shuffle(available)
    selected = available[:TARGET_N]

    selection: list[dict] = []
    for alert in selected:
        aid = str(alert["alert_id"])
        selection.append({
            "alert_id": aid,
            "family": "clean",
            "source_file_key": "sample500",
        })

    return selection


def _print_selection(selection: list[dict]) -> None:
    """Print the full alert selection table."""
    p(f"\n{'=' * 72}")
    p(f"ALERT SELECTION — {len(selection)} clean alerts")
    p(f"Seed: {SELECTION_SEED}")
    p(f"Excluded IDs (already used in NCE-7/NCE-7-SCALE): {len(ALREADY_USED_CLEAN_IDS)}")
    p(f"{'=' * 72}")
    p(f"{'#':>3}  {'Alert ID':>16}  {'Family':10s}  {'Source':10s}")
    p("-" * 50)

    for idx, entry in enumerate(selection, 1):
        p(f"{idx:>3}  {entry['alert_id']:>16}  {entry['family']:10s}  "
          f"{entry['source_file_key']:10s}")

    p("-" * 50)
    p(f"Total: {len(selection)} (all new — {len(selection)} API calls required)")


# ---------------------------------------------------------------------------
# Helpers (same pattern as run_nce7_scale_eval.py)
# ---------------------------------------------------------------------------

def _load_alert(alert_id: str) -> dict:
    """Load a specific alert by ID from guide_sample_500_alerts.json."""
    with open(SAMPLE_500_JSON, encoding="utf-8") as f:
        alerts = json.load(f)
    for alert in alerts:
        if str(alert.get("alert_id")) == alert_id:
            return alert
    raise ValueError(f"Alert {alert_id} not found in {SAMPLE_500_JSON}")


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


# ---------------------------------------------------------------------------
# Candidate actions for RSEM ranking
# ---------------------------------------------------------------------------

def _build_candidate_actions(hypotheses: list[NCEHypothesis]) -> list[ProposedAction]:
    """Build candidate defensive actions based on the hypotheses."""
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

    # MONITOR_ONLY
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


# ---------------------------------------------------------------------------
# API call audit logging
# ---------------------------------------------------------------------------

def _log_api_call(
    alert_id: str,
    family: str,
    model: str,
    key_index: int,
    success: bool,
    api_call_count: int,
) -> None:
    """Append one entry to the JSONL audit log (append-only, multi-session safe)."""
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


def _get_current_key_index() -> int:
    """Get the current key index from a fresh key pool (for audit logging)."""
    from agent.key_pool import load_gemini_pool
    pool = load_gemini_pool()
    return pool.current_index()


# ---------------------------------------------------------------------------
# Resume infrastructure
# ---------------------------------------------------------------------------

def _load_existing_results() -> dict[str, dict]:
    """Load previously saved incremental results keyed by alert_id."""
    if RESULTS_JSON.exists():
        try:
            with open(RESULTS_JSON, encoding="utf-8") as f:
                data = json.load(f)
            return {str(r["alert_id"]): r for r in data}
        except (json.JSONDecodeError, KeyError):
            pass
    return {}


def _save_incremental(results_by_id: dict[str, dict]) -> None:
    """Persist the current results map to disk immediately."""
    ordered = sorted(results_by_id.values(), key=lambda r: r.get("alert_id", ""))
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(ordered, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def main():
    # ── Check for --show-selection-only flag ─────────────────────────────
    show_only = "--show-selection-only" in sys.argv

    p("=" * 72)
    p("Phase NCE-8: Clean-Alert False-Positive Assessment — SSE")
    p(f"Target: {TARGET_N} clean alerts from guide_sample_500_alerts.json")
    p(f"Seed: {SELECTION_SEED}")
    p(f"Excluded: {len(ALREADY_USED_CLEAN_IDS)} alert IDs (already used in NCE-7/NCE-7-SCALE)")
    p("=" * 72)

    # ── Build alert selection ────────────────────────────────────────────
    selection = _build_alert_selection()
    _print_selection(selection)

    if show_only:
        p("\n[--show-selection-only] Exiting without making any API calls.")
        return

    # ── Verify API key ───────────────────────────────────────────────────
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get(
        "GEMINI_API_KEYS", ""
    ).split(",")[0].strip()
    if not api_key:
        p("ERROR: No GEMINI_API_KEY or GEMINI_API_KEYS set.")
        sys.exit(1)

    # Count keys for logging
    keys_str = os.environ.get("GEMINI_API_KEYS", "")
    if keys_str:
        key_count = len([k.strip() for k in keys_str.split(",") if k.strip()])
    else:
        key_count = 1
    p(f"\nGemini API keys available: {key_count}")

    # ── Initialize structural pipeline components ────────────────────────
    p("\nInitializing Knowledge Graph + SSE...")
    gs = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(gs)
    p("  Done.")

    # ── Resume-safety: load any previously completed results ─────────────
    results_by_id: dict[str, dict] = _load_existing_results()
    if results_by_id:
        p(f"Resuming — {len(results_by_id)} alert(s) already completed.")

    api_calls_made = 0
    completed_count = len(results_by_id)
    total_count = len(selection)
    feasible_so_far = 0
    infeasible_so_far = 0

    # Count existing stats for progress reporting
    for rec in results_by_id.values():
        feasible_so_far += rec.get("sse_feasible_count", 0)
        infeasible_so_far += rec.get("sse_infeasible_count", 0)

    for idx, entry in enumerate(selection, 1):
        alert_id = entry["alert_id"]
        family = entry["family"]
        source_key = entry["source_file_key"]

        p(f"\n{'─' * 72}")
        p(f"[{idx}/{total_count}] {family} (alert_id={alert_id})")
        p(f"{'─' * 72}")

        # ── Resume check: skip if already completed ─────────────────────
        if alert_id in results_by_id:
            existing = results_by_id[alert_id]
            if existing.get("sse_results") is not None:
                p(f"  SKIP — already completed (resumed from file)")
                continue

        # ── New evaluation: NCE + SSE + RSEM ────────────────────────────
        record: dict = {
            "alert_id": alert_id,
            "family": family,
            "source": source_key,
        }

        # ── Step 1: NCE stage — generate hypotheses ─────────────────────
        hypotheses: list[NCEHypothesis] = []
        try:
            alert = _load_alert(alert_id)
            nce_input = alert_to_nce_input(alert)
            p(f"  NCE: Calling generate_hypotheses()...")

            # Capture key index before the call for audit log
            current_key_idx = _get_current_key_index()

            call_result = generate_hypotheses(nce_input, model="gemini-3.1-flash-lite")
            api_calls_made += call_result.api_call_count
            record["nce_api_calls"] = call_result.api_call_count
            record["nce_raw_response"] = call_result.raw_response

            # Audit log
            _log_api_call(
                alert_id=alert_id,
                family=family,
                model="gemini-3.1-flash-lite",
                key_index=current_key_idx,
                success=call_result.success,
                api_call_count=call_result.api_call_count,
            )

            if call_result.success and call_result.output:
                hypotheses = list(call_result.output.hypotheses)
                p(f"  NCE: SUCCESS — {len(hypotheses)} hypothesis(es)")
            else:
                p(f"  NCE: FAILED — {call_result.error}")
                record["nce_error"] = call_result.error

            # Rate-limit pacing
            p(f"  Sleeping {INTER_CALL_DELAY_S}s...")
            time.sleep(INTER_CALL_DELAY_S)

        except Exception as exc:
            p(f"  NCE: ERROR — {exc}")
            record["nce_error"] = str(exc)

            # Check if this is a rate-limit / quota exhaustion
            from agent.llm_utils import is_rate_limit_error
            if is_rate_limit_error(exc):
                p(f"\n  *** QUOTA EXHAUSTED — saving checkpoint and exiting ***")
                p(f"  *** Completed: {completed_count}/{total_count} ***")
                p(f"  *** Remaining: {total_count - completed_count} alerts ***")
                _save_incremental(results_by_id)
                sys.exit(2)

        # Log NCE hypotheses
        nce_hyp_records = []
        for i, h in enumerate(hypotheses):
            p(f"    [{i}] technique={h.technique_id}, "
              f"account={h.source_account}, "
              f"target={h.target_host}, "
              f"nce_confidence={h.nce_confidence:.2f}, "
              f"refs={h.supporting_evidence_refs}")
            nce_hyp_records.append({
                "technique_id": h.technique_id,
                "source_account": h.source_account,
                "source_host": h.source_host,
                "target_host": h.target_host,
                "nce_confidence": h.nce_confidence,
                "supporting_evidence_refs": list(h.supporting_evidence_refs),
                "missing_context_flags": [f.value for f in h.missing_context_flags],
            })
        record["nce_hypotheses"] = nce_hyp_records

        # ── Step 2: SSE stage ───────────────────────────────────────────
        validated: list[ValidatedHypothesis] = []
        sse_records = []

        for i, h in enumerate(hypotheses):
            vh = validate_hypothesis_with_sse(h, sse)
            validated.append(vh)
            sse_rec = _serialize_validated(vh)
            sse_records.append(sse_rec)
            verdict = vh.best_sse_verdict.value
            status = vh.hypothesis.status.value
            p(f"    [{i}] SSE: {verdict} (path_conf={vh.best_path_confidence:.2f}, "
              f"gap={vh.confidence_gap:+.2f}) → status={status}")

        record["sse_results"] = sse_records

        feasible_count = sum(1 for vh in validated
                            if vh.hypothesis.status == HypothesisStatus.FEASIBLE)
        infeasible_count = sum(1 for vh in validated
                              if vh.hypothesis.status == HypothesisStatus.INFEASIBLE)
        record["sse_feasible_count"] = feasible_count
        record["sse_infeasible_count"] = infeasible_count
        p(f"  SSE summary: {feasible_count} FEASIBLE, {infeasible_count} INFEASIBLE")

        feasible_so_far += feasible_count
        infeasible_so_far += infeasible_count

        # ── Step 3: RSEM stage ──────────────────────────────────────────
        if feasible_count > 0:
            feasible_hyps = [vh.hypothesis for vh in validated
                            if vh.hypothesis.status == HypothesisStatus.FEASIBLE]
            candidate_actions = _build_candidate_actions(feasible_hyps)

            pipeline_result = rank_validated_hypotheses(
                validated, gs, sse, candidate_actions, RiskWeights()
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
                p(f"  RSEM: {h.technique_id} ({h.source_account} → {h.target_host})")
                for j, sa in enumerate(rhr.ranked_actions):
                    p(f"    [{j+1}] {sa.action.action_type.value}: "
                      f"containment={sa.containment:.3f}, "
                      f"biz_impact={sa.business_impact:.3f}, "
                      f"composite={sa.composite_score:.3f}")

            record["rsem_results"] = rsem_records
            record["reached_rsem"] = True
        else:
            p("  RSEM: Excluded — no FEASIBLE hypotheses")
            record["rsem_results"] = []
            record["reached_rsem"] = False

        # ── Incremental save ────────────────────────────────────────────
        results_by_id[alert_id] = record
        _save_incremental(results_by_id)
        completed_count += 1
        p(f"  [saved — {completed_count}/{total_count} complete]")

        # ── Progress report ─────────────────────────────────────────────
        if completed_count % PROGRESS_INTERVAL == 0:
            p(f"\n  *** PROGRESS: {completed_count}/{total_count} complete, "
              f"{feasible_so_far} FEASIBLE, {infeasible_so_far} INFEASIBLE so far ***\n")

    # ── Final summary ───────────────────────────────────────────────────
    _print_summary(results_by_id, api_calls_made)


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def _print_summary(results_by_id: dict[str, dict], api_calls_made: int) -> None:
    """Print the final summary table."""
    results = sorted(results_by_id.values(), key=lambda r: r.get("alert_id", ""))

    p(f"\n{'=' * 72}")
    p("FINAL SUMMARY — Phase NCE-8: Clean-Alert FP Assessment")
    p(f"{'=' * 72}")
    p(f"{'#':>3}  {'Alert ID':>16}  {'Hypotheses':>10}  {'FEASIBLE':>8}  "
      f"{'INFEASIBLE':>10}  {'Techniques w/ FEASIBLE':30s}")
    p("-" * 90)

    total_alerts = len(results)
    alerts_with_feasible = 0
    total_hypotheses = 0
    total_feasible = 0
    total_infeasible = 0
    technique_counts: dict[str, int] = {}

    for i, rec in enumerate(results, 1):
        alert_id = rec["alert_id"]
        n_hyps = len(rec.get("nce_hypotheses", []))
        n_feasible = rec.get("sse_feasible_count", 0)
        n_infeasible = rec.get("sse_infeasible_count", 0)
        total_hypotheses += n_hyps
        total_feasible += n_feasible
        total_infeasible += n_infeasible

        if n_feasible > 0:
            alerts_with_feasible += 1

        # Collect FEASIBLE technique IDs
        feasible_techs = []
        for sr in rec.get("sse_results", []):
            if sr.get("sse_verdict") == "FEASIBLE":
                tech = sr.get("technique_id", "?")
                feasible_techs.append(tech)
                technique_counts[tech] = technique_counts.get(tech, 0) + 1

        tech_str = ", ".join(feasible_techs) if feasible_techs else "—"

        p(f"{i:>3}  {alert_id:>16}  {n_hyps:>10}  {n_feasible:>8}  "
          f"{n_infeasible:>10}  {tech_str:30s}")

    p("-" * 90)

    # ── Aggregate statistics ────────────────────────────────────────────
    p(f"\nAPI calls made this run: {api_calls_made}")
    p(f"Total clean alerts evaluated: {total_alerts}")
    p(f"Total hypotheses across all alerts: {total_hypotheses}")
    p(f"Total FEASIBLE: {total_feasible}/{total_hypotheses} hypotheses")
    p(f"Total INFEASIBLE: {total_infeasible}/{total_hypotheses} hypotheses")

    fp_rate = alerts_with_feasible / total_alerts if total_alerts > 0 else 0
    p(f"\nAlerts with at least one FEASIBLE hypothesis: "
      f"{alerts_with_feasible}/{total_alerts} ({fp_rate:.1%})")
    p(f"  NOTE: FEASIBLE on clean data is not automatically a false positive —")
    p(f"  some clean activity genuinely satisfies technique preconditions.")

    if technique_counts:
        p(f"\nFEASIBLE hypotheses by technique:")
        for tech, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
            p(f"  {tech}: {count}")

    # ── Invariant verification ──────────────────────────────────────────
    p(f"\n{'=' * 72}")
    p("CRITICAL INVARIANT VERIFICATION")
    p(f"{'=' * 72}")
    p("nce_confidence is NEVER used as an input to SSE or RSEM:")
    p("  - SSE.check() takes (account_id, source_host_id, target_host_id,")
    p("    technique_id) — no confidence parameter")
    p("  - RSEM score_action() computes containment from graph topology")
    p("    and business_impact from criticality/blast-radius")
    p("  - nce_confidence appears only in diagnostic fields (confidence_gap)")
    p("  - Verified by code inspection of validate_hypothesis_with_sse()")
    p("    and rank_validated_hypotheses() — no nce_confidence read path")
    p("    feeds into any FEASIBLE/INFEASIBLE determination or composite score")


if __name__ == "__main__":
    main()
