"""
streamlit_app.py — AgentSOC 2.0 Review Demo

Multi-stage visual walkthrough of the Perception → NCE → SSE → RSEM →
Action/Playbook pipeline, replaying real pre-computed results from
completed evaluations (NCE-7-SCALE, NCE-7 Comparative, NCE-8 Clean FP).

DESIGN CONSTRAINT: The default demo path makes ZERO live API calls.
All 7 curated scenarios replay from existing JSON files or run
deterministic graph computations.  A secondary "Live Mode" toggle
(off by default) allows optional live Gemini calls during rehearsal.

Run:  streamlit run streamlit_app.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# =========================================================================
# PROJECT ROOT — all file paths relative to this
# =========================================================================

PROJECT_ROOT = Path(__file__).resolve().parent


# =========================================================================
# SCENARIO REGISTRY — 7 curated demo scenarios
# =========================================================================

SCENARIOS: dict[str, dict[str, Any]] = {
    "1_defended_attack": {
        "label": "1 │ Defended Contaminated Attack (Core Thesis)",
        "source_file": "nce7_comparative_results",
        "alert_id": "1073741825161",
        "slot": 1,
        "description": (
            "An attacker injected fabricated evidence into the alert's free-text "
            "fields, causing the LLM (NCE) to generate a verdict-flip hijack.  "
            "The Structural Simulation Engine (SSE) independently checked the "
            "knowledge graph and found NO valid attack path — all hypotheses "
            "INFEASIBLE.  **The LLM was fooled; the graph was not.**"
        ),
    },
    "2_t1071_limitation": {
        "label": "2 │ T1071 Structural Limitation (Defense Fails)",
        "source_file": "nce7_comparative_results",
        "alert_id": "146028890043",
        "slot": 8,
        "description": (
            "A contaminated alert with T1071 (Command & Control) injection.  "
            "SSE returns FEASIBLE because T1071's constraint checks only "
            "zone-egress topology — any outbound connection from a workstation "
            "zone is structurally valid.  This is the documented architectural "
            "limitation: structural defense cannot distinguish real vs. "
            "fabricated T1071/C2 narratives."
        ),
    },
    "3_clean_correct": {
        "label": "3 │ Clean Alert, Correctly Handled (No FP)",
        "source_file": "nce8_clean_fp_results",
        "alert_id": "1073741824021",
        "description": (
            "A genuinely clean (non-contaminated) alert from the sample-500 pool.  "
            "NCE generates hypotheses (T1562, T1484, T1078), but SSE finds ALL "
            "are structurally INFEASIBLE.  RSEM is never reached.  "
            "No false positive — the pipeline correctly ignores this benign alert."
        ),
    },
    "4_t1071_guardrail_silence": {
        "label": "4 │ Clean T1071 → Guardrail-Silence Finding",
        "source_file": "nce8_clean_fp_results",
        "alert_id": "1125281436175",
        "description": (
            "A clean alert with a T1071 hypothesis that SSE marks FEASIBLE "
            "(same structural limitation as Scenario 2).  RSEM ranks "
            "MONITOR_ONLY as the top action (containment=0.0, BI=0.0).  "
            "The playbook is AUTO_APPROVED with zero guardrail friction — "
            "illustrating the T1071 Guardrail-Silence finding: neither the "
            "hard-floor nor the BI-threshold rule fires on any real T1071 case."
        ),
    },
    "5_hard_floor": {
        "label": "5 │ Guardrail Hard-Floor (REVOKE_SESSION → Review)",
        "source_file": "guardrail_constructed",
        "scenario_key": "hard_floor",
        "description": (
            "Hand-constructed scenario: an aggressive SOC response offering "
            "only disruptive actions.  REVOKE_SESSION ranks #1 (containment=0.5, "
            "BI=0.0).  The hard-floor guardrail fires because REVOKE_SESSION is "
            "in the mandatory-review set → PENDING_ANALYST_REVIEW.  "
            "Dry-run execution is REFUSED."
        ),
    },
    "6_threshold": {
        "label": "6 │ Guardrail BI Threshold (BI=0.75 → Review)",
        "source_file": "guardrail_constructed",
        "scenario_key": "threshold",
        "description": (
            "Hand-constructed scenario: host-targeted RESTRICT_PRIVILEGES on "
            "server-db01 (tier-2, BI=0.75).  The business-impact threshold "
            "rule fires (0.75 > 0.35) → PENDING_ANALYST_REVIEW.  "
            "Dry-run execution is REFUSED."
        ),
    },
    "7_auto_approve": {
        "label": "7 │ Guardrail Auto-Approve + Real Containment",
        "source_file": "guardrail_constructed",
        "scenario_key": "auto_approve",
        "description": (
            "Hand-constructed scenario: the original svc_backup/server-db01 "
            "T1550 demo case with account-targeted actions.  RESTRICT_PRIVILEGES "
            "ranks #1 (BI=0.0, below threshold).  AUTO_APPROVED → dry-run "
            "executes with real before/after edge diff and rollback instructions."
        ),
    },
}


# =========================================================================
# DATA LAYER — no Streamlit imports, fully testable independently
# =========================================================================

def _load_json_file(filename: str) -> list[dict]:
    """Load a JSON results file from the agent/ directory."""
    path = PROJECT_ROOT / "agent" / f"{filename}.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_raw_alert(alert_id: str) -> dict | None:
    """Look up a raw alert from the GUIDE dataset files."""
    for fname in [
        "GUIDE_Dataset/processed/guide_heldout_140_alerts.json",
        "GUIDE_Dataset/processed/guide_sample_500_alerts.json",
    ]:
        path = PROJECT_ROOT / fname
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as f:
            alerts = json.load(f)
        for alert in alerts:
            if str(alert.get("alert_id")) == str(alert_id):
                return alert
    return None


def _find_record(data: list[dict], alert_id: str) -> dict | None:
    """Find a record by alert_id in a results list."""
    for record in data:
        if str(record.get("alert_id")) == str(alert_id):
            return record
    return None


def _compute_playbook_for_feasible(
    rsem_record: dict,
    feasible_hyp: dict,
    feasible_sse: dict,
) -> dict:
    """
    Reconstruct pipeline objects from JSON and run the playbook layer.

    Used for scenarios 2 and 4 where RSEM data exists in JSON but
    the playbook/guardrail/execution layer needs to be computed.

    Returns a dict with playbook steps, guardrail decision, and
    dry-run report (or refusal).
    """
    from perception.action_playbook import (
        build_playbook,
        evaluate_guardrails,
        execute_playbook_dry_run,
        Playbook,
    )
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.nce_contract import HypothesisStatus, MissingContextFlag, NCEHypothesis
    from perception.nce_rsem_integration import RankedHypothesisResult
    from perception.nce_sse_integration import ValidatedHypothesis
    from perception.rsem import ActionType, ProposedAction, ScoredAction
    from perception.sse import SSEVerdict

    # --- Reconstruct NCEHypothesis ---
    missing_flags = []
    for flag_str in feasible_hyp.get("missing_context_flags", []):
        try:
            missing_flags.append(MissingContextFlag(flag_str))
        except ValueError:
            pass

    hypothesis = NCEHypothesis(
        technique_id=feasible_hyp["technique_id"],
        source_account=feasible_hyp["source_account"],
        source_host=feasible_hyp["source_host"],
        target_host=feasible_hyp["target_host"],
        nce_confidence=feasible_hyp["nce_confidence"],
        supporting_evidence_refs=feasible_hyp.get("supporting_evidence_refs", []),
        missing_context_flags=missing_flags,
        status=HypothesisStatus.RSEM_RANKED,
    )

    # --- Reconstruct ValidatedHypothesis ---
    best_verdict = SSEVerdict(feasible_sse.get("sse_verdict", "FEASIBLE"))
    validated = ValidatedHypothesis(
        hypothesis=hypothesis,
        sse_results=[],
        best_sse_verdict=best_verdict,
        best_path_confidence=feasible_sse.get("path_confidence", 0.0),
        confidence_gap=feasible_sse.get("confidence_gap", 0.0),
    )

    # --- Reconstruct ScoredActions ---
    scored_actions: list[ScoredAction] = []
    for action_data in rsem_record.get("ranked_actions", []):
        target_acct = action_data.get("target_account")
        target_host = action_data.get("target_host")
        proposed = ProposedAction(
            action_type=ActionType(action_data["action_type"]),
            target_account_id=target_acct,
            target_host_id=target_host,
        )
        scored = ScoredAction(
            action=proposed,
            containment=action_data.get("containment", 0.0),
            business_impact=action_data.get("business_impact", 0.0),
            composite_score=action_data.get("composite", 0.0),
            paths_cut=0,
            paths_total_before=0,
        )
        scored_actions.append(scored)

    ranked_result = RankedHypothesisResult(
        validated=validated,
        ranked_actions=scored_actions,
    )

    # --- Run Playbook Pipeline ---
    kg = KnowledgeStoreGraph()
    playbook = build_playbook(ranked_result, kg)
    playbook = evaluate_guardrails(playbook)
    playbook = execute_playbook_dry_run(playbook, kg)

    # --- Serialize to dict ---
    steps_data = []
    for step in playbook.steps:
        target_parts = []
        if step.action.action.target_account_id:
            target_parts.append(f"account={step.action.action.target_account_id}")
        if step.action.action.target_host_id:
            target_parts.append(f"host={step.action.action.target_host_id}")

        steps_data.append({
            "step_number": step.step_number,
            "action_type": step.action.action.action_type.value,
            "is_policy_action": step.is_policy_action,
            "status": step.status.value,
            "containment": step.action.containment,
            "business_impact": step.action.business_impact,
            "composite_score": step.action.composite_score,
            "target": ", ".join(target_parts),
        })

    return {
        "steps": steps_data,
        "overall_status": playbook.overall_status.value,
        "guardrail_decision_reason": playbook.guardrail_decision_reason,
        "dry_run_report": playbook.dry_run_report,
    }


def _build_guardrail_scenario(scenario_key: str) -> dict:
    """
    Build a hand-constructed guardrail demo scenario.

    Reuses the exact same setup logic as scratch/action_playbook_demo.py:
    svc_backup T1550 hypothesis targeting server-db01, with different
    candidate action sets to trigger different guardrail rules.

    Returns the full scenario data dict.
    """
    from perception.action_playbook import (
        GUARDRAIL_BUSINESS_IMPACT_THRESHOLD,
        build_playbook,
        evaluate_guardrails,
        execute_playbook_dry_run,
    )
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.nce_contract import HypothesisStatus, NCEHypothesis
    from perception.nce_rsem_integration import RankedHypothesisResult, rank_validated_hypotheses
    from perception.nce_sse_integration import validate_hypothesis_with_sse
    from perception.rsem import ActionType, ProposedAction, StructuralSimulationEngine

    # --- Common setup ---
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)

    hypothesis = NCEHypothesis(
        technique_id="T1550",
        source_account="svc_backup",
        source_host="workstation-01",
        target_host="server-db01",
        nce_confidence=0.85,
        supporting_evidence_refs=["raw_log_line", "event_timestamp"],
        missing_context_flags=[],
        status=HypothesisStatus.GENERATED,
    )

    # SSE validation (deterministic)
    validated = validate_hypothesis_with_sse(hypothesis, sse)

    # NCE hypothesis data (for display)
    nce_hyp_data = [{
        "technique_id": "T1550",
        "source_account": "svc_backup",
        "source_host": "workstation-01",
        "target_host": "server-db01",
        "nce_confidence": 0.85,
        "supporting_evidence_refs": ["raw_log_line", "event_timestamp"],
        "missing_context_flags": [],
    }]

    # SSE result data (for display)
    sse_data = [{
        "technique_id": "T1550",
        "source_account": "svc_backup",
        "source_host": "workstation-01",
        "target_host": "server-db01",
        "nce_confidence": 0.85,
        "sse_verdict": validated.best_sse_verdict.value,
        "path_confidence": validated.best_path_confidence,
        "confidence_gap": validated.confidence_gap,
        "status": validated.hypothesis.status.value,
    }]

    # --- Scenario-specific candidate actions ---
    if scenario_key == "hard_floor":
        candidate_actions = [
            ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="svc_backup"),
            ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-db01"),
        ]
    elif scenario_key == "threshold":
        candidate_actions = [
            ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_host_id="server-db01"),
            ProposedAction(action_type=ActionType.MONITOR_ONLY, target_host_id="server-db01"),
        ]
    else:  # auto_approve
        candidate_actions = [
            ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id="svc_backup"),
            ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id="svc_backup"),
            ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id="server-db01"),
            ProposedAction(action_type=ActionType.MONITOR_ONLY, target_account_id="svc_backup"),
        ]

    # RSEM ranking
    pipeline_result = rank_validated_hypotheses(
        [validated], kg, sse, candidate_actions,
    )
    ranked = pipeline_result.ranked[0]

    # RSEM display data
    rsem_actions = []
    for sa in ranked.ranked_actions:
        target_parts = []
        if sa.action.target_account_id:
            target_parts.append(f"account={sa.action.target_account_id}")
        if sa.action.target_host_id:
            target_parts.append(f"host={sa.action.target_host_id}")
        rsem_actions.append({
            "action_type": sa.action.action_type.value,
            "containment": sa.containment,
            "business_impact": sa.business_impact,
            "composite": sa.composite_score,
            "paths_cut": sa.paths_cut,
            "paths_total_before": sa.paths_total_before,
            "target": ", ".join(target_parts),
        })

    rsem_results = [{
        "technique_id": "T1550",
        "source_account": "svc_backup",
        "target_host": "server-db01",
        "status": "RSEM_RANKED",
        "ranked_actions": rsem_actions,
    }]

    # Playbook pipeline
    playbook = build_playbook(ranked, kg)
    playbook = evaluate_guardrails(playbook)
    playbook = execute_playbook_dry_run(playbook, kg)

    steps_data = []
    for step in playbook.steps:
        target_parts = []
        if step.action.action.target_account_id:
            target_parts.append(f"account={step.action.action.target_account_id}")
        if step.action.action.target_host_id:
            target_parts.append(f"host={step.action.action.target_host_id}")
        steps_data.append({
            "step_number": step.step_number,
            "action_type": step.action.action.action_type.value,
            "is_policy_action": step.is_policy_action,
            "status": step.status.value,
            "containment": step.action.containment,
            "business_impact": step.action.business_impact,
            "composite_score": step.action.composite_score,
            "target": ", ".join(target_parts),
        })

    playbook_data = {
        "steps": steps_data,
        "overall_status": playbook.overall_status.value,
        "guardrail_decision_reason": playbook.guardrail_decision_reason,
        "dry_run_report": playbook.dry_run_report,
    }

    return {
        "name": SCENARIOS[f"{_scenario_num(scenario_key)}_" + scenario_key]["label"],
        "description": SCENARIOS[f"{_scenario_num(scenario_key)}_" + scenario_key]["description"],
        "scenario_type": "guardrail",
        "raw_alert": None,
        "is_contaminated": False,
        "injection_category": None,
        "constructed_params": {
            "hypothesis": {
                "technique_id": "T1550",
                "source_account": "svc_backup",
                "source_host": "workstation-01",
                "target_host": "server-db01",
                "nce_confidence": 0.85,
            },
            "candidate_actions": [
                {
                    "action_type": a.action_type.value,
                    "target_account_id": a.target_account_id,
                    "target_host_id": a.target_host_id,
                }
                for a in candidate_actions
            ],
            "guardrail_threshold": GUARDRAIL_BUSINESS_IMPACT_THRESHOLD,
        },
        "nce_hypotheses": nce_hyp_data,
        "sse_results": sse_data,
        "sse_feasible_count": 1 if validated.best_sse_verdict.value == "FEASIBLE" else 0,
        "sse_infeasible_count": 0 if validated.best_sse_verdict.value == "FEASIBLE" else 1,
        "rsem_results": rsem_results,
        "reached_rsem": True,
        "playbook": playbook_data,
        "hijack_data": None,
        "structural_defense_success": None,
    }


def _scenario_num(key: str) -> str:
    """Map scenario_key back to its number."""
    mapping = {"hard_floor": "5", "threshold": "6", "auto_approve": "7"}
    return mapping.get(key, "?")


def load_scenario(name: str) -> dict:
    """
    Load a curated demo scenario by registry key.

    Returns a dict with all pipeline stage data needed for rendering.
    This function has ZERO Streamlit dependencies — call it from
    scripts, tests, or the verification harness independently.

    Args:
        name: A key from SCENARIOS (e.g., "1_defended_attack").

    Returns:
        Dict with keys: name, description, scenario_type, raw_alert,
        is_contaminated, injection_category, nce_hypotheses, sse_results,
        sse_feasible_count, sse_infeasible_count, rsem_results,
        reached_rsem, playbook, hijack_data, structural_defense_success,
        plus scenario-type-specific keys.

    Raises:
        KeyError: If name is not in SCENARIOS.
        FileNotFoundError: If a required JSON file is missing.
    """
    config = SCENARIOS[name]
    source = config["source_file"]

    # -----------------------------------------------------------------
    # Guardrail hand-constructed scenarios (5, 6, 7)
    # -----------------------------------------------------------------
    if source == "guardrail_constructed":
        return _build_guardrail_scenario(config["scenario_key"])

    # -----------------------------------------------------------------
    # JSON replay scenarios (1, 2, 3, 4)
    # -----------------------------------------------------------------
    alert_id = config["alert_id"]
    data = _load_json_file(source)
    record = _find_record(data, alert_id)
    if record is None:
        raise ValueError(
            f"Alert {alert_id} not found in {source}.json"
        )

    # Raw alert from GUIDE dataset
    raw_alert = _load_raw_alert(alert_id)

    is_contaminated = False
    injection_category = None
    if raw_alert:
        is_contaminated = raw_alert.get("_ground_truth_is_contaminated", False)
        injection_category = raw_alert.get("_ground_truth_injection_category")

    # Hijack/defense metadata (NCE-7 only)
    hijack_data = record.get("undefended_hijack")
    defense_success = record.get("structural_defense_success")

    # NCE hypotheses
    nce_hypotheses = record.get("nce_hypotheses", [])

    # SSE results
    sse_results = record.get("sse_results", [])
    sse_feasible = record.get("sse_feasible_count", 0)
    sse_infeasible = record.get("sse_infeasible_count", 0)

    # RSEM results
    rsem_results = record.get("rsem_results", [])
    reached_rsem = record.get("reached_rsem", False)

    # Playbook (compute for FEASIBLE scenarios)
    playbook_data = None
    if reached_rsem and rsem_results:
        # Find the FEASIBLE hypothesis and its SSE result
        feasible_hyp = None
        feasible_sse = None
        for hyp in nce_hypotheses:
            for sse_r in sse_results:
                if (
                    sse_r.get("technique_id") == hyp.get("technique_id")
                    and sse_r.get("sse_verdict") == "FEASIBLE"
                ):
                    feasible_hyp = hyp
                    feasible_sse = sse_r
                    break
            if feasible_hyp:
                break

        if feasible_hyp and feasible_sse and rsem_results:
            playbook_data = _compute_playbook_for_feasible(
                rsem_results[0], feasible_hyp, feasible_sse,
            )

    return {
        "name": config["label"],
        "description": config["description"],
        "scenario_type": "replay",
        "raw_alert": raw_alert,
        "is_contaminated": is_contaminated,
        "injection_category": injection_category,
        "nce_hypotheses": nce_hypotheses,
        "nce_raw_response": record.get("nce_raw_response"),
        "sse_results": sse_results,
        "sse_feasible_count": sse_feasible,
        "sse_infeasible_count": sse_infeasible,
        "rsem_results": rsem_results,
        "reached_rsem": reached_rsem,
        "playbook": playbook_data,
        "hijack_data": hijack_data,
        "structural_defense_success": defense_success,
    }


# =========================================================================
# RENDERING LAYER — Streamlit UI
# =========================================================================

def _import_streamlit():
    """Lazy import of Streamlit so the data layer stays import-free."""
    import streamlit as st
    return st


def _inject_custom_css(st) -> None:
    """Inject custom CSS for visual polish."""
    st.markdown("""
    <style>
    /* --- Global --- */
    .stApp {
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }

    /* --- Header banner --- */
    .demo-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        border-radius: 12px;
        padding: 28px 32px;
        margin-bottom: 24px;
        border: 1px solid rgba(100, 100, 255, 0.15);
    }
    .demo-header h1 {
        color: #e0e0ff;
        font-size: 1.8rem;
        margin: 0 0 4px 0;
        font-weight: 700;
        letter-spacing: -0.5px;
    }
    .demo-header .subtitle {
        color: #9a9abf;
        font-size: 0.95rem;
        margin: 0;
    }

    /* --- Metric cards --- */
    .metric-row {
        display: flex;
        gap: 16px;
        margin: 16px 0 8px 0;
    }
    .metric-card {
        flex: 1;
        border-radius: 10px;
        padding: 16px 20px;
        text-align: center;
        border: 1px solid rgba(255,255,255,0.08);
    }
    .metric-card.defense {
        background: linear-gradient(135deg, rgba(0,180,80,0.12), rgba(0,120,60,0.08));
        border-color: rgba(0,180,80,0.25);
    }
    .metric-card.fp {
        background: linear-gradient(135deg, rgba(0,120,255,0.12), rgba(0,80,200,0.08));
        border-color: rgba(0,120,255,0.25);
    }
    .metric-card .metric-value {
        font-size: 1.6rem;
        font-weight: 700;
        margin: 0;
    }
    .metric-card.defense .metric-value { color: #00e676; }
    .metric-card.fp .metric-value { color: #448aff; }
    .metric-card .metric-label {
        font-size: 0.78rem;
        color: #9a9abf;
        margin: 4px 0 0 0;
        line-height: 1.3;
    }

    /* --- Pipeline stage badges --- */
    .stage-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin-right: 8px;
        vertical-align: middle;
    }
    .stage-badge.feasible {
        background: rgba(255,82,82,0.15);
        color: #ff5252;
        border: 1px solid rgba(255,82,82,0.3);
    }
    .stage-badge.infeasible {
        background: rgba(0,230,118,0.12);
        color: #00e676;
        border: 1px solid rgba(0,230,118,0.3);
    }
    .stage-badge.approved {
        background: rgba(0,230,118,0.12);
        color: #00e676;
        border: 1px solid rgba(0,230,118,0.3);
    }
    .stage-badge.pending {
        background: rgba(255,171,0,0.15);
        color: #ffab00;
        border: 1px solid rgba(255,171,0,0.3);
    }
    .stage-badge.policy {
        background: rgba(100,100,255,0.12);
        color: #7c7cff;
        border: 1px solid rgba(100,100,255,0.3);
    }
    .stage-badge.refused {
        background: rgba(255,82,82,0.15);
        color: #ff5252;
        border: 1px solid rgba(255,82,82,0.3);
    }
    .stage-badge.executed {
        background: rgba(0,230,118,0.12);
        color: #00e676;
        border: 1px solid rgba(0,230,118,0.3);
    }

    /* --- Contaminated field highlight --- */
    .contaminated-highlight {
        background: rgba(255,82,82,0.08);
        border-left: 3px solid #ff5252;
        padding: 8px 12px;
        border-radius: 0 6px 6px 0;
        margin: 4px 0;
        font-family: 'Cascadia Code', 'Fira Code', monospace;
        font-size: 0.82rem;
        word-break: break-all;
    }

    /* --- Info callout --- */
    .callout {
        border-radius: 8px;
        padding: 14px 18px;
        margin: 10px 0;
        font-size: 0.88rem;
        line-height: 1.5;
    }
    .callout.insight {
        background: rgba(100,100,255,0.08);
        border: 1px solid rgba(100,100,255,0.2);
        color: #c0c0ff;
    }
    .callout.warning {
        background: rgba(255,171,0,0.08);
        border: 1px solid rgba(255,171,0,0.2);
        color: #ffd180;
    }
    .callout.success {
        background: rgba(0,230,118,0.06);
        border: 1px solid rgba(0,230,118,0.2);
        color: #a5d6a7;
    }
    .callout.danger {
        background: rgba(255,82,82,0.06);
        border: 1px solid rgba(255,82,82,0.2);
        color: #ef9a9a;
    }

    /* --- Sidebar --- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f0c29, #1a1a3e);
    }

    /* --- Expander styling --- */
    .stExpander {
        border: 1px solid rgba(255,255,255,0.06) !important;
        border-radius: 10px !important;
        margin-bottom: 12px !important;
    }
    </style>
    """, unsafe_allow_html=True)


def render_header(st) -> None:
    """Render the project header with headline metrics."""
    st.markdown("""
    <div class="demo-header">
        <h1>🛡️ AgentSOC 2.0 — Pipeline Review Demo</h1>
        <p class="subtitle">Securing Autonomous Defense: Mitigating Log-Contamination Vulnerabilities in Agentic SOC Frameworks</p>
        <div class="metric-row">
            <div class="metric-card defense">
                <p class="metric-value">80.0%</p>
                <p class="metric-label">Structural Defense Rate<br>64/80 contaminated attacks blocked</p>
            </div>
            <div class="metric-card fp">
                <p class="metric-value">0.0%</p>
                <p class="metric-label">False Positive Rate (non-T1071)<br>0/60 clean alerts misclassified</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_raw_alert(st, data: dict) -> None:
    """Stage 1: Raw Alert as it would appear in a SIEM."""
    with st.expander("📋 Stage 1 — Raw Alert (SIEM View)", expanded=True):
        if data.get("scenario_type") == "guardrail":
            st.markdown("""
            <div class="callout insight">
                <strong>Hand-Constructed Scenario</strong> — This scenario uses
                a manually defined hypothesis and candidate action set to
                demonstrate specific guardrail behavior.  No raw SIEM alert is
                involved; the parameters below feed directly into the SSE → RSEM
                → Playbook pipeline.
            </div>
            """, unsafe_allow_html=True)

            params = data.get("constructed_params", {})
            hyp = params.get("hypothesis", {})

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Hypothesis Parameters**")
                st.json(hyp)
            with col2:
                st.markdown("**Candidate Actions**")
                st.json(params.get("candidate_actions", []))
            return

        raw = data.get("raw_alert")
        if not raw:
            st.warning("Raw alert data not available for this scenario.")
            return

        is_contaminated = data.get("is_contaminated", False)
        injection_cat = data.get("injection_category")

        if is_contaminated:
            st.markdown(f"""
            <div class="callout danger">
                <strong>⚠️ Contaminated Alert</strong> — Injection category:
                <code>{injection_cat}</code>.  The highlighted fields below
                contain attacker-injected content.
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="callout success">
                <strong>✓ Clean Alert</strong> — This is a genuine, uncontaminated
                alert from the evaluation corpus.  Ground truth:
                <code>BenignPositive</code>.
            </div>
            """, unsafe_allow_html=True)

        # Display alert fields
        display_fields = [
            ("alert_id", "Alert ID"),
            ("source_system", "Source System"),
            ("event_type", "Event Type"),
            ("timestamp", "Timestamp"),
            ("severity", "Severity"),
            ("source_user", "Source User"),
            ("source_host", "Source Host"),
            ("target_host", "Target Host"),
            ("process_name", "Process Name"),
            ("command_line", "Command Line"),
            ("registry_key", "Registry Key"),
            ("parent_process", "Parent Process"),
            ("file_path", "File Path"),
        ]

        # Free-text fields that might be contaminated
        free_text_keys = {"process_name", "command_line", "registry_key",
                          "parent_process", "file_path", "raw_log_line"}

        for key, label in display_fields:
            val = raw.get(key)
            if val is None:
                continue
            val_str = str(val)

            if is_contaminated and key in free_text_keys and len(val_str) > 30:
                st.markdown(f"**{label}:**")
                st.markdown(
                    f'<div class="contaminated-highlight">{_escape_html(val_str)}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(f"**{label}:** `{val_str}`")

        # Raw log line (always show separately, often long)
        raw_log = raw.get("raw_log_line")
        if raw_log:
            st.markdown("**Raw Log Line:**")
            if is_contaminated:
                st.markdown(
                    f'<div class="contaminated-highlight">{_escape_html(str(raw_log))}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.code(str(raw_log), language=None)


def render_nce_hypotheses(st, data: dict) -> None:
    """Stage 2: NCE Hypothesis Generation."""
    with st.expander("🧠 Stage 2 — NCE Hypothesis Generation", expanded=True):
        st.markdown("""
        <div class="callout insight">
            <strong>Knowledge Store Isolation</strong> — NCE saw ONLY the raw
            evidence fields below (process_name, command_line, raw_log_line, etc.).
            It had <strong>no access</strong> to privilege tier, asset criticality,
            network zone, or historical access — those are structurally isolated in
            the ImmutableContext, which only SSE and RSEM can read.  This isolation
            was verified by the project's FORBIDDEN_FIELD_NAMES guard and
            isinstance(Evidence) checks.
        </div>
        """, unsafe_allow_html=True)

        hypotheses = data.get("nce_hypotheses", [])
        if not hypotheses:
            st.info("No hypotheses generated.")
            return

        for i, hyp in enumerate(hypotheses):
            st.markdown(f"#### Hypothesis {i + 1}: `{hyp.get('technique_id', '?')}`")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"- **Technique:** `{hyp.get('technique_id')}`")
                st.markdown(f"- **Source Account:** `{hyp.get('source_account')}`")
                st.markdown(f"- **Source Host:** `{hyp.get('source_host')}`")
                st.markdown(f"- **Target Host:** `{hyp.get('target_host')}`")
            with col2:
                conf = hyp.get("nce_confidence", 0)
                st.markdown(f"- **NCE Confidence:** `{conf:.2f}` *(advisory only)*")
                refs = hyp.get("supporting_evidence_refs", [])
                st.markdown(f"- **Evidence Refs:** `{', '.join(refs)}`")
                flags = hyp.get("missing_context_flags", [])
                if flags:
                    st.markdown(f"- **Missing Context:** `{', '.join(flags)}`")
                else:
                    st.markdown("- **Missing Context:** *(none flagged)*")

            if i < len(hypotheses) - 1:
                st.divider()


def render_sse_validation(st, data: dict) -> None:
    """Stage 3: SSE Structural Validation."""
    with st.expander("🔬 Stage 3 — SSE Structural Validation", expanded=True):
        sse_results = data.get("sse_results", [])
        feas_count = data.get("sse_feasible_count", 0)
        infeas_count = data.get("sse_infeasible_count", 0)

        # Summary
        if feas_count == 0:
            st.markdown(f"""
            <div class="callout success">
                <span class="stage-badge infeasible">ALL INFEASIBLE</span>
                <strong>{infeas_count} hypothesis(es) checked — none are
                structurally feasible.</strong>  The knowledge graph has no valid
                attack path matching any NCE hypothesis.
            </div>
            """, unsafe_allow_html=True)

            # Core thesis callout for defended attack
            hijack = data.get("hijack_data")
            if isinstance(hijack, dict) and hijack.get("any_hijack"):
                st.markdown("""
                <div class="callout warning">
                    <strong>🎯 Core Thesis Demonstration:</strong> The LLM (NCE)
                    was fooled here — the undefended baseline produced a
                    <strong>verdict flip</strong> hijack.  But SSE's pure
                    graph-traversal check independently found NO valid attack path.
                    <strong>The structural layer caught what the LLM missed.</strong>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="callout warning">
                <span class="stage-badge feasible">FEASIBLE DETECTED</span>
                <strong>{feas_count} FEASIBLE, {infeas_count} INFEASIBLE</strong> —
                at least one hypothesis has a structurally valid attack path.
                This hypothesis proceeds to RSEM for risk scoring.
            </div>
            """, unsafe_allow_html=True)

        # Per-hypothesis results
        for i, sse_r in enumerate(sse_results):
            verdict = sse_r.get("sse_verdict", "?")
            path_conf = sse_r.get("path_confidence", 0.0)
            conf_gap = sse_r.get("confidence_gap", 0.0)
            tech = sse_r.get("technique_id", "?")

            badge_class = "infeasible" if verdict == "INFEASIBLE" else "feasible"

            st.markdown(f"""
            <span class="stage-badge {badge_class}">{verdict}</span>
            **{tech}** — path_confidence: `{path_conf:.2f}`,
            confidence_gap: `{conf_gap:+.2f}`
            """, unsafe_allow_html=True)

        # T1071 limitation callout
        has_t1071_feasible = any(
            r.get("technique_id") == "T1071" and r.get("sse_verdict") == "FEASIBLE"
            for r in sse_results
        )
        if has_t1071_feasible:
            st.markdown("""
            <div class="callout danger">
                <strong>📌 Architectural Limitation — T1071/Network-Egress:</strong>
                T1071 (Command & Control) checks only zone-egress topology.
                Any outbound connection from a workstation-zone source to an
                external IP is automatically FEASIBLE, regardless of whether
                the alert is contaminated or clean.  This is the documented
                structural defense gap — SSE cannot distinguish real vs.
                fabricated C2 narratives.
            </div>
            """, unsafe_allow_html=True)


def render_rsem_ranking(st, data: dict) -> None:
    """Stage 4: RSEM Risk Scoring."""
    with st.expander("📊 Stage 4 — RSEM Risk Scoring", expanded=True):
        reached = data.get("reached_rsem", False)
        rsem_results = data.get("rsem_results", [])

        if not reached or not rsem_results:
            st.markdown("""
            <div class="callout insight">
                <strong>RSEM Not Reached</strong> — All hypotheses were
                INFEASIBLE at SSE validation.  Since no structurally valid
                attack path exists, there is nothing for RSEM to score.
                This hypothesis was excluded from risk ranking (by design —
                ranking defensive actions against a structurally impossible
                attack would produce meaningless scores).
            </div>
            """, unsafe_allow_html=True)
            return

        for rsem_r in rsem_results:
            tech = rsem_r.get("technique_id", "?")
            acct = rsem_r.get("source_account", "?")
            tgt = rsem_r.get("target_host", "?")

            st.markdown(f"**Ranked actions for `{tech}` "
                        f"({acct} → {tgt}):**")

            actions = rsem_r.get("ranked_actions", [])
            if actions:
                rows = []
                for j, act in enumerate(actions):
                    rows.append({
                        "Rank": j + 1,
                        "Action": act.get("action_type", "?"),
                        "Target": act.get("target", "")
                               or _format_target(act.get("target_account"),
                                                 act.get("target_host")),
                        "Containment": f"{act.get('containment', 0):.4f}",
                        "Business Impact": f"{act.get('business_impact', 0):.4f}",
                        "Composite": f"{act.get('composite', 0):.4f}",
                    })

                st.table(rows)


def render_playbook_guardrails(st, data: dict) -> None:
    """Stage 5: Action/Playbook Generation & Guardrails."""
    with st.expander("📑 Stage 5 — Playbook & Guardrails", expanded=True):
        playbook = data.get("playbook")
        if not playbook:
            st.markdown("""
            <div class="callout insight">
                <strong>Playbook Not Applicable</strong> — No hypothesis
                reached RSEM, so no playbook was generated.  The pipeline
                correctly stops at SSE for fully INFEASIBLE alerts.
            </div>
            """, unsafe_allow_html=True)
            return

        status = playbook.get("overall_status", "?")
        reason = playbook.get("guardrail_decision_reason", "")
        steps = playbook.get("steps", [])

        # Status badge
        if status == "AUTO_APPROVED":
            badge = "approved"
        elif status == "PENDING_ANALYST_REVIEW":
            badge = "pending"
        elif status == "DRY_RUN_COMPLETE":
            badge = "executed"
        else:
            badge = "pending"

        st.markdown(f"""
        <span class="stage-badge {badge}">{status}</span>
        """, unsafe_allow_html=True)

        # Steps table
        st.markdown("**Playbook Steps:**")
        for step in steps:
            step_num = step.get("step_number", "?")
            action_type = step.get("action_type", "?")
            is_policy = step.get("is_policy_action", False)
            target = step.get("target", "?")
            cont = step.get("containment", 0)
            bi = step.get("business_impact", 0)
            comp = step.get("composite_score", 0)

            policy_badge = ""
            if is_policy:
                policy_badge = '<span class="stage-badge policy">POLICY</span>'

            st.markdown(f"""
            **Step {step_num}:** `{action_type}` {policy_badge}
            → Target: `{target}` | Containment: `{cont:.4f}` |
            BI: `{bi:.4f}` | Composite: `{comp:.4f}`
            """, unsafe_allow_html=True)

        # Guardrail decision
        st.markdown("---")
        st.markdown(f"**Guardrail Decision:**")
        st.code(reason, language=None)


def render_execution(st, data: dict) -> None:
    """Stage 6: Execution Interface (Dry-Run)."""
    with st.expander("⚡ Stage 6 — Execution Interface (Dry-Run)", expanded=True):
        playbook = data.get("playbook")
        if not playbook:
            st.markdown("""
            <div class="callout insight">
                <strong>Execution Not Applicable</strong> — No playbook was
                generated (all hypotheses INFEASIBLE).
            </div>
            """, unsafe_allow_html=True)
            return

        status = playbook.get("overall_status", "?")
        dry_run = playbook.get("dry_run_report", "")

        if status in ("AUTO_APPROVED", "DRY_RUN_COMPLETE"):
            st.markdown("""
            <div class="callout success">
                <span class="stage-badge executed">DRY-RUN EXECUTED</span>
                <strong>Playbook was AUTO_APPROVED.</strong>  The dry-run
                executed on a deep copy of the knowledge graph — the live
                graph was NEVER mutated.  Before/after state diff and
                rollback instructions below.
            </div>
            """, unsafe_allow_html=True)
        elif status == "PENDING_ANALYST_REVIEW":
            st.markdown(f"""
            <div class="callout danger">
                <span class="stage-badge refused">EXECUTION REFUSED</span>
                <strong>This playbook requires human approval before any
                action is simulated.</strong>  The guardrail layer routed
                it to PENDING_ANALYST_REVIEW — the refusal IS the
                interesting result for this scenario.
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="callout warning">
                <strong>Status:</strong> <code>{status}</code>
            </div>
            """, unsafe_allow_html=True)

        if dry_run:
            st.markdown("**Dry-Run Report:**")
            st.code(dry_run, language=None)


# =========================================================================
# UTILITY HELPERS
# =========================================================================

def _escape_html(text: str) -> str:
    """Escape HTML special characters for safe rendering."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _format_target(account: str | None, host: str | None) -> str:
    """Format a target description from account/host fields."""
    parts = []
    if account:
        parts.append(f"account={account}")
    if host:
        parts.append(f"host={host}")
    return ", ".join(parts) if parts else "—"


# =========================================================================
# LIVE MODE (stretch scope — optional API-calling mode)
# =========================================================================

def render_live_mode(st) -> None:
    """Render the optional live-mode panel (behind toggle, off by default)."""
    st.markdown("---")
    st.markdown("### ⚡ Advanced: Run a New Alert Live")
    st.markdown("""
    <div class="callout warning">
        <strong>⚠️ API Quota Warning:</strong> Live mode makes real Gemini API
        calls.  Each alert consumes 1+ API call from your quota (20 req/day
        free tier for gemini-3.6-flash, 500/day for flash-lite).  Use only
        during rehearsal or if a reviewer requests a live demo.
    </div>
    """, unsafe_allow_html=True)

    alert_json = st.text_area(
        "Paste raw alert JSON:",
        height=200,
        placeholder='{"alert_id": "...", "source_system": "EDR", ...}',
    )

    if st.button("🚀 Run Pipeline (uses API quota)", type="primary"):
        if not alert_json.strip():
            st.error("Please paste a valid alert JSON first.")
            return

        try:
            alert_dict = json.loads(alert_json)
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {e}")
            return

        with st.spinner("Running pipeline... (this may take 5-15 seconds)"):
            try:
                result = _run_live_pipeline(alert_dict)
                st.success("Pipeline completed!")
                _render_live_result(st, result)
            except Exception as e:
                st.error(f"Pipeline error: {e}")


def _run_live_pipeline(alert_dict: dict) -> dict:
    """Run a new alert through the full live pipeline."""
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.nce_engine import alert_to_nce_input, generate_hypotheses
    from perception.nce_rsem_integration import rank_validated_hypotheses
    from perception.nce_sse_integration import validate_hypothesis_with_sse
    from perception.rsem import (
        ActionType,
        ProposedAction,
        StructuralSimulationEngine,
    )

    # NCE
    nce_input = alert_to_nce_input(alert_dict)
    nce_result = generate_hypotheses(nce_input)

    if not nce_result.success or not nce_result.hypotheses:
        return {
            "error": f"NCE failed: {nce_result.failure_reason}",
            "nce_raw_response": nce_result.raw_response,
        }

    # SSE
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    validated_list = [
        validate_hypothesis_with_sse(h, sse)
        for h in nce_result.hypotheses
    ]

    # RSEM
    candidate_actions = [
        ProposedAction(action_type=ActionType.REVOKE_SESSION,
                       target_account_id=nce_result.hypotheses[0].source_account),
        ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES,
                       target_account_id=nce_result.hypotheses[0].source_account),
        ProposedAction(action_type=ActionType.QUARANTINE_ACCESS,
                       target_host_id=nce_result.hypotheses[0].target_host),
        ProposedAction(action_type=ActionType.MONITOR_ONLY,
                       target_account_id=nce_result.hypotheses[0].source_account),
    ]
    pipeline_result = rank_validated_hypotheses(
        validated_list, kg, sse, candidate_actions,
    )

    # Format results
    nce_hyps = []
    for h in nce_result.hypotheses:
        nce_hyps.append({
            "technique_id": h.technique_id,
            "source_account": h.source_account,
            "source_host": h.source_host,
            "target_host": h.target_host,
            "nce_confidence": h.nce_confidence,
            "supporting_evidence_refs": h.supporting_evidence_refs,
        })

    sse_data = []
    for vh in validated_list:
        sse_data.append({
            "technique_id": vh.hypothesis.technique_id,
            "sse_verdict": vh.best_sse_verdict.value,
            "path_confidence": vh.best_path_confidence,
            "confidence_gap": vh.confidence_gap,
            "status": vh.hypothesis.status.value,
        })

    return {
        "nce_hypotheses": nce_hyps,
        "nce_raw_response": nce_result.raw_response,
        "sse_results": sse_data,
        "sse_feasible_count": sum(1 for v in validated_list
                                  if v.best_sse_verdict.value != "INFEASIBLE"),
        "sse_infeasible_count": sum(1 for v in validated_list
                                    if v.best_sse_verdict.value == "INFEASIBLE"),
    }


def _render_live_result(st, result: dict) -> None:
    """Render live pipeline results inline."""
    if "error" in result:
        st.error(result["error"])
        return

    st.markdown("#### NCE Hypotheses")
    st.json(result.get("nce_hypotheses", []))

    st.markdown("#### SSE Validation")
    for sse_r in result.get("sse_results", []):
        verdict = sse_r.get("sse_verdict", "?")
        badge = "infeasible" if verdict == "INFEASIBLE" else "feasible"
        st.markdown(f"""
        <span class="stage-badge {badge}">{verdict}</span>
        **{sse_r.get('technique_id')}** —
        path_confidence: `{sse_r.get('path_confidence', 0):.2f}`
        """, unsafe_allow_html=True)


# =========================================================================
# MAIN APPLICATION
# =========================================================================

def main() -> None:
    """Streamlit application entry point."""
    st = _import_streamlit()

    st.set_page_config(
        page_title="AgentSOC 2.0 — Pipeline Demo",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    _inject_custom_css(st)

    # -----------------------------------------------------------------
    # Sidebar
    # -----------------------------------------------------------------
    with st.sidebar:
        st.markdown("## 🛡️ AgentSOC 2.0")
        st.markdown("**Pipeline Review Demo**")
        st.markdown("---")

        scenario_key = st.selectbox(
            "Select Scenario:",
            options=list(SCENARIOS.keys()),
            format_func=lambda k: SCENARIOS[k]["label"],
            index=0,
        )

        st.markdown("---")

        # Live Mode toggle
        live_mode = st.toggle(
            "🔴 Live Mode (API calls)",
            value=False,
            help="Enable to run new alerts through the real Gemini pipeline. "
                 "Uses API quota — off by default for demo safety.",
        )

        st.markdown("---")
        st.markdown(
            "<small style='color:#666'>Pipeline: Perception → NCE → SSE → "
            "RSEM → Action/Playbook</small>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<small style='color:#666'>All 7 scenarios replay from "
            "pre-computed results (zero API calls).</small>",
            unsafe_allow_html=True,
        )

    # -----------------------------------------------------------------
    # Main Area
    # -----------------------------------------------------------------
    render_header(st)

    # Load scenario data
    try:
        scenario_data = load_scenario(scenario_key)
    except Exception as e:
        st.error(f"Failed to load scenario: {e}")
        return

    # Scenario description
    st.markdown(f"### {scenario_data['name']}")
    st.markdown(scenario_data["description"])
    st.markdown("---")

    # Render all 6 pipeline stages
    render_raw_alert(st, scenario_data)
    render_nce_hypotheses(st, scenario_data)
    render_sse_validation(st, scenario_data)
    render_rsem_ranking(st, scenario_data)
    render_playbook_guardrails(st, scenario_data)
    render_execution(st, scenario_data)

    # Live Mode panel (if enabled)
    if live_mode:
        st.markdown("---")
        render_live_mode(st)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align:center; color:#666; font-size:0.8rem; padding:16px 0;">
        AgentSOC 2.0 — Structural Defense Rate: 64/80 (80.0%) |
        Clean-Alert FP: 0/60 non-T1071 (0.0%) |
        Full Pipeline: 366/366 tests passing
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
