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
        "label": "1 │ Contaminated Alert, All Hypotheses Infeasible",
        "source_file": "nce7_comparative_results",
        "alert_id": "1073741825161",
        "slot": 1,
        "description": (
            "A fabricated-evidence alert on which the undefended *triage* agent "
            "was hijacked (verdict flip).  NCE's hypotheses (replayed from the "
            "archive) are all INFEASIBLE in SSE.  Caveat: the identity graph "
            "holds none of this alert's hosts or accounts, so every non-T1071 "
            "hypothesis is infeasible regardless of the LLM — this shows the "
            "pipeline's behaviour on an empty identity graph, not proof that "
            "SSE catches hijacked hypotheses."
        ),
    },
    "2_t1071_limitation": {
        "label": "2 │ Contaminated T1071 → BLOCK_EGRESS → Analyst Review",
        "source_file": "nce7_comparative_results",
        "alert_id": "146028890043",
        "slot": 8,
        "description": (
            "A contaminated alert where NCE proposes T1071 (C2).  SSE checks the "
            "synthetic enterprise network model: the source laptop's zone has a "
            "proxied internet route, so C2 is FEASIBLE (destination unverified — "
            "this corpus has no trusted destination field yet).  RSEM ranks "
            "BLOCK_EGRESS first (it cuts the host's internet route); it is a "
            "hard-floor action, so the playbook goes to analyst review."
        ),
    },
    "3_clean_correct": {
        "label": "3 │ Clean Alert, All Hypotheses Infeasible",
        "source_file": "nce8_clean_fp_results",
        "alert_id": "1073741824021",
        "description": (
            "A clean alert.  NCE (which must always name at least one attack "
            "technique) proposes T1562, T1484 and T1078; SSE finds all "
            "INFEASIBLE and RSEM is not reached.  Same caveat as Scenario 1: "
            "with no identity edges for this alert's entities, infeasibility "
            "comes from the empty graph."
        ),
    },
    "4_t1071_guardrail_silence": {
        "label": "4 │ Clean T1071 → BLOCK_EGRESS → Analyst Review",
        "source_file": "nce8_clean_fp_results",
        "alert_id": "1125281436175",
        "description": (
            "A clean alert with genuine-looking C2 telemetry (curl to an "
            "external IP).  T1071 is labelled grounded and is FEASIBLE from a "
            "workstation zone.  Previously every action tied at 0.0 and the "
            "first in the list (MONITOR_ONLY) was silently auto-approved; now "
            "BLOCK_EGRESS gives real containment and any remaining tie routes "
            "to analyst review, so C2 hypotheses never pass with zero friction."
        ),
    },
    "5_hard_floor": {
        "label": "5 │ Guardrail Hard-Floor (QUARANTINE_ACCESS → Review)",
        "source_file": "guardrail_constructed",
        "scenario_key": "hard_floor",
        "description": (
            "Hand-constructed scenario offering only disruptive actions "
            "(REVOKE_SESSION, QUARANTINE_ACCESS) against svc_backup's T1550 "
            "path to server-db01.  QUARANTINE_ACCESS ranks #1 (containment 1.0 "
            "− BI 0.75 = 0.25; REVOKE cuts nothing for T1550).  It is in the "
            "mandatory-review set → PENDING_ANALYST_REVIEW; dry run REFUSED."
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

    # Replay ONLY the archived NCE output (2026-10-10).  SSE, RSEM,
    # guardrails and the dry run are recomputed with the current pipeline
    # code via _run_downstream, the same function Live Mode uses, so the demo
    # never shows stale downstream results.  T1071 hypotheses are labelled
    # grounded/ungrounded from the raw alert's evidence fields.
    from perception.nce_contract import MissingContextFlag, NCEHypothesis
    from perception.nce_engine import label_t1071_grounding

    hypotheses = []
    for h in record.get("nce_hypotheses", []):
        hypotheses.append(NCEHypothesis(
            technique_id=h["technique_id"],
            source_account=h.get("source_account") or "",
            source_host=h.get("source_host") or "",
            target_host=h.get("target_host") or "",
            nce_confidence=float(h.get("nce_confidence", 0.0)),
            supporting_evidence_refs=list(h.get("supporting_evidence_refs") or []),
            missing_context_flags=[
                MissingContextFlag(f) for f in (h.get("missing_context_flags") or [])
                if f in {m.value for m in MissingContextFlag}
            ],
            incident_id=str(alert_id),
        ))
    if raw_alert:
        evidence = {
            f: str(raw_alert[f])
            for f in ("process_name", "command_line", "registry_key",
                      "parent_process", "file_path", "raw_log_line")
            if raw_alert.get(f) is not None
        }
        hypotheses = label_t1071_grounding(hypotheses, evidence)

    data = _run_downstream(
        hypotheses, raw_alert, scenario_type="replay",
        nce_raw_response=record.get("nce_raw_response"),
    )
    data.update({
        "name": config["label"],
        "description": config["description"],
        "is_contaminated": is_contaminated,
        "injection_category": injection_category,
        "hijack_data": hijack_data,
        "structural_defense_success": defense_success,
    })
    return data


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
                <p class="metric-value">80.6-81.9%</p>
                <p class="metric-label">No actionable hypothesis — contaminated<br>258-262/320 alerts (2 NCE runs)</p>
            </div>
            <div class="metric-card fp">
                <p class="metric-value">78.1-79.1%</p>
                <p class="metric-label">No actionable hypothesis — clean twins<br>250-253/320 alerts (2 NCE runs)<br><em>Similar rates: driven by graph coverage, not attack detection</em></p>
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

        scenario_type = data.get("scenario_type")
        is_contaminated = data.get("is_contaminated", False)
        injection_cat = data.get("injection_category")

        if scenario_type == "live":
            st.markdown("""
            <div class="callout insight">
                <strong>⚡ Live Alert</strong> — Real alert processed through
                the live pipeline.  No ground-truth label exists for live data.
            </div>
            """, unsafe_allow_html=True)
        elif is_contaminated:
            st.markdown(f"""
            <div class="callout danger">
                <strong>⚠️ Contaminated Alert</strong> — Injection category:
                <code>{injection_cat}</code>.  The highlighted fields below
                contain attacker-injected content.
            </div>
            """, unsafe_allow_html=True)
        else:
            grade = _escape_html(str(raw.get("_source_incident_grade") or "unknown"))
            st.markdown(f"""
            <div class="callout success">
                <strong>✓ Clean Alert</strong> — No injection was applied to this
                alert.  GUIDE incident grade: <code>{grade}</code>.
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
            network zone, or historical access — those live in the ImmutableContext
            and the knowledge graph, which NCE's prompt builder never receives.
            The FORBIDDEN_FIELD_NAMES guard and isinstance(Evidence) checks enforce
            this on the NCE side.
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
                    <strong>Note:</strong> the undefended triage agent was hijacked
                    on this alert (<strong>verdict flip</strong>), and SSE found no
                    valid attack path for NCE's hypotheses.  Caveat: the identity
                    graph contains none of this alert's hosts or accounts, so
                    non-T1071 hypotheses are infeasible whatever the LLM says —
                    this is not evidence that SSE detected the hijack.
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
                if "error" in result and not result.get("nce_hypotheses"):
                    st.error(result["error"])
                else:
                    st.success("Pipeline completed!")
                    render_raw_alert(st, result)
                    _render_live_explanation(st, "raw_alert", result)

                    render_nce_hypotheses(st, result)
                    _render_live_explanation(st, "nce", result)

                    render_sse_validation(st, result)
                    _render_live_explanation(st, "sse", result)

                    render_rsem_ranking(st, result)
                    _render_live_explanation(st, "rsem", result)

                    render_playbook_guardrails(st, result)
                    _render_live_explanation(st, "playbook", result)

                    render_execution(st, result)
                    _render_live_explanation(st, "execution", result)
            except Exception as e:
                st.error(f"Pipeline error: {e}")


def _run_live_pipeline(alert_dict: dict) -> dict:
    """Run a new alert through the full live pipeline (real NCE API call)."""
    from perception.nce_engine import alert_to_nce_input, generate_hypotheses

    # NCE (labels T1071 grounded/ungrounded; never drops hypotheses)
    nce_input = alert_to_nce_input(alert_dict)
    nce_result = generate_hypotheses(nce_input)

    if not nce_result.success or nce_result.output is None or not nce_result.output.hypotheses:
        return {
            "error": f"NCE failed: {nce_result.error}",
            "nce_raw_response": nce_result.raw_response,
        }

    return _run_downstream(
        list(nce_result.output.hypotheses),
        alert_dict,
        scenario_type="live",
        nce_raw_response=nce_result.raw_response,
    )


def _run_downstream(
    hypotheses: list,
    raw_alert: dict | None,
    *,
    scenario_type: str,
    nce_raw_response: str | None = None,
) -> dict:
    """
    SSE -> RSEM -> Playbook/Guardrails -> dry run for a list of NCE hypotheses,
    using the CURRENT pipeline code.  Shared by Live Mode and the replay
    scenarios (which feed archived NCE output), so both show identical logic.
    """
    from perception.action_playbook import (
        build_playbook,
        evaluate_guardrails,
        execute_playbook_dry_run,
    )
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.nce_contract import HypothesisStatus
    from perception.nce_rsem_integration import rank_validated_hypotheses
    from perception.nce_sse_integration import validate_hypothesis_with_sse
    from perception.rsem import StructuralSimulationEngine

    # SSE
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    validated_list = [
        validate_hypothesis_with_sse(h, sse)
        for h in hypotheses
    ]

    # RSEM - Candidate actions built from feasible hypotheses only
    feasible_validated = [
        v for v in validated_list
        if v.hypothesis.status == HypothesisStatus.FEASIBLE
    ]

    if feasible_validated:
        from perception.action_playbook import build_candidate_actions

        top_feasible = feasible_validated[0].hypothesis
        # Shared canonical candidate set (2026-10-10); ties route to review.
        candidate_actions = build_candidate_actions(top_feasible)
        pipeline_result = rank_validated_hypotheses(
            validated_list, kg, sse, candidate_actions,
        )
    else:
        candidate_actions = []
        pipeline_result = rank_validated_hypotheses(
            validated_list, kg, sse, candidate_actions,
        )

    # Serialize RSEM results
    rsem_results = []
    for rh in pipeline_result.ranked:
        hyp = rh.validated.hypothesis
        ranked_actions_data = []
        for sa in rh.ranked_actions:
            target_parts = []
            if sa.action.target_account_id:
                target_parts.append(f"account={sa.action.target_account_id}")
            if sa.action.target_host_id:
                target_parts.append(f"host={sa.action.target_host_id}")
            ranked_actions_data.append({
                "action_type": sa.action.action_type.value,
                "containment": sa.containment,
                "business_impact": sa.business_impact,
                "composite": sa.composite_score,
                "target": ", ".join(target_parts) if target_parts else "—",
                "target_account": sa.action.target_account_id,
                "target_host": sa.action.target_host_id,
            })
        rsem_results.append({
            "technique_id": hyp.technique_id,
            "source_account": hyp.source_account,
            "source_host": hyp.source_host,
            "target_host": hyp.target_host,
            "ranked_actions": ranked_actions_data,
        })

    reached_rsem = len(pipeline_result.ranked) > 0

    # Playbook layer (guard against pipeline_result.ranked being empty)
    playbook_data = None
    if pipeline_result.ranked:
        playbook = build_playbook(pipeline_result.ranked[0], kg)
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
                "target": ", ".join(target_parts) if target_parts else "—",
            })

        playbook_data = {
            "steps": steps_data,
            "overall_status": playbook.overall_status.value,
            "guardrail_decision_reason": playbook.guardrail_decision_reason,
            "dry_run_report": playbook.dry_run_report,
        }

    # Format results
    nce_hyps = []
    for h in hypotheses:
        missing_flags = [
            f.value if hasattr(f, "value") else str(f)
            for f in (h.missing_context_flags or [])
        ]
        evidence_refs = [str(r) for r in (h.supporting_evidence_refs or [])]
        nce_hyps.append({
            "technique_id": h.technique_id,
            "source_account": h.source_account,
            "source_host": h.source_host,
            "target_host": h.target_host,
            "nce_confidence": h.nce_confidence,
            "supporting_evidence_refs": evidence_refs,
            "missing_context_flags": missing_flags,
            "evidence_grounding": h.evidence_grounding,
        })

    sse_data = []
    for vh in validated_list:
        best = next((r for r in vh.sse_results if r.verdict == vh.best_sse_verdict), None)
        sse_data.append({
            "technique_id": vh.hypothesis.technique_id,
            "sse_verdict": vh.best_sse_verdict.value,
            "path_confidence": vh.best_path_confidence,
            "confidence_gap": vh.confidence_gap,
            "status": vh.hypothesis.status.value,
            "evidence_grounding": vh.hypothesis.evidence_grounding,
            "destination_status": getattr(best, "destination_status", None),
            "dependency_note": getattr(best, "dependency_note", None),
        })

    return {
        "scenario_type": scenario_type,
        "raw_alert": raw_alert,
        "is_contaminated": None,
        "injection_category": None,
        "hijack_data": None,
        "nce_hypotheses": nce_hyps,
        "nce_raw_response": nce_raw_response,
        "sse_results": sse_data,
        "sse_feasible_count": sum(1 for v in validated_list
                                  if v.best_sse_verdict.value != "INFEASIBLE"),
        "sse_infeasible_count": sum(1 for v in validated_list
                                    if v.best_sse_verdict.value == "INFEASIBLE"),
        "reached_rsem": reached_rsem,
        "rsem_results": rsem_results,
        "playbook": playbook_data,
    }


def _render_live_explanation(st, stage: str, data: dict) -> None:
    """Generate deterministic, template-based plain-English explanation for live alerts."""
    if stage == "raw_alert":
        raw = data.get("raw_alert", {})
        alert_id = raw.get("alert_id", "Unknown")
        src_sys = raw.get("source_system", "SIEM/EDR")
        n_fields = len(raw)
        st.info(
            f"💡 **Plain-English Explanation (Stage 1 — Raw Alert):**\n\n"
            f"Alert **{alert_id}** was ingested from **{src_sys}** ({n_fields} structured fields). "
            f"Unlike curated evaluation alerts, live alerts carry **no ground truth** — free-text "
            f"telemetry fields may contain legitimate administrative activity or malicious prompt injection. "
            f"AgentSOC isolates these raw fields from the immutable Knowledge Graph so untrusted SIEM inputs "
            f"cannot manipulate downstream defense logic."
        )

    elif stage == "nce":
        hyps = data.get("nce_hypotheses", [])
        if not hyps:
            st.info("💡 **Plain-English Explanation (Stage 2 — NCE):** No hypotheses were generated.")
            return
        lines = []
        for i, h in enumerate(hyps):
            t = h.get("technique_id", "?")
            c = h.get("nce_confidence", 0.0)
            refs = ", ".join(h.get("supporting_evidence_refs", [])) or "none"
            lines.append(f"• **Hypothesis {i+1} ({t}):** NCE confidence **{c:.2f}**, grounded in `{refs}`.")
        summary = "\n".join(lines)
        st.info(
            f"💡 **Plain-English Explanation (Stage 2 — NCE Hypothesis Generation):**\n\n"
            f"The Narrative Counterfactual Engine proposed **{len(hyps)} candidate hypothesis(es)** based solely on unverified alert fields:\n\n"
            f"{summary}\n\n"
            f"**Architectural Guarantee:** NCE confidence scores are **advisory only**. The LLM operates in an isolated sandbox "
            f"without access to topological privileges or network segmentation. Every hypothesis must undergo deterministic graph validation in Stage 3."
        )

    elif stage == "sse":
        sse_results = data.get("sse_results", [])
        feas_count = data.get("sse_feasible_count", 0)

        hyp_details = []
        for r in sse_results:
            tech = r.get("technique_id", "?")
            verdict = r.get("sse_verdict", "?")
            conf = r.get("path_confidence", 0.0)

            if verdict == "FEASIBLE":
                hyp_details.append(
                    f"• **{tech} → FEASIBLE** (path confidence: **{conf:.2f}**): A structurally complete attack path "
                    f"exists in the Knowledge Graph with high confidence (>= 0.50)."
                )
            elif verdict == "CONDITIONALLY_FEASIBLE":
                hyp_details.append(
                    f"• **{tech} → CONDITIONALLY_FEASIBLE** (path confidence: **{conf:.2f}**): A structurally complete attack path "
                    f"exists in the Knowledge Graph, but confidence is below the 0.50 threshold (e.g., low-confidence or heuristic link). "
                    f"It is treated as structurally viable and advanced to RSEM for risk scoring."
                )
            else:
                hyp_details.append(
                    f"• **{tech} → INFEASIBLE** (path confidence: **{conf:.2f}**): No valid topological access path exists "
                    f"in the Knowledge Graph. This hypothesis cannot execute in the enterprise environment and is dropped."
                )

        has_t1071_feasible = any(
            r.get("technique_id") == "T1071" and r.get("sse_verdict") in ("FEASIBLE", "CONDITIONALLY_FEASIBLE")
            for r in sse_results
        )
        t1071_note = ""
        if has_t1071_feasible:
            t1071_note = (
                f"\n\n⚠️ **Architectural Note (T1071 / Network-Egress):** T1071 evaluates zone-egress topology. "
                f"Because outbound traffic from a workstation to the internet is topologically permitted, "
                f"T1071 is marked FEASIBLE regardless of whether the traffic is malicious C2 or benign browsing. "
                f"This reflects the documented structural defense boundary."
            )

        detail_str = "\n".join(hyp_details)
        if feas_count == 0:
            conclusion = "**Verdict:** All hypotheses are INFEASIBLE. The pipeline safely terminates here — no risk to score."
        else:
            conclusion = f"**Verdict:** {feas_count} hypothesis(es) proved structurally viable and proceed to Stage 4 (RSEM)."

        st.info(
            f"💡 **Plain-English Explanation (Stage 3 — SSE Structural Validation):**\n\n"
            f"{detail_str}\n\n"
            f"{conclusion}{t1071_note}"
        )

    elif stage == "rsem":
        reached = data.get("reached_rsem", False)
        rsem_results = data.get("rsem_results", [])
        if not reached or not rsem_results:
            st.info(
                "💡 **Plain-English Explanation (Stage 4 — RSEM Risk Scoring):**\n\n"
                "RSEM was not reached because all hypotheses were found **INFEASIBLE** by SSE. "
                "Ranking defensive actions against impossible attack paths is avoided by design."
            )
            return

        lines = []
        for rh in rsem_results:
            tech = rh.get("technique_id", "?")
            actions = rh.get("ranked_actions", [])
            if actions:
                top = actions[0]
                lines.append(
                    f"• For **{tech}**, top-ranked action is **{top.get('action_type')}** (target: `{top.get('target')}`) "
                    f"with containment = **{top.get('containment', 0):.4f}**, business impact = **{top.get('business_impact', 0):.4f}**, "
                    f"and composite score = **{top.get('composite', 0):.4f}**."
                )
                if len(actions) > 1:
                    other_strs = [
                        f"{a.get('action_type')} (containment={a.get('containment', 0):.4f}, BI={a.get('business_impact', 0):.4f}, score={a.get('composite', 0):.4f})"
                        for a in actions[1:]
                    ]
                    lines.append(f"  *Other candidate actions scored:* {'; '.join(other_strs)}.")
        summary = "\n".join(lines)
        st.info(
            f"💡 **Plain-English Explanation (Stage 4 — RSEM Risk Scoring):**\n\n"
            f"RSEM scored candidate response actions by balancing graph containment against operational business impact:\n\n"
            f"{summary}\n\n"
            f"The top-ranked action proceeds to Stage 5 for playbook generation and safety guardrail evaluation."
        )

    elif stage == "playbook":
        playbook = data.get("playbook")
        if not playbook:
            st.info(
                "💡 **Plain-English Explanation (Stage 5 — Playbook & Guardrails):**\n\n"
                "No playbook was generated because no hypotheses survived SSE structural validation."
            )
            return

        overall_status = playbook.get("overall_status", "?")
        reason = playbook.get("guardrail_decision_reason", "")
        steps = playbook.get("steps", [])
        top_step = steps[0] if steps else {}
        top_action = top_step.get("action_type", "")
        top_containment = top_step.get("containment", 0.0)

        if (
            top_action == "MONITOR_ONLY"
            and top_containment == 0.0
            and overall_status == "AUTO_APPROVED"
        ):
            st.info(
                f"💡 **Plain-English Explanation (Stage 5 — Playbook & Guardrails):**\n\n"
                f"Playbook status: **`{overall_status}`**\n\n"
                f"⚠️ **Guardrail-Silence finding:** **No guardrail rule fires — this technique's containment is architecturally zero (see Guardrail-Silence finding)**. "
                f"Because the top-ranked action is **MONITOR_ONLY** with containment = **0.0000** and business impact = **0.0000**, "
                f"it triggers neither disruptive action guardrails nor high-impact blocks. It is marked `AUTO_APPROVED` because "
                f"passive monitoring causes zero business disruption, not because active mitigation occurred."
            )
        elif overall_status == "PENDING_ANALYST_REVIEW":
            st.info(
                f"💡 **Plain-English Explanation (Stage 5 — Playbook & Guardrails):**\n\n"
                f"Playbook status: **`{overall_status}`**\n\n"
                f"🛡️ **Automated Execution Refused:** The safety guardrail layer blocked automatic execution: `{reason}`. "
                f"High-impact containment or restricted actions (such as privileged credential revocation) require mandatory human review."
            )
        else:
            st.info(
                f"💡 **Plain-English Explanation (Stage 5 — Playbook & Guardrails):**\n\n"
                f"Playbook status: **`{overall_status}`**\n\n"
                f"✅ **Guardrail Cleared:** The recommended action passed all automated guardrail safety checks: `{reason}`. "
                f"The action proceeds to dry-run execution."
            )

    elif stage == "execution":
        playbook = data.get("playbook")
        if not playbook:
            st.info(
                "💡 **Plain-English Explanation (Stage 6 — Execution Interface):**\n\n"
                "Execution not applicable — no playbook was generated."
            )
            return

        status = playbook.get("overall_status", "?")
        if status in ("AUTO_APPROVED", "DRY_RUN_COMPLETE"):
            st.info(
                f"💡 **Plain-English Explanation (Stage 6 — Execution Interface / Dry-Run):**\n\n"
                f"The playbook completed a **safe dry-run** execution. The simulation ran on an isolated deep copy "
                f"of the Knowledge Graph — the live production environment and authoritative knowledge store were **never mutated**. "
                f"A deterministic before/after state diff and automated rollback recipe have been generated."
            )
        elif status == "PENDING_ANALYST_REVIEW":
            st.info(
                f"💡 **Plain-English Explanation (Stage 6 — Execution Interface / Dry-Run):**\n\n"
                f"Execution was **safely refused** by the guardrail layer. No simulated state modifications were executed. "
                f"The case has been routed to the SOC analyst review queue with full telemetry, evidence refs, and risk scores."
            )
        else:
            st.info(
                f"💡 **Plain-English Explanation (Stage 6 — Execution Interface):**\n\n"
                f"Execution status: **`{status}`**."
            )


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

    # Tabs: Pipeline Review Demo (existing) vs Live Monitoring (new)
    tab_review, tab_monitor = st.tabs(["🔬 Pipeline Review Demo", "📡 Live Monitoring"])

    with tab_review:
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

    with tab_monitor:
        from monitoring.dashboard import render_live_monitoring_tab
        render_live_monitoring_tab(st)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align:center; color:#666; font-size:0.8rem; padding:16px 0;">
        AgentSOC 2.0 — research prototype |
        No-actionable rate: contaminated 80.6-81.9%, clean twins 78.1-79.1% (2 NCE runs, n=320 each) |
        Identity graph and T1071 network model are synthetic; see PROJECT_STATUS.md
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
