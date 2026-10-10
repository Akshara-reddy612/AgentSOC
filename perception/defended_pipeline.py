"""
perception/defended_pipeline.py

Everything after NCE for one alert, as a pure function (Phase 3 step 3.4,
2026-10-11): T1071 grounding label -> trusted alert context (entity binding,
trusted destination) -> SSE -> RSEM (shared candidate builder) -> playbook +
guardrails -> alert outcome.  No dry run, no audit-log writes, live graph
never mutated.  Used by the v2 evaluation runner; Monitoring and Streamlit
perform the same steps inline.
"""
from __future__ import annotations

from perception.action_playbook import build_candidate_actions, build_playbook, evaluate_guardrails
from perception.entity_binding import attach_alert_context, bind_entities
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import NCEHypothesis
from perception.nce_engine import _NCE_EVIDENCE_FIELD_NAMES, label_t1071_grounding
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.outcome import decide
from perception.sse import SSEVerdict, StructuralSimulationEngine


def run_downstream(hypotheses: list[NCEHypothesis], alert: dict,
                   kg: KnowledgeStoreGraph | None = None) -> dict:
    kg = kg or KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    evidence = {f: str(alert[f]) for f in _NCE_EVIDENCE_FIELD_NAMES if alert.get(f) is not None}
    hyps = attach_alert_context(label_t1071_grounding(hypotheses, evidence), alert)

    rows, statuses = [], []
    for h in hyps:
        vh = validate_hypothesis_with_sse(h, sse)
        row = {
            "technique_id": h.technique_id, "source_account": h.source_account,
            "source_host": h.source_host, "target_host": h.target_host,
            "evidence_grounding": h.evidence_grounding, "entity_binding": h.entity_binding,
            "binding_roles": bind_entities(h, alert).roles,
            "trusted_destination": h.trusted_destination,
            "sse_verdict": vh.best_sse_verdict.value, "path_confidence": round(vh.best_path_confidence, 6),
        }
        if vh.best_sse_verdict != SSEVerdict.INFEASIBLE:
            rhr = rank_validated_hypotheses([vh], kg, sse, build_candidate_actions(h)).ranked[0]
            pb = evaluate_guardrails(build_playbook(rhr, kg), kg)
            top = rhr.ranked_actions[0]
            row.update({
                "top_action": top.action.action_type.value,
                "top_target_account": top.action.target_account_id,
                "top_target_host": top.action.target_host_id,
                "top_composite": round(top.composite_score, 6),
                "playbook_status": pb.overall_status.value,
                "guardrail_reason": pb.guardrail_decision_reason,
            })
            statuses.append(pb.overall_status.value)
        rows.append(row)
    out = decide(alert, statuses, kg)
    return {"hypotheses": rows, "outcome": out.label, "outcome_reasons": out.reasons}
