"""
perception/defended_pipeline.py

Everything after NCE for one alert, as a pure function (Phase 3 step 3.4,
2026-10-11): T1071 grounding label -> trusted alert context (entity binding,
trusted destination) -> SSE -> RSEM (shared candidate builder) -> playbook +
guardrails -> alert outcome.  No dry run, no audit-log writes, live graph
never mutated.  Used by the v2 evaluation runner; Monitoring and Streamlit
perform the same steps inline.

Asymmetric trust (2026-10-31, decision P9 A): `asymmetric_downstream` lets the
LLM's hypotheses raise scrutiny but never lower it.  NCE reads text the attacker
can write, so nothing automatic may rest on its output:

  - the outcome is the text-free decision (the same pipeline without NCE's
    hypotheses: trusted fields, the store, ERA, the telemetry C2 check) or
    REVIEW; never a dismissal or a lower priority the text-free decision did
    not reach;
  - only actions the text-free decision auto-approves execute, and they execute
    even if NCE's hypotheses send the case to review (escalating cannot delay
    them); an action only NCE's hypotheses support becomes a proposal for an
    analyst;
  - so NCE's output cannot make a case learnable either: the learning gate
    learns dismissed cases only (perception/knowledge_updater.py).
"""
from __future__ import annotations

from perception.action_playbook import build_candidate_actions, build_playbook, evaluate_guardrails
from perception.entity_binding import attach_alert_context, bind_entities
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import NCEHypothesis
from perception.nce_engine import _NCE_EVIDENCE_FIELD_NAMES, label_t1071_grounding
from perception.nce_rsem_integration import rank_validated_hypotheses
from perception.nce_sse_integration import validate_hypothesis_with_sse
from perception.outcome import AUTO_APPROVED, REVIEW, decide
from perception.sse import SSEVerdict, StructuralSimulationEngine

LLM_AUTHORITIES = ("full", "escalate")      # full: NCE's hypotheses decide as before; escalate: asymmetric trust
_AUTOMATED = ("AUTO_APPROVED", "DRY_RUN_COMPLETE")


def run_downstream(hypotheses: list[NCEHypothesis], alert: dict,
                   kg: KnowledgeStoreGraph | None = None, era_level: str | None = None) -> dict:
    kg = kg or KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    evidence = {f: str(alert[f]) for f in _NCE_EVIDENCE_FIELD_NAMES if alert.get(f) is not None}
    profile = kg.profile   # which addresses are internal (design step S1)
    hyps = attach_alert_context(label_t1071_grounding(hypotheses, evidence, profile), alert, profile)

    rows, statuses = [], []
    for h in hyps:
        vh = validate_hypothesis_with_sse(h, sse)
        row = {
            "technique_id": h.technique_id, "source_account": h.source_account,
            "source_host": h.source_host, "target_host": h.target_host,
            "evidence_grounding": h.evidence_grounding, "entity_binding": h.entity_binding,
            "binding_roles": bind_entities(h, alert, profile).roles,
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
    out = decide(alert, statuses, kg, era_level=era_level)
    return {"hypotheses": rows, "outcome": out.label, "outcome_reasons": out.reasons}


def _action(row: dict) -> tuple:
    """An action by what it acts on (a destination, host or account), as the outcome monitor executes it."""
    from perception.outcome_monitor import TARGET_KIND      # not at module level: outcome_monitor imports the gate

    action = row.get("top_action")
    kind = TARGET_KIND.get(action)
    if kind is None:
        return action, row.get("top_target_account"), row.get("top_target_host")
    return action, row.get("top_target_account") if kind == "account" else row.get("top_target_host")


def _same_hypothesis(a: dict, b: dict) -> bool:
    return all(a.get(k) == b.get(k) for k in ("technique_id", "source_account", "source_host", "target_host",
                                              "trusted_destination"))


def asymmetric_downstream(hypotheses: list[NCEHypothesis], alert: dict, kg: KnowledgeStoreGraph | None = None,
                          era_level: str | None = None, *, text_free: dict | None = None) -> dict:
    """
    run_downstream under asymmetric trust (module docstring).  `text_free` is the decision without NCE's
    hypotheses (run_downstream([], ...)), possibly raised by the caller's policy -- the triage gate sends a
    pattern the store never learned to review (open decision D7); computed here if not given.
    Returns run_downstream's keys plus "text_free_outcome" and "llm_outcome" (the outcome NCE's hypotheses alone
    would have given: the current pipeline's).  Rows of the text-free decision carry "text_free": True; only
    those can execute without an analyst.
    """
    kg = kg or KnowledgeStoreGraph()
    base = text_free if text_free is not None else run_downstream([], alert, kg, era_level)
    base_rows = [dict(r, text_free=True) for r in base["hypotheses"]]
    if not hypotheses:
        return {"hypotheses": base_rows, "outcome": base["outcome"], "outcome_reasons": list(base["outcome_reasons"]),
                "text_free_outcome": base["outcome"], "llm_outcome": None}
    try:
        llm = run_downstream(hypotheses, alert, kg, era_level)
    except Exception as e:  # noqa: BLE001 -- failing to evaluate NCE's output may only raise scrutiny (2026-10-31)
        return {"hypotheses": base_rows, "outcome": REVIEW,
                "outcome_reasons": [*base["outcome_reasons"], f"NCE's hypotheses could not be evaluated "
                                    f"({type(e).__name__}): the case goes to an analyst."],
                "text_free_outcome": base["outcome"], "llm_outcome": None}
    base_auto = {_action(r) for r in base_rows if r.get("playbook_status") in _AUTOMATED}
    rows, notes = list(base_rows), []
    for r in llm["hypotheses"]:
        if any(_same_hypothesis(r, b) for b in base_rows):
            continue                                  # the text-free decision already holds this hypothesis
        r = dict(r)
        if r.get("playbook_status") in _AUTOMATED:
            if _action(r) in base_auto:
                r["playbook_status"] = "COVERED_BY_TEXT_FREE"     # executes once, from the text-free row
            else:
                r["playbook_status"] = "PENDING_ANALYST_REVIEW"
                r["guardrail_reason"] = ("Asymmetric trust: only NCE's hypotheses support this action, so an "
                                         "analyst must approve it. " + str(r.get("guardrail_reason") or ""))
                notes.append(f"NCE proposed {r.get('top_action')}, which the text-free decision does not support: "
                             "an analyst must approve it.")
        rows.append(r)
    escalates = llm["outcome"] == REVIEW or bool(notes)
    outcome = REVIEW if escalates else base["outcome"]
    reasons = [*base["outcome_reasons"], *notes]
    if llm["outcome"] == REVIEW:
        reasons.append("NCE's hypotheses call for review: " + "; ".join(llm["outcome_reasons"]))
    elif not escalates and llm["outcome"] != base["outcome"]:
        reasons.append(f"NCE's hypotheses alone would give {llm['outcome']}; asymmetric trust keeps the "
                       f"text-free decision {base['outcome']} (LLM output may raise scrutiny, never lower it).")
    if outcome == AUTO_APPROVED and any(r.get("playbook_status") in _AUTOMATED and not r.get("text_free")
                                        for r in rows):
        raise AssertionError("asymmetric trust: an NCE-only action would execute")          # cannot happen
    return {"hypotheses": rows, "outcome": outcome, "outcome_reasons": reasons,
            "text_free_outcome": base["outcome"], "llm_outcome": llm["outcome"]}
