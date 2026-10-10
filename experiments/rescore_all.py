"""
experiments/rescore_all.py

Offline regression tool for Phase 2.  Re-scores every stored NCE run with the
CURRENT pipeline code (filter -> SSE -> RSEM) from the archived hypotheses, so
code changes can be checked alert by alert without any API call.

Runs covered (archived hypotheses are always the pre-filter set):
  clean_A, clean_B   experiments/paired_clean_results*.json   (input: guide_sample_500, as actually run)
  contam_A, contam_B agent/nce_n50_scaleup_results_run*.json  (input: guide_n50_scaleup_320)
  nce7               agent/nce7_scale_results.json            (80 heldout + 10 sample500 clean)
  nce8               agent/nce8_clean_fp_results.json         (50 sample500 clean)

For every alert the snapshot records each hypothesis (technique, entities,
whether the legacy T1071 filter would drop it, SSE verdict and path
confidence, optional grounding label) plus alert-level outcomes and the RSEM
top action for feasible hypotheses.

Usage:
    python -m experiments.rescore_all --snapshot NAME        # write experiments/rescore_snapshots/NAME.json
    python -m experiments.rescore_all --diff OLD NEW         # list every alert/hypothesis whose result changed
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED = PROJECT_ROOT / "GUIDE_Dataset" / "processed"
SNAP_DIR = PROJECT_ROOT / "experiments" / "rescore_snapshots"
EVIDENCE_FIELDS = ("process_name", "command_line", "registry_key",
                   "parent_process", "file_path", "raw_log_line")
FEASIBLE = {"FEASIBLE", "CONDITIONALLY_FEASIBLE"}


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _by_id_last(path: Path) -> dict[str, dict]:
    """Last row per alert_id wins — the lookup the historical harnesses used."""
    return {str(a["alert_id"]): a for a in _load(path)}


def _by_id_prefer_clean(path: Path) -> dict[str, dict]:
    """For duplicated ids keep the non-contaminated row (nce7/nce8 selected clean rows)."""
    out: dict[str, dict] = {}
    for a in _load(path):
        aid = str(a["alert_id"])
        if aid not in out or (out[aid].get("_ground_truth_is_contaminated") and not a.get("_ground_truth_is_contaminated")):
            out[aid] = a
    return out


def _runs():
    sample_last = _by_id_last(PROCESSED / "guide_sample_500_alerts.json")
    sample_clean = _by_id_prefer_clean(PROCESSED / "guide_sample_500_alerts.json")
    contam = _by_id_last(PROCESSED / "guide_n50_scaleup_320_alerts.json")
    heldout = _by_id_last(PROCESSED / "guide_heldout_140_alerts.json")
    return [
        ("clean_A", PROJECT_ROOT / "experiments" / "paired_clean_results.json", "nce_hypotheses_orig", lambda r: sample_last),
        ("clean_B", PROJECT_ROOT / "experiments" / "paired_clean_results_B.json", "nce_hypotheses_orig", lambda r: sample_last),
        ("contam_A", PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runA.json", "nce_hypotheses_orig", lambda r: contam),
        ("contam_B", PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runB.json", "nce_hypotheses_orig", lambda r: contam),
        ("nce7", PROJECT_ROOT / "agent" / "nce7_scale_results.json", "nce_hypotheses",
         lambda r: heldout if r.get("source") == "heldout" else sample_clean),
        ("nce8", PROJECT_ROOT / "agent" / "nce8_clean_fp_results.json", "nce_hypotheses", lambda r: sample_clean),
    ]


def _candidate_actions(hyp):
    """
    Candidate actions for RSEM.  Uses the shared builder when it exists
    (Phase 2 step 2.5+); otherwise the historical harness set (MONITOR_ONLY first).
    """
    try:
        from perception.action_playbook import build_candidate_actions
        return build_candidate_actions(hyp)
    except ImportError:
        pass
    from perception.rsem import ActionType, ProposedAction
    actions = [ProposedAction(action_type=ActionType.MONITOR_ONLY,
                              target_account_id=hyp.source_account or None,
                              target_host_id=None if hyp.source_account else (hyp.target_host or None))]
    if hyp.source_account:
        actions += [ProposedAction(action_type=ActionType.REVOKE_SESSION, target_account_id=hyp.source_account),
                    ProposedAction(action_type=ActionType.RESTRICT_PRIVILEGES, target_account_id=hyp.source_account)]
    if hyp.target_host:
        actions.append(ProposedAction(action_type=ActionType.QUARANTINE_ACCESS, target_host_id=hyp.target_host))
    return actions


def score_all() -> dict:
    from perception.knowledge_graph import KnowledgeStoreGraph
    from perception.nce_contract import MissingContextFlag, NCEHypothesis
    from perception.nce_engine import _apply_t1071_evidentiary_filter
    from perception.nce_sse_integration import validate_hypothesis_with_sse
    from perception.rsem import rank_actions
    from perception.sse import StructuralSimulationEngine
    import perception.nce_engine as nce_engine

    labeller = getattr(nce_engine, "label_t1071_grounding", None)  # added in a later Phase 2 step
    try:  # Phase 2 step 2.7+
        try:  # Phase 3 step 3.3+: binding + trusted destination
            from perception.entity_binding import attach_alert_context as binder
        except ImportError:
            from perception.entity_binding import label_entity_binding as binder
        from perception.action_playbook import build_playbook, evaluate_guardrails
        from perception.nce_rsem_integration import rank_validated_hypotheses
        guardrail = lambda rhr: evaluate_guardrails(build_playbook(rhr, kg))  # noqa: E731
    except ImportError:
        binder = guardrail = None
    try:
        from perception.outcome import decide
    except ImportError:
        decide = None
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    snapshot: dict = {"runs": {}}

    for run, path, field, corpus_for in _runs():
        out = {}
        for rec in _load(path):
            if rec.get("nce_error"):
                continue
            aid = str(rec["alert_id"])
            alert = corpus_for(rec).get(aid)
            if alert is None:
                raise SystemExit(f"{run}: alert {aid} missing from its input corpus")
            evidence = {f: str(alert[f]) for f in EVIDENCE_FIELDS if alert.get(f) is not None}
            hyps = []
            for h in rec.get(field) or []:
                hyps.append(NCEHypothesis(
                    technique_id=h["technique_id"],
                    source_account=h.get("source_account") or "",
                    source_host=h.get("source_host") or "",
                    target_host=h.get("target_host") or "",
                    nce_confidence=float(h.get("nce_confidence", 0.0)),
                    supporting_evidence_refs=list(h.get("supporting_evidence_refs") or []),
                    missing_context_flags=[MissingContextFlag(f) for f in h.get("missing_context_flags") or []],
                ))
            surviving, _ = _apply_t1071_evidentiary_filter(hyps, evidence)
            kept = {id(h) for h in surviving}
            labelled = labeller(hyps, evidence) if labeller else list(hyps)
            labels = [getattr(h, "evidence_grounding", None) for h in labelled]
            if binder:
                labelled = binder(labelled, alert)

            hyp_rows = []
            for h, label, hl in zip(hyps, labels, labelled):
                vh = validate_hypothesis_with_sse(hl, sse)
                row = {
                    "technique": h.technique_id,
                    "source_account": h.source_account,
                    "source_host": h.source_host,
                    "target_host": h.target_host,
                    "legacy_filter_drop": id(h) not in kept,
                    "grounding": label,
                    "entity_binding": getattr(hl, "entity_binding", None),
                    "sse_verdict": vh.best_sse_verdict.value,
                    "path_confidence": round(vh.best_path_confidence, 6),
                    "n_paths": len(vh.sse_results),
                }
                if row["sse_verdict"] in FEASIBLE:
                    ranked = rank_actions(kg, sse, _candidate_actions(h), [h])
                    row["rsem_top"] = ranked[0].action.action_type.value
                    row["rsem_top_composite"] = round(ranked[0].composite_score, 6)
                    row["rsem_tied_top"] = sum(1 for s in ranked if s.composite_score == ranked[0].composite_score)
                    row["rsem_containment"] = {s.action.action_type.value: round(s.containment, 6) for s in ranked}
                    if guardrail:
                        rhr = rank_validated_hypotheses([vh], kg, sse, _candidate_actions(hl)).ranked[0]
                        row["guardrail_status"] = guardrail(rhr).overall_status.value
                hyp_rows.append(row)

            feasible = [r for r in hyp_rows if r["sse_verdict"] in FEASIBLE]
            out[aid] = {
                "hypotheses": hyp_rows,
                "no_actionable_pre": not feasible,
                "no_actionable_post_legacy": not [r for r in feasible if not r["legacy_filter_drop"]],
                "actionable_grounded": any(r["grounding"] != "ungrounded" for r in feasible),
                "actionable_ungrounded_only": bool(feasible) and all(r["grounding"] == "ungrounded" for r in feasible),
            }
            if decide:  # Phase 3 step 3.3+: alert-level outcome incl. known-bad escalation
                out[aid]["outcome"] = decide(alert, [r["guardrail_status"] for r in feasible if "guardrail_status" in r], kg).label
        snapshot["runs"][run] = out
    return snapshot


def summarize(snapshot: dict) -> None:
    for run, alerts in snapshot["runs"].items():
        n = len(alerts)
        pre = sum(a["no_actionable_pre"] for a in alerts.values())
        post = sum(a["no_actionable_post_legacy"] for a in alerts.values())
        ung = sum(a["actionable_ungrounded_only"] for a in alerts.values())
        verdicts = Counter((h["technique"] == "T1071", h["sse_verdict"]) for a in alerts.values() for h in a["hypotheses"])
        print(f"{run:<9} n={n:>3}  no-actionable pre={pre:>3} post(legacy filter)={post:>3}  "
              f"actionable-ungrounded-only={ung:>3}  "
              f"T1071 verdicts={dict((v, c) for (t, v), c in verdicts.items() if t)}  "
              f"non-T1071 feasible={sum(c for (t, v), c in verdicts.items() if not t and v in FEASIBLE)}")


def diff(old: dict, new: dict) -> int:
    changes = 0
    for run in old["runs"]:
        for aid, a in old["runs"][run].items():
            b = new["runs"][run].get(aid)
            for key in ("no_actionable_pre", "no_actionable_post_legacy", "actionable_grounded",
                        "actionable_ungrounded_only", "outcome"):
                if a.get(key) != b.get(key):
                    changes += 1
                    print(f"[{run}] {aid} {key}: {a.get(key)} -> {b.get(key)}")
            for i, (ha, hb) in enumerate(zip(a["hypotheses"], b["hypotheses"])):
                for key in ("sse_verdict", "path_confidence", "n_paths", "grounding", "entity_binding",
                            "rsem_top", "rsem_tied_top", "guardrail_status"):
                    if ha.get(key) != hb.get(key):
                        changes += 1
                        print(f"[{run}] {aid} hyp{i} {ha['technique']} src={ha['source_host']!r} {key}: {ha.get(key)} -> {hb.get(key)}")
    print(f"TOTAL CHANGES: {changes}")
    return changes


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["--snapshot"] and len(args) == 2:
        snap = score_all()
        SNAP_DIR.mkdir(exist_ok=True)
        out = SNAP_DIR / f"{args[1]}.json"
        out.write_text(json.dumps(snap, indent=1), encoding="utf-8")
        summarize(snap)
        print(f"Wrote {out}")
    elif args[:1] == ["--diff"] and len(args) == 3:
        old = _load(SNAP_DIR / f"{args[1]}.json")
        new = _load(SNAP_DIR / f"{args[2]}.json")
        diff(old, new)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
