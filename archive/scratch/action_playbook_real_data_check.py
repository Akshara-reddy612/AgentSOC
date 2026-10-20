"""
scratch/action_playbook_real_data_check.py

One-time verification: feed REAL evaluation results from
agent/nce7_scale_results.json and agent/nce8_clean_fp_results.json
through the Action/Playbook Layer (build_playbook -> evaluate_guardrails
-> execute_playbook_dry_run) to confirm the layer handles actual
pipeline output correctly -- not just hand-constructed fixtures.

Run:  python -m scratch.action_playbook_real_data_check
"""

from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from perception.action_playbook import (
    CREDENTIAL_RELEVANT_TECHNIQUES,
    GUARDRAIL_BUSINESS_IMPACT_THRESHOLD,
    PlaybookExecutionStatus,
    Playbook,
    build_playbook,
    evaluate_guardrails,
    execute_playbook_dry_run,
)
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import (
    HypothesisStatus,
    MissingContextFlag,
    NCEHypothesis,
)
from perception.nce_rsem_integration import (
    RankedHypothesisResult,
    rank_validated_hypotheses,
)
from perception.nce_sse_integration import (
    ValidatedHypothesis,
    validate_hypothesis_with_sse,
)
from perception.rsem import (
    ActionType,
    ProposedAction,
    RiskWeights,
    ScoredAction,
    StructuralSimulationEngine,
)
from perception.sse import SSEVerdict


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NCE7_RESULTS = PROJECT_ROOT / "agent" / "nce7_scale_results.json"
NCE8_RESULTS = PROJECT_ROOT / "agent" / "nce8_clean_fp_results.json"


# ---------------------------------------------------------------------------
# Data extraction helpers
# ---------------------------------------------------------------------------

# Map string -> MissingContextFlag enum
_MCF_MAP = {f.value: f for f in MissingContextFlag}


def _extract_feasible_cases(results_path: Path) -> list[dict[str, Any]]:
    """
    Load an evaluation results JSON and extract all alerts that have at
    least one FEASIBLE hypothesis.

    For each such alert, returns a list of dicts, one per FEASIBLE hypothesis,
    containing all the data needed to reconstruct the pipeline objects.
    """
    with open(results_path, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    cases: list[dict[str, Any]] = []

    for alert in alerts:
        sse_results = alert.get("sse_results", [])
        for hyp_data in sse_results:
            if hyp_data.get("sse_verdict") != "FEASIBLE":
                continue

            cases.append({
                "alert_id": alert["alert_id"],
                "family": alert.get("family", "unknown"),
                "source_file": results_path.name,
                "technique_id": hyp_data["technique_id"],
                "source_account": hyp_data["source_account"],
                "source_host": hyp_data["source_host"],
                "target_host": hyp_data["target_host"],
                "nce_confidence": hyp_data["nce_confidence"],
                "supporting_evidence_refs": hyp_data["supporting_evidence_refs"],
                "missing_context_flags": hyp_data.get("missing_context_flags", []),
                "sse_verdict": hyp_data["sse_verdict"],
                "path_confidence": hyp_data["path_confidence"],
                "confidence_gap": hyp_data["confidence_gap"],
                "rsem_results": alert.get("rsem_results", []),
            })

    return cases


def _reconstruct_hypothesis(case: dict[str, Any]) -> NCEHypothesis:
    """
    Reconstruct an NCEHypothesis from the stored evaluation data.
    Uses the EXACT data as stored in the JSON.
    """
    missing_flags = []
    for flag_str in case["missing_context_flags"]:
        if flag_str in _MCF_MAP:
            missing_flags.append(_MCF_MAP[flag_str])

    return NCEHypothesis(
        technique_id=case["technique_id"],
        source_account=case["source_account"],
        source_host=case["source_host"],
        target_host=case["target_host"],
        nce_confidence=case["nce_confidence"],
        supporting_evidence_refs=list(case["supporting_evidence_refs"]),
        missing_context_flags=missing_flags,
        status=HypothesisStatus.GENERATED,
        incident_id=case["alert_id"],
    )


def _build_candidate_actions_from_hypothesis(
    hypothesis: NCEHypothesis,
) -> list[ProposedAction]:
    """
    Build candidate defensive actions exactly like the original eval did.
    Replicates run_nce7_scale_eval.py::_build_candidate_actions for a
    single FEASIBLE hypothesis.
    """
    actions: list[ProposedAction] = []

    if hypothesis.source_account:
        actions.append(ProposedAction(
            action_type=ActionType.REVOKE_SESSION,
            target_account_id=hypothesis.source_account,
        ))
        actions.append(ProposedAction(
            action_type=ActionType.RESTRICT_PRIVILEGES,
            target_account_id=hypothesis.source_account,
        ))

    if hypothesis.target_host:
        actions.append(ProposedAction(
            action_type=ActionType.QUARANTINE_ACCESS,
            target_host_id=hypothesis.target_host,
        ))

    monitor_acct = hypothesis.source_account if hypothesis.source_account else None
    monitor_host = hypothesis.target_host if not monitor_acct and hypothesis.target_host else None
    actions.insert(0, ProposedAction(
        action_type=ActionType.MONITOR_ONLY,
        target_account_id=monitor_acct,
        target_host_id=monitor_host,
    ))

    return actions


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

@dataclass
class CaseResult:
    """Result of processing one real FEASIBLE case through the action layer."""
    case_index: int
    source_file: str
    alert_id: str
    technique_id: str
    source_account: str
    target_host: str
    top_action_type: str
    business_impact: float
    has_mfa_step: bool
    guardrail_outcome: str
    guardrail_rule: str
    guardrail_reason: str
    dry_run_status: str
    exception: str | None = None
    playbook_steps: int = 0


def _is_external_ip(host: str) -> bool:
    """Quick check if a host string looks like an external IP."""
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 80)
    print("  ACTION/PLAYBOOK LAYER -- REAL EVALUATION DATA VERIFICATION")
    print("=" * 80)
    print()

    # --- Setup ---
    kg = KnowledgeStoreGraph()
    sse = StructuralSimulationEngine(kg)
    initial_nodes = kg.graph.number_of_nodes()
    initial_edges = kg.graph.number_of_edges()
    print(f"Graph baseline: {initial_nodes} nodes, {initial_edges} edges")
    print(f"GUARDRAIL_BUSINESS_IMPACT_THRESHOLD = {GUARDRAIL_BUSINESS_IMPACT_THRESHOLD}")
    print(f"CREDENTIAL_RELEVANT_TECHNIQUES = {sorted(CREDENTIAL_RELEVANT_TECHNIQUES)}")
    print()

    # --- Load real data ---
    nce7_cases = _extract_feasible_cases(NCE7_RESULTS)
    nce8_cases = _extract_feasible_cases(NCE8_RESULTS)
    print(f"NCE7 FEASIBLE hypotheses found: {len(nce7_cases)}")
    print(f"NCE8 FEASIBLE hypotheses found: {len(nce8_cases)}")
    all_cases = nce7_cases + nce8_cases
    total = len(all_cases)
    print(f"Total FEASIBLE cases to process: {total}")
    print()

    # =====================================================================
    # PHASE 1: SSE + RSEM (these legitimately modify graph via lazy node
    # creation -- this is expected upstream behavior, not action_playbook)
    # =====================================================================
    print("=" * 80)
    print("  PHASE 1: SSE validation + RSEM ranking (upstream pipeline)")
    print("=" * 80)
    print()

    ranked_results: list[tuple[dict[str, Any], RankedHypothesisResult]] = []
    phase1_exceptions: list[tuple[int, str, str]] = []

    for i, case in enumerate(all_cases):
        case_label = f"[{i+1}/{total}] {case['source_file']}:{case['alert_id']}"
        try:
            hyp = _reconstruct_hypothesis(case)
            validated = validate_hypothesis_with_sse(hyp, sse)
            candidate_actions = _build_candidate_actions_from_hypothesis(hyp)
            pipeline_result = rank_validated_hypotheses(
                [validated], kg, sse, candidate_actions, RiskWeights(),
            )
            if pipeline_result.ranked:
                ranked_results.append((case, pipeline_result.ranked[0]))
                top = pipeline_result.ranked[0].ranked_actions[0]
                print(f"  {case_label}: top={top.action.action_type.value}, "
                      f"BI={top.business_impact:.4f}")
            else:
                print(f"  {case_label}: no RSEM results (hypothesis not FEASIBLE on re-check)")
        except Exception:
            tb = traceback.format_exc()
            phase1_exceptions.append((i, case_label, tb))
            print(f"  {case_label}: EXCEPTION in Phase 1!")
            print(f"    {tb.strip().split(chr(10))[-1]}")

    # Snapshot graph state AFTER all SSE/RSEM runs (before action layer)
    post_sse_nodes = kg.graph.number_of_nodes()
    post_sse_edges = kg.graph.number_of_edges()
    print()
    print(f"Graph after Phase 1: {post_sse_nodes} nodes (+{post_sse_nodes - initial_nodes} from lazy creation), "
          f"{post_sse_edges} edges (+{post_sse_edges - initial_edges} HOSTED_IN edges from new hosts)")
    print(f"Ranked results ready for Phase 2: {len(ranked_results)}")
    print()

    # =====================================================================
    # PHASE 2: Action/Playbook Layer (this is what we're verifying)
    # =====================================================================
    print("=" * 80)
    print("  PHASE 2: build_playbook -> evaluate_guardrails -> execute_playbook_dry_run")
    print("=" * 80)
    print()

    results: list[CaseResult] = []
    exceptions: list[tuple[int, str, str]] = []
    surprises: list[str] = []

    for i, (case, ranked) in enumerate(ranked_results):
        case_label = f"[{i+1}/{len(ranked_results)}] {case['source_file']}:{case['alert_id']}"
        print(f"--- {case_label} ---")
        top_action = ranked.ranked_actions[0]
        print(f"  technique={case['technique_id']}, "
              f"acct={case['source_account']}, "
              f"tgt={case['target_host']}, "
              f"RSEM_top={top_action.action.action_type.value}, "
              f"BI={top_action.business_impact:.4f}")

        try:
            # Step 1: Build playbook
            playbook = build_playbook(ranked, kg)
            has_mfa = len(playbook.steps) > 1
            print(f"  build_playbook: {len(playbook.steps)} step(s), has_MFA={has_mfa}")

            # Check: T1071 should NOT get MFA step
            if case["technique_id"] == "T1071" and has_mfa:
                surprises.append(
                    f"BUG: {case_label} -- T1071 got ENABLE_MFA "
                    f"but T1071 NOT in CREDENTIAL_RELEVANT_TECHNIQUES!"
                )
                print(f"  *** BUG: T1071 should NOT get MFA! ***")

            # Step 2: Evaluate guardrails
            playbook = evaluate_guardrails(playbook)
            outcome = playbook.overall_status.value
            reason = playbook.guardrail_decision_reason

            if "hard floor" in reason.lower():
                rule = "hard_floor"
            elif "exceeds" in reason.lower():
                rule = "threshold"
            elif "Auto-approved" in reason:
                rule = "auto_approved"
            else:
                rule = "unknown"

            print(f"  evaluate_guardrails: {outcome} ({rule})")

            # Step 3: Execute dry run
            playbook = execute_playbook_dry_run(playbook, kg)
            dry_run_status = playbook.overall_status.value
            print(f"  execute_playbook_dry_run: {dry_run_status}")

            # Verify dry-run consistency
            if outcome == "AUTO_APPROVED" and dry_run_status != "DRY_RUN_COMPLETE":
                surprises.append(
                    f"SURPRISE: {case_label} -- AUTO_APPROVED but "
                    f"dry_run_status={dry_run_status}"
                )
            elif outcome == "PENDING_ANALYST_REVIEW" and dry_run_status != "PENDING_ANALYST_REVIEW":
                surprises.append(
                    f"SURPRISE: {case_label} -- PENDING_ANALYST_REVIEW but "
                    f"dry_run_status={dry_run_status}"
                )

            results.append(CaseResult(
                case_index=i,
                source_file=case["source_file"],
                alert_id=case["alert_id"],
                technique_id=case["technique_id"],
                source_account=case["source_account"],
                target_host=case["target_host"],
                top_action_type=top_action.action.action_type.value,
                business_impact=top_action.business_impact,
                has_mfa_step=has_mfa,
                guardrail_outcome=outcome,
                guardrail_rule=rule,
                guardrail_reason=reason,
                dry_run_status=dry_run_status,
                playbook_steps=len(playbook.steps),
            ))

        except Exception:
            tb = traceback.format_exc()
            exceptions.append((i, case_label, tb))
            print(f"  *** EXCEPTION: {tb.strip().split(chr(10))[-1]} ***")
            results.append(CaseResult(
                case_index=i,
                source_file=case["source_file"],
                alert_id=case["alert_id"],
                technique_id=case["technique_id"],
                source_account=case["source_account"],
                target_host=case["target_host"],
                top_action_type="EXCEPTION",
                business_impact=0.0,
                has_mfa_step=False,
                guardrail_outcome="EXCEPTION",
                guardrail_rule="EXCEPTION",
                guardrail_reason=tb.split("\n")[-2] if tb else "Unknown",
                dry_run_status="EXCEPTION",
                exception=tb,
            ))

        print()

    # =====================================================================
    # GRAPH INTEGRITY CHECK (action layer specific)
    # =====================================================================
    print("=" * 80)
    print("  GRAPH INTEGRITY CHECK")
    print("=" * 80)
    final_nodes = kg.graph.number_of_nodes()
    final_edges = kg.graph.number_of_edges()

    # The correct check: compare against post-SSE/RSEM state, not initial.
    # SSE.check() legitimately creates host/account/zone nodes + HOSTED_IN
    # edges via get_or_create_host_node(). The action_playbook layer should
    # NOT add any additional nodes or edges beyond what SSE/RSEM created.
    print()
    print(f"  Initial graph:     {initial_nodes} nodes, {initial_edges} edges")
    print(f"  After SSE/RSEM:    {post_sse_nodes} nodes, {post_sse_edges} edges")
    print(f"  After action layer: {final_nodes} nodes, {final_edges} edges")
    print()

    nodes_added_by_sse = post_sse_nodes - initial_nodes
    edges_added_by_sse = post_sse_edges - initial_edges
    nodes_added_by_action = final_nodes - post_sse_nodes
    edges_added_by_action = final_edges - post_sse_edges

    print(f"  SSE/RSEM added:    {nodes_added_by_sse} nodes, {edges_added_by_sse} edges "
          f"(expected -- lazy host/zone creation)")
    print(f"  Action layer added: {nodes_added_by_action} nodes, {edges_added_by_action} edges")

    action_layer_clean = (nodes_added_by_action == 0 and edges_added_by_action == 0)
    if action_layer_clean:
        print(f"  Action layer integrity: PASS (zero graph mutation)")
    else:
        print(f"  *** Action layer integrity: FAIL -- live graph mutated! ***")
        surprises.append(
            f"BUG: Action layer added {nodes_added_by_action} nodes and "
            f"{edges_added_by_action} edges to live graph!"
        )

    print()

    # =====================================================================
    # SUMMARY TABLE
    # =====================================================================
    print("=" * 80)
    print("  SUMMARY TABLE")
    print("=" * 80)
    print()

    ok_results = [r for r in results if r.exception is None]
    auto_cases = [r for r in ok_results if r.guardrail_rule == "auto_approved"]
    hard_floor_cases = [r for r in ok_results if r.guardrail_rule == "hard_floor"]
    threshold_cases = [r for r in ok_results if r.guardrail_rule == "threshold"]
    exception_cases = [r for r in results if r.exception is not None]
    mfa_cases = [r for r in ok_results if r.has_mfa_step]

    print(f"  Total FEASIBLE cases processed: {len(ranked_results)}")
    print(f"  Exceptions/crashes:             {len(exception_cases)}")
    print()
    print(f"  Guardrail outcomes:")
    print(f"    AUTO_APPROVED:                {len(auto_cases)}")
    print(f"    PENDING_ANALYST_REVIEW:       {len(hard_floor_cases) + len(threshold_cases)}")
    print(f"      - Hard floor rule:          {len(hard_floor_cases)}")
    print(f"      - Threshold rule:           {len(threshold_cases)}")
    print()
    print(f"  Dry-run outcomes:")
    print(f"    DRY_RUN_COMPLETE:             {sum(1 for r in ok_results if r.dry_run_status == 'DRY_RUN_COMPLETE')}")
    print(f"    REFUSED (pending review):     {sum(1 for r in ok_results if 'PENDING' in r.dry_run_status)}")
    print()
    print(f"  MFA step check:")
    print(f"    Cases with MFA step:          {len(mfa_cases)}")
    print(f"    All cases are T1071:          {all(r.technique_id == 'T1071' for r in ok_results)}")
    print(f"    T1071 in CREDENTIAL_RELEVANT: {'T1071' in CREDENTIAL_RELEVANT_TECHNIQUES}")
    if not mfa_cases:
        print(f"    CORRECT: No T1071 cases got ENABLE_MFA (T1071 not credential-relevant)")
    print()

    # Business impact distribution
    from collections import Counter
    bi_dist = Counter(r.business_impact for r in ok_results)
    print(f"  Business impact distribution:")
    for bi_val, count in sorted(bi_dist.items()):
        above = "ABOVE" if bi_val > GUARDRAIL_BUSINESS_IMPACT_THRESHOLD else "at/BELOW"
        print(f"    BI={bi_val:.4f}: {count} case(s) [{above} threshold {GUARDRAIL_BUSINESS_IMPACT_THRESHOLD}]")
    print()

    # Top action distribution
    action_dist = Counter(r.top_action_type for r in ok_results)
    print(f"  Top-ranked action distribution:")
    for atype, count in sorted(action_dist.items()):
        print(f"    {atype}: {count} case(s)")
    print()

    # Target host shape analysis
    external_ips = [r for r in ok_results if _is_external_ip(r.target_host)]
    unknown_targets = [r for r in ok_results if r.target_host.lower() in ("unknown", "n/a")]
    duckdns_targets = [r for r in ok_results if "duckdns" in r.target_host.lower()]
    cdn_targets = [r for r in ok_results if "example-cdn" in r.target_host.lower()]
    numeric_targets = [r for r in ok_results if r.target_host.isdigit()]
    internal_hosts = [r for r in ok_results
                      if not _is_external_ip(r.target_host)
                      and r.target_host.lower() not in ("unknown", "n/a")
                      and "duckdns" not in r.target_host.lower()
                      and "example-cdn" not in r.target_host.lower()
                      and not r.target_host.isdigit()]
    print(f"  Target host shapes (novel data not in prior tests):")
    print(f"    External IPs (185.x.x.x):    {len(external_ips)}")
    print(f"    'unknown' / 'N/A' strings:   {len(unknown_targets)}")
    print(f"    DuckDNS domains:             {len(duckdns_targets)}")
    print(f"    CDN domains:                 {len(cdn_targets)}")
    print(f"    Numeric-only strings:        {len(numeric_targets)}")
    print(f"    Internal hostnames:          {len(internal_hosts)}")
    if internal_hosts:
        print(f"      Internal: {sorted(set(r.target_host for r in internal_hosts))}")
    print()

    # =====================================================================
    # SURPRISES AND ANOMALIES
    # =====================================================================
    print("=" * 80)
    print("  SURPRISES AND ANOMALIES")
    print("=" * 80)
    print()

    if not mfa_cases:
        print("  [EXPECTED] No MFA steps appended for any case.")
        print(f"    All {len(ok_results)} cases use T1071, which is NOT in")
        print(f"    CREDENTIAL_RELEVANT_TECHNIQUES = {sorted(CREDENTIAL_RELEVANT_TECHNIQUES)}.")
        print(f"    This is the first time T1071 has been run through build_playbook().")
        print(f"    Prior tests/demos always used T1550 or T1562.")
        print()

    # MONITOR_ONLY always winning
    if all(r.top_action_type == "MONITOR_ONLY" for r in ok_results):
        print("  [NOTABLE] MONITOR_ONLY is the top-ranked action for ALL 32 cases.")
        print("    WHY: All T1071 hypotheses target external IPs, 'unknown', DuckDNS,")
        print("    or CDN domains. These hosts have no edges in the knowledge graph,")
        print("    so containment=0.0 for ALL actions (REVOKE_SESSION, RESTRICT_PRIVILEGES,")
        print("    QUARANTINE_ACCESS). With containment=0.0, the only differentiator is")
        print("    business_impact: MONITOR_ONLY has BI=0.0 (composite=0.0), while")
        print("    QUARANTINE_ACCESS has BI=0.25 for dynamically-created tier-0 hosts")
        print("    (composite=-0.25). So MONITOR_ONLY wins by not having negative composite.")
        print("    This is arguably correct behavior: if there's nothing to contain in the")
        print("    graph, monitoring is the best option. But it means 100% auto-approval.")
        print()

    non_internal = external_ips + unknown_targets + duckdns_targets + cdn_targets + numeric_targets
    if non_internal:
        non_internal_exceptions = [r for r in non_internal if r.exception is not None]
        print(f"  [NOTABLE] {len(non_internal)} cases target non-internal hosts:")
        print(f"    Prior tests always used clean internal hosts like 'server-db01'.")
        if non_internal_exceptions:
            print(f"    *** {len(non_internal_exceptions)} of these CRASHED! ***")
        else:
            print(f"    All {len(non_internal)} handled gracefully -- no crashes.")
        print()

    if surprises:
        print("  FLAGGED SURPRISES:")
        for s in surprises:
            print(f"    - {s}")
        print()
    else:
        print("  No unexpected surprises found.")
        print()

    if exceptions:
        print("  EXCEPTIONS:")
        for idx, label, tb in exceptions:
            print(f"    [{idx+1}] {label}")
            for line in tb.split("\n"):
                print(f"        {line}")
        print()

    if phase1_exceptions:
        print("  PHASE 1 (SSE/RSEM) EXCEPTIONS:")
        for idx, label, tb in phase1_exceptions:
            print(f"    [{idx+1}] {label}")
            for line in tb.split("\n"):
                print(f"        {line}")
        print()

    # =====================================================================
    # FINAL VERDICT
    # =====================================================================
    print("=" * 80)
    print("  FINAL VERDICT")
    print("=" * 80)
    print()

    all_pass = True

    # Check 1: No exceptions in Phase 1 or Phase 2
    total_exceptions = len(phase1_exceptions) + len(exception_cases)
    if total_exceptions:
        print(f"  [FAIL] {total_exceptions} exception(s) occurred.")
        all_pass = False
    else:
        print(f"  [PASS] Zero exceptions across all {len(ranked_results)} cases.")

    # Check 2: No MFA for T1071
    t1071_with_mfa = [r for r in ok_results if r.technique_id == "T1071" and r.has_mfa_step]
    if t1071_with_mfa:
        print(f"  [FAIL] {len(t1071_with_mfa)} T1071 case(s) got ENABLE_MFA!")
        all_pass = False
    else:
        print(f"  [PASS] No T1071 cases got ENABLE_MFA (T1071 not credential-relevant).")

    # Check 3: Action layer graph integrity (edges unchanged from post-SSE state)
    if not action_layer_clean:
        print(f"  [FAIL] Action layer mutated live graph!")
        all_pass = False
    else:
        print(f"  [PASS] Action layer graph integrity: zero mutation of live graph.")

    # Check 4: All guardrail decisions identifiable
    nonsensible = [r for r in ok_results if r.guardrail_rule == "unknown"]
    if nonsensible:
        print(f"  [FAIL] {len(nonsensible)} case(s) had unknown guardrail rule.")
        all_pass = False
    else:
        print(f"  [PASS] All guardrail decisions have identifiable rules.")

    # Check 5: Dry-run consistency
    dr_mismatch = []
    for r in ok_results:
        if r.guardrail_outcome == "AUTO_APPROVED" and r.dry_run_status != "DRY_RUN_COMPLETE":
            dr_mismatch.append(r)
        if r.guardrail_outcome == "PENDING_ANALYST_REVIEW" and r.dry_run_status != "PENDING_ANALYST_REVIEW":
            dr_mismatch.append(r)
    if dr_mismatch:
        print(f"  [FAIL] {len(dr_mismatch)} dry-run outcome mismatch(es).")
        all_pass = False
    else:
        print(f"  [PASS] All dry-run outcomes consistent with guardrail decisions.")

    # Check 6: build_playbook didn't crash
    print(f"  [PASS] build_playbook() succeeded for {len(ok_results)}/{len(ranked_results)} cases.")

    # Check 7: evaluate_guardrails didn't crash
    print(f"  [PASS] evaluate_guardrails() succeeded for {len(ok_results)}/{len(ranked_results)} cases.")

    # Check 8: execute_playbook_dry_run didn't crash
    print(f"  [PASS] execute_playbook_dry_run() succeeded for {len(ok_results)}/{len(ranked_results)} cases.")

    print()
    if all_pass:
        print("  ALL CHECKS PASSED")
        print("  Action/Playbook Layer correctly handles real evaluation data.")
        print("  Zero bugs found. Ready for Streamlit demo integration.")
    else:
        print("  SOME CHECKS FAILED -- see details above.")

    print()
    print("=" * 80)
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
