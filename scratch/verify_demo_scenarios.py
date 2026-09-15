"""
scratch/verify_demo_scenarios.py

Independent verification of all 7 curated demo scenarios.

Imports load_scenario() from streamlit_app and validates that each
scenario loads correctly with all expected pipeline stage data.
No Streamlit dependency — this is pure data verification.

Run:  python -m scratch.verify_demo_scenarios
"""

from __future__ import annotations

import sys
import traceback

# Force UTF-8 stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def p(*args, **kwargs):
    """Flushing print."""
    print(*args, **kwargs, flush=True)


def verify_scenario(name: str, checks: list[tuple[str, callable]]) -> bool:
    """
    Load a scenario and run a list of named checks.

    Returns True if all checks pass.
    """
    from streamlit_app import load_scenario

    p(f"\n{'=' * 70}")
    p(f"  SCENARIO: {name}")
    p(f"{'=' * 70}")

    try:
        data = load_scenario(name)
    except Exception as e:
        p(f"  ❌ FAILED TO LOAD: {e}")
        traceback.print_exc()
        return False

    p(f"  Name: {data.get('name', '?')}")
    p(f"  Type: {data.get('scenario_type', '?')}")
    p(f"  Description: {data.get('description', '?')[:100]}...")

    all_passed = True
    for check_name, check_fn in checks:
        try:
            result = check_fn(data)
            if result:
                p(f"  ✓ {check_name}")
            else:
                p(f"  ❌ {check_name}")
                all_passed = False
        except Exception as e:
            p(f"  ❌ {check_name}: EXCEPTION — {e}")
            all_passed = False

    return all_passed


def main() -> None:
    p("=" * 70)
    p("  AGENTSOC 2.0 — DEMO SCENARIO VERIFICATION")
    p("=" * 70)

    results: dict[str, bool] = {}

    # =====================================================================
    # SCENARIO 1: Defended Contaminated Attack (Core Thesis)
    # =====================================================================
    results["1_defended_attack"] = verify_scenario("1_defended_attack", [
        ("Has raw alert data",
         lambda d: d.get("raw_alert") is not None),
        ("Alert is contaminated",
         lambda d: d.get("is_contaminated") is True),
        ("Injection category = fabricated_evidence",
         lambda d: d.get("injection_category") == "fabricated_evidence"),
        ("Has NCE hypotheses",
         lambda d: len(d.get("nce_hypotheses", [])) >= 1),
        ("Has SSE results",
         lambda d: len(d.get("sse_results", [])) >= 1),
        ("SSE: all INFEASIBLE (feas=0)",
         lambda d: d.get("sse_feasible_count") == 0),
        ("SSE: infeasible count >= 2",
         lambda d: d.get("sse_infeasible_count", 0) >= 2),
        ("RSEM not reached",
         lambda d: d.get("reached_rsem") is False),
        ("Has hijack data (verdict_flip)",
         lambda d: (isinstance(d.get("hijack_data"), dict)
                    and d["hijack_data"].get("any_hijack") is True)),
        ("Structural defense succeeded",
         lambda d: d.get("structural_defense_success") is True),
        ("No playbook (correct for INFEASIBLE)",
         lambda d: d.get("playbook") is None),
    ])

    # =====================================================================
    # SCENARIO 2: T1071 Structural Limitation
    # =====================================================================
    results["2_t1071_limitation"] = verify_scenario("2_t1071_limitation", [
        ("Has raw alert data",
         lambda d: d.get("raw_alert") is not None),
        ("Alert is contaminated",
         lambda d: d.get("is_contaminated") is True),
        ("Has NCE hypotheses",
         lambda d: len(d.get("nce_hypotheses", [])) >= 1),
        ("Has T1071 hypothesis",
         lambda d: any(h.get("technique_id") == "T1071"
                       for h in d.get("nce_hypotheses", []))),
        ("SSE: at least 1 FEASIBLE",
         lambda d: d.get("sse_feasible_count", 0) >= 1),
        ("T1071 SSE verdict = FEASIBLE",
         lambda d: any(r.get("technique_id") == "T1071"
                       and r.get("sse_verdict") == "FEASIBLE"
                       for r in d.get("sse_results", []))),
        ("RSEM reached",
         lambda d: d.get("reached_rsem") is True),
        ("Has RSEM results",
         lambda d: len(d.get("rsem_results", [])) >= 1),
        ("RSEM top action = MONITOR_ONLY",
         lambda d: (d.get("rsem_results", [{}])[0]
                     .get("ranked_actions", [{}])[0]
                     .get("action_type") == "MONITOR_ONLY")),
        ("Playbook computed",
         lambda d: d.get("playbook") is not None),
        ("Playbook status = AUTO_APPROVED or DRY_RUN_COMPLETE",
         lambda d: d.get("playbook", {}).get("overall_status") in
                   ("AUTO_APPROVED", "DRY_RUN_COMPLETE")),
    ])

    # =====================================================================
    # SCENARIO 3: Clean Alert, Correctly Handled
    # =====================================================================
    results["3_clean_correct"] = verify_scenario("3_clean_correct", [
        ("Has raw alert data",
         lambda d: d.get("raw_alert") is not None),
        ("Alert is NOT contaminated",
         lambda d: d.get("is_contaminated") is False),
        ("Has NCE hypotheses",
         lambda d: len(d.get("nce_hypotheses", [])) >= 1),
        ("No T1071 hypotheses",
         lambda d: not any(h.get("technique_id") == "T1071"
                           for h in d.get("nce_hypotheses", []))),
        ("SSE: all INFEASIBLE (feas=0)",
         lambda d: d.get("sse_feasible_count") == 0),
        ("SSE: infeasible count = 3",
         lambda d: d.get("sse_infeasible_count") == 3),
        ("RSEM not reached",
         lambda d: d.get("reached_rsem") is False),
        ("No playbook (correct for INFEASIBLE)",
         lambda d: d.get("playbook") is None),
    ])

    # =====================================================================
    # SCENARIO 4: Clean T1071 → Guardrail-Silence
    # =====================================================================
    results["4_t1071_guardrail_silence"] = verify_scenario("4_t1071_guardrail_silence", [
        ("Has raw alert data",
         lambda d: d.get("raw_alert") is not None),
        ("Alert is NOT contaminated",
         lambda d: d.get("is_contaminated") is False),
        ("Has T1071 hypothesis",
         lambda d: any(h.get("technique_id") == "T1071"
                       for h in d.get("nce_hypotheses", []))),
        ("SSE: at least 1 FEASIBLE (T1071)",
         lambda d: d.get("sse_feasible_count", 0) >= 1),
        ("RSEM reached",
         lambda d: d.get("reached_rsem") is True),
        ("RSEM top action = MONITOR_ONLY",
         lambda d: (d.get("rsem_results", [{}])[0]
                     .get("ranked_actions", [{}])[0]
                     .get("action_type") == "MONITOR_ONLY")),
        ("Playbook computed",
         lambda d: d.get("playbook") is not None),
        ("Guardrail-Silence: AUTO_APPROVED or DRY_RUN_COMPLETE",
         lambda d: d.get("playbook", {}).get("overall_status") in
                   ("AUTO_APPROVED", "DRY_RUN_COMPLETE")),
        ("Has dry-run report",
         lambda d: d.get("playbook", {}).get("dry_run_report") is not None),
    ])

    # =====================================================================
    # SCENARIO 5: Guardrail Hard-Floor (REVOKE_SESSION)
    # =====================================================================
    results["5_hard_floor"] = verify_scenario("5_hard_floor", [
        ("Scenario type = guardrail",
         lambda d: d.get("scenario_type") == "guardrail"),
        ("Has constructed params",
         lambda d: d.get("constructed_params") is not None),
        ("Hypothesis technique = T1550",
         lambda d: d.get("nce_hypotheses", [{}])[0].get("technique_id") == "T1550"),
        ("SSE: FEASIBLE",
         lambda d: d.get("sse_feasible_count", 0) >= 1),
        ("RSEM reached",
         lambda d: d.get("reached_rsem") is True),
        ("Playbook computed",
         lambda d: d.get("playbook") is not None),
        ("REVOKE_SESSION is top action",
         lambda d: d.get("playbook", {}).get("steps", [{}])[0]
                    .get("action_type") == "REVOKE_SESSION"),
        ("Status = PENDING_ANALYST_REVIEW",
         lambda d: d.get("playbook", {}).get("overall_status") ==
                   "PENDING_ANALYST_REVIEW"),
        ("Guardrail reason mentions hard floor",
         lambda d: "hard floor" in
                   d.get("playbook", {}).get("guardrail_decision_reason", "").lower()),
        ("Dry-run REFUSED",
         lambda d: "REFUSED" in
                   d.get("playbook", {}).get("dry_run_report", "")),
    ])

    # =====================================================================
    # SCENARIO 6: Guardrail BI Threshold (RESTRICT_PRIVILEGES)
    # =====================================================================
    results["6_threshold"] = verify_scenario("6_threshold", [
        ("Scenario type = guardrail",
         lambda d: d.get("scenario_type") == "guardrail"),
        ("Playbook computed",
         lambda d: d.get("playbook") is not None),
        ("RESTRICT_PRIVILEGES is top action",
         lambda d: d.get("playbook", {}).get("steps", [{}])[0]
                    .get("action_type") == "RESTRICT_PRIVILEGES"),
        ("Top action BI = 0.75",
         lambda d: abs(d.get("playbook", {}).get("steps", [{}])[0]
                        .get("business_impact", -1) - 0.75) < 0.01),
        ("Status = PENDING_ANALYST_REVIEW",
         lambda d: d.get("playbook", {}).get("overall_status") ==
                   "PENDING_ANALYST_REVIEW"),
        ("Guardrail reason mentions exceeds threshold",
         lambda d: "exceeds" in
                   d.get("playbook", {}).get("guardrail_decision_reason", "").lower()),
        ("Dry-run REFUSED",
         lambda d: "REFUSED" in
                   d.get("playbook", {}).get("dry_run_report", "")),
    ])

    # =====================================================================
    # SCENARIO 7: Guardrail Auto-Approve + Real Containment
    # =====================================================================
    results["7_auto_approve"] = verify_scenario("7_auto_approve", [
        ("Scenario type = guardrail",
         lambda d: d.get("scenario_type") == "guardrail"),
        ("Playbook computed",
         lambda d: d.get("playbook") is not None),
        ("RESTRICT_PRIVILEGES is top action",
         lambda d: d.get("playbook", {}).get("steps", [{}])[0]
                    .get("action_type") == "RESTRICT_PRIVILEGES"),
        ("Top action BI = 0.0 (account-targeted)",
         lambda d: abs(d.get("playbook", {}).get("steps", [{}])[0]
                        .get("business_impact", -1)) < 0.01),
        ("Status = DRY_RUN_COMPLETE",
         lambda d: d.get("playbook", {}).get("overall_status") ==
                   "DRY_RUN_COMPLETE"),
        ("Guardrail = Auto-approved",
         lambda d: "Auto-approved" in
                   d.get("playbook", {}).get("guardrail_decision_reason", "")),
        ("Has dry-run report with edge diff",
         lambda d: ("DRY-RUN" in
                    d.get("playbook", {}).get("dry_run_report", "")
                    and len(d.get("playbook", {}).get("dry_run_report", "")) > 100)),
        ("Has ENABLE_MFA policy step (T1550 is credential-relevant)",
         lambda d: any(s.get("is_policy_action") and s.get("action_type") == "ENABLE_MFA"
                       for s in d.get("playbook", {}).get("steps", []))),
        ("Playbook has 2 steps (RSEM + MFA policy)",
         lambda d: len(d.get("playbook", {}).get("steps", [])) == 2),
    ])

    # =====================================================================
    # SUMMARY
    # =====================================================================
    p()
    p("=" * 70)
    p("  VERIFICATION SUMMARY")
    p("=" * 70)

    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed

    for name, ok in results.items():
        status = "✓ PASS" if ok else "❌ FAIL"
        p(f"  {status}  {name}")

    p()
    p(f"  {passed}/{total} scenarios verified successfully.")

    if failed > 0:
        p(f"  ❌ {failed} scenario(s) FAILED — review output above.")
        sys.exit(1)
    else:
        p(f"  ✓ All {total} scenarios verified — data layer is correct.")
        sys.exit(0)


if __name__ == "__main__":
    main()
