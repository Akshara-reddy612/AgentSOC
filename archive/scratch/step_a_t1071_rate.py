"""
Step A: Per-family T1071 hypothesis generation rate.
How often does NCE generate T1071 hypotheses, by family?
"""
import json

with open("agent/nce7_scale_results.json", encoding="utf-8") as f:
    results = json.load(f)

FAMILIES = [
    "fabricated_evidence", "cross_field_split", "authority_escalation",
    "direct_override", "zero_imperative_evidence", "native_format_mimicry",
    "fake_output_injection", "obfuscated_trigger", "clean"
]

print("=" * 90)
print("STEP A: T1071 HYPOTHESIS GENERATION RATE PER FAMILY")
print("=" * 90)
print(f"\n{'Family':28s}  {'n':>3}  {'has_T1071':>9}  {'T1071_count':>11}  {'rate':>8}  {'defense_fails':>13}")
print("-" * 85)

for fam in FAMILIES:
    alerts = [r for r in results if r["family"] == fam]
    n = len(alerts)
    has_t1071 = 0
    t1071_total = 0
    defense_fails = 0
    
    for r in alerts:
        hyps = r.get("nce_hypotheses", [])
        t1071_in_alert = sum(1 for h in hyps if h.get("technique_id") == "T1071")
        if t1071_in_alert > 0:
            has_t1071 += 1
        t1071_total += t1071_in_alert
        if r.get("structural_defense_success") is False:
            defense_fails += 1
    
    rate = f"{has_t1071}/{n}" if n > 0 else "N/A"
    pct = f"({has_t1071/n*100:.0f}%)" if n > 0 else ""
    fail_str = str(defense_fails) if fam != "clean" else "N/A"
    print(f"{fam:28s}  {n:>3}  {has_t1071:>9}  {t1071_total:>11}  {rate:>5} {pct:>4}  {fail_str:>13}")

print()
print("KEY INSIGHT: If has_T1071 == defense_fails for every family,")
print("then T1071 generation is the SOLE determinant of defense failure.")
print()

# Verify: for every FAIL, was there a T1071 hypothesis?
all_fails = [r for r in results if r.get("structural_defense_success") is False]
fails_with_t1071 = sum(1 for r in all_fails 
                       if any(h.get("technique_id") == "T1071" for h in r.get("nce_hypotheses", [])))
fails_without_t1071 = len(all_fails) - fails_with_t1071
print(f"Total defense failures: {len(all_fails)}")
print(f"  With T1071 hypothesis: {fails_with_t1071}")
print(f"  Without T1071 hypothesis: {fails_without_t1071}")
print()

# Also check: were there alerts WITH T1071 that still SUCCEEDED?
# (This would mean T1071 was generated but SSE said INFEASIBLE — 
#  possible if the host was in a zone WITHOUT web egress)
all_contam = [r for r in results if r["family"] != "clean"]
has_t1071_succeeded = sum(1 for r in all_contam
                         if r.get("structural_defense_success") is True
                         and any(h.get("technique_id") == "T1071" for h in r.get("nce_hypotheses", [])))
print(f"Alerts with T1071 that STILL succeeded (defense held): {has_t1071_succeeded}")
if has_t1071_succeeded > 0:
    print("  These would be cases where the host was NOT in a web-egress zone.")
    for r in all_contam:
        if (r.get("structural_defense_success") is True
            and any(h.get("technique_id") == "T1071" for h in r.get("nce_hypotheses", []))):
            sse = r.get("sse_results", [])
            t1071_sse = [s for s in sse if s["technique_id"] == "T1071"]
            print(f"    {r['family']:28s} alert={r['alert_id']} T1071 SSE verdicts: "
                  + ", ".join(f"{s['sse_verdict']}(target={s['target_host']},pconf={s['path_confidence']})" 
                              for s in t1071_sse))
