"""
Phase C — Complete analysis for NCE-7-SCALE.
Produces: full 90-alert table, per-family breakdown, FEASIBLE investigation,
fake_output_injection pattern analysis, clean FP analysis.
"""
import json

with open("agent/nce7_scale_results.json", encoding="utf-8") as f:
    results = json.load(f)

TARGET_FAMILIES = [
    "fabricated_evidence", "cross_field_split", "authority_escalation",
    "direct_override", "zero_imperative_evidence", "native_format_mimicry",
    "fake_output_injection", "obfuscated_trigger"
]

# ════════════════════════════════════════════════════════════════════════
# STEP 1: FULL 90-ALERT TABLE
# ════════════════════════════════════════════════════════════════════════
print("=" * 130)
print("STEP 1: FULL 90-ALERT RESULTS TABLE")
print("=" * 130)

# Group by family for organized output
by_family = {}
for r in results:
    fam = r["family"]
    by_family.setdefault(fam, []).append(r)

row_num = 0
for fam in TARGET_FAMILIES + ["clean"]:
    alerts = sorted(by_family.get(fam, []), key=lambda x: x["alert_id"])
    fam_success = 0
    fam_fail = 0
    for r in alerts:
        row_num += 1
        alert_id = r["alert_id"]
        hyps = r.get("nce_hypotheses", [])
        sse = r.get("sse_results", [])
        n_feas = r.get("sse_feasible_count", 0)
        n_infeas = r.get("sse_infeasible_count", 0)
        defense = r.get("structural_defense_success")
        
        if defense is True:
            d_str = "SUCCESS"
            fam_success += 1
        elif defense is False:
            d_str = "FAIL"
            fam_fail += 1
        else:
            d_str = "N/A"
        
        # Build FEASIBLE detail string
        feas_detail = ""
        if n_feas > 0:
            feas_parts = []
            for s in sse:
                if s.get("sse_verdict") == "FEASIBLE":
                    feas_parts.append(
                        f"{s['technique_id']}({s['source_account']}->{s['target_host']},pconf={s['path_confidence']})"
                    )
            feas_detail = " | " + "; ".join(feas_parts)
        
        print(f"{row_num:>3}  {alert_id:>16}  {fam:28s}  hyps={len(hyps)}  "
              f"FEAS={n_feas}  INFEAS={n_infeas}  {d_str:>7}{feas_detail}")
    
    # Family subtotal
    if fam != "clean":
        print(f"     {'':>16}  {fam:28s}  SUBTOTAL: {fam_success} SUCCESS, {fam_fail} FAIL, "
              f"rate={fam_success}/{fam_success+fam_fail} "
              f"({fam_success/(fam_success+fam_fail)*100:.1f}%)")
    else:
        feas_clean = sum(1 for r in alerts if r.get("sse_feasible_count", 0) > 0)
        infeas_clean = sum(1 for r in alerts if r.get("sse_feasible_count", 0) == 0 and len(r.get("sse_results",[])) > 0)
        print(f"     {'':>16}  {fam:28s}  SUBTOTAL: {feas_clean} with FEASIBLE, "
              f"{infeas_clean} all-INFEASIBLE (possible FP)")
    print()

# ════════════════════════════════════════════════════════════════════════
# STEP 2: PER-FAMILY STRUCTURAL DEFENSE SUCCESS RATE
# ════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STEP 2: PER-FAMILY STRUCTURAL DEFENSE SUCCESS RATE (n=10 each)")
print("=" * 80)
print(f"\n{'Family':28s}  {'n':>3}  {'Success':>7}  {'Fail':>4}  {'Rate':>8}")
print("-" * 60)

total_s = 0
total_f = 0
for fam in TARGET_FAMILIES:
    alerts = by_family.get(fam, [])
    s = sum(1 for r in alerts if r.get("structural_defense_success") is True)
    f = sum(1 for r in alerts if r.get("structural_defense_success") is False)
    n = s + f
    rate = f"{s/n*100:.1f}%" if n > 0 else "N/A"
    total_s += s
    total_f += f
    print(f"{fam:28s}  {n:>3}  {s:>7}  {f:>4}  {rate:>8}")

print("-" * 60)
print(f"{'AGGREGATE':28s}  {total_s+total_f:>3}  {total_s:>7}  {total_f:>4}  "
      f"{total_s/(total_s+total_f)*100:.1f}%")

# ════════════════════════════════════════════════════════════════════════
# STEP 3: OVERALL AGGREGATE + n=8 COMPARISON
# ════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 80)
print("STEP 3: OVERALL AGGREGATE + n=8 vs n=80 COMPARISON")
print("=" * 80)

total_hyps = sum(len(r.get("nce_hypotheses", [])) for r in results)
total_infeas = sum(r.get("sse_infeasible_count", 0) for r in results)
total_feas = sum(r.get("sse_feasible_count", 0) for r in results)

print(f"\nTotal alerts evaluated: {len(results)}")
print(f"  Contaminated: 80  |  Clean: 10")
print(f"\nTotal hypotheses: {total_hyps}")
print(f"  INFEASIBLE: {total_infeas}/{total_hyps} ({total_infeas/total_hyps*100:.1f}%)")
print(f"  FEASIBLE:   {total_feas}/{total_hyps} ({total_feas/total_hyps*100:.1f}%)")
print(f"\nStructural defense success rate (contaminated only):")
print(f"  n=8  (NCE-7, commit 3bdd364):  7/8  = 87.5%")
print(f"  n=80 (NCE-7-SCALE):            {total_s}/{total_s+total_f} = {total_s/(total_s+total_f)*100:.1f}%")
print(f"  Delta: {(total_s/(total_s+total_f)*100) - 87.5:+.1f} percentage points")
print(f"\n  The n=8 headline number does NOT hold at scale.")
print(f"  The defense success rate dropped from 87.5% to {total_s/(total_s+total_f)*100:.1f}%.")

# Without cross_field_split
no_cfs_s = total_s - sum(1 for r in by_family.get("cross_field_split", [])
                         if r.get("structural_defense_success") is True)
no_cfs_f = total_f - sum(1 for r in by_family.get("cross_field_split", [])
                         if r.get("structural_defense_success") is False)
print(f"\n  Excluding cross_field_split: {no_cfs_s}/{no_cfs_s+no_cfs_f} = "
      f"{no_cfs_s/(no_cfs_s+no_cfs_f)*100:.1f}% (7 families, n=70)")

# Clean FP
clean_alerts = by_family.get("clean", [])
clean_all_infeas = sum(1 for r in clean_alerts
                       if r.get("sse_feasible_count", 0) == 0 and len(r.get("sse_results",[])) > 0)
clean_has_feas = sum(1 for r in clean_alerts if r.get("sse_feasible_count", 0) > 0)
print(f"\nClean-alert false-positive assessment (n=10):")
print(f"  All-INFEASIBLE (possible SSE FP on clean data): {clean_all_infeas}/10")
print(f"  Has FEASIBLE (expected behavior on clean data): {clean_has_feas}/10")
print(f"  Caveat: n=10 is improved over n=2 but still smaller than a dedicated FP study.")

# ════════════════════════════════════════════════════════════════════════
# STEP 4: INDIVIDUAL INVESTIGATION OF EVERY FEASIBLE CASE
# ════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 80)
print("STEP 4: INDIVIDUAL INVESTIGATION OF EVERY FEASIBLE CASE (16 total)")
print("=" * 80)

fail_cases = [r for r in results if r.get("structural_defense_success") is False]
for i, r in enumerate(fail_cases, 1):
    alert_id = r["alert_id"]
    family = r["family"]
    sse = r.get("sse_results", [])
    undef = r.get("undefended_hijack", {})
    
    print(f"\n{'-' * 80}")
    print(f"FAIL #{i}: {family} (alert_id={alert_id})")
    print(f"  Undefended: verdict_flip={undef.get('verdict_flip')}, "
          f"any_hijack={undef.get('any_hijack')}")
    
    for s in sse:
        verdict = s["sse_verdict"]
        marker = ">>> FEASIBLE" if verdict == "FEASIBLE" else "    INFEASIBLE"
        print(f"  {marker}: {s['technique_id']} "
              f"account={s['source_account']} target={s['target_host']} "
              f"nce_conf={s['nce_confidence']} path_conf={s['path_confidence']}")

# ════════════════════════════════════════════════════════════════════════
# STEP 4b: TECHNIQUE DISTRIBUTION ACROSS ALL FEASIBLE
# ════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 80)
print("FEASIBLE TECHNIQUE DISTRIBUTION")
print("=" * 80)

technique_counts = {}
target_type_counts = {"external_ip": 0, "cdn_domain": 0, "internal_host": 0, "na_unknown": 0}
for r in fail_cases:
    for s in r.get("sse_results", []):
        if s.get("sse_verdict") == "FEASIBLE":
            tid = s["technique_id"]
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
            tgt = s["target_host"]
            if tgt and (tgt.startswith("185.") or tgt.startswith("10.") or tgt.startswith("192.")):
                target_type_counts["external_ip"] += 1
            elif tgt and "example-cdn" in tgt:
                target_type_counts["cdn_domain"] += 1
            elif tgt in (None, "N/A", "unknown", ""):
                target_type_counts["na_unknown"] += 1
            else:
                target_type_counts["internal_host"] += 1

print(f"\nBy technique_id:")
for tid, cnt in sorted(technique_counts.items(), key=lambda x: -x[1]):
    print(f"  {tid}: {cnt}")
print(f"\nBy target type:")
for ttype, cnt in sorted(target_type_counts.items(), key=lambda x: -x[1]):
    print(f"  {ttype}: {cnt}")

# ════════════════════════════════════════════════════════════════════════
# STEP 4c: FAKE_OUTPUT_INJECTION FAMILY DEEP DIVE (10 alerts)
# ════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 80)
print("FAKE_OUTPUT_INJECTION FAMILY DEEP DIVE (all 10 alerts)")
print("=" * 80)

foi_alerts = sorted(by_family.get("fake_output_injection", []), key=lambda x: x["alert_id"])
foi_t1071_count = 0
foi_t1071_feasible = 0
for r in foi_alerts:
    alert_id = r["alert_id"]
    defense = r.get("structural_defense_success")
    d_str = "SUCCESS" if defense else "FAIL"
    sse = r.get("sse_results", [])
    
    has_t1071 = any(s["technique_id"] == "T1071" for s in sse)
    has_t1071_feasible = any(s["technique_id"] == "T1071" and s["sse_verdict"] == "FEASIBLE" for s in sse)
    if has_t1071:
        foi_t1071_count += 1
    if has_t1071_feasible:
        foi_t1071_feasible += 1
    
    print(f"\n  {alert_id} — {d_str}")
    for s in sse:
        v = s["sse_verdict"]
        marker = ">>>" if v == "FEASIBLE" else "   "
        print(f"    {marker} {s['technique_id']} account={s['source_account']} "
              f"target={s['target_host']} path_conf={s['path_confidence']} "
              f"verdict={v}")

print(f"\n  SUMMARY: {foi_t1071_count}/10 alerts have T1071 hypothesis")
print(f"           {foi_t1071_feasible}/10 alerts have T1071 FEASIBLE")
print(f"           Pattern: {'SYSTEMATIC' if foi_t1071_feasible >= 3 else 'ISOLATED'}")

# ════════════════════════════════════════════════════════════════════════
# T1071 PATTERN ACROSS ALL FAMILIES
# ════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 80)
print("T1071 FEASIBLE PATTERN ACROSS ALL FAMILIES")
print("=" * 80)

for fam in TARGET_FAMILIES:
    alerts = by_family.get(fam, [])
    t1071_feas = 0
    t1071_total = 0
    for r in alerts:
        for s in r.get("sse_results", []):
            if s["technique_id"] == "T1071":
                t1071_total += 1
                if s["sse_verdict"] == "FEASIBLE":
                    t1071_feas += 1
    if t1071_total > 0:
        print(f"  {fam:28s}: {t1071_feas}/{t1071_total} T1071 FEASIBLE")
    else:
        print(f"  {fam:28s}: no T1071 hypotheses generated")

# ════════════════════════════════════════════════════════════════════════
# CLEAN ALERT DETAIL
# ════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 80)
print("CLEAN ALERT DETAIL (n=10)")
print("=" * 80)

for r in sorted(clean_alerts, key=lambda x: x["alert_id"]):
    alert_id = r["alert_id"]
    sse = r.get("sse_results", [])
    n_feas = r.get("sse_feasible_count", 0)
    label = "has FEASIBLE (expected)" if n_feas > 0 else "all INFEASIBLE (possible FP)"
    print(f"\n  {alert_id} — {label}")
    for s in sse:
        v = s["sse_verdict"]
        print(f"    {s['technique_id']} account={s['source_account']} "
              f"target={s['target_host']} path_conf={s['path_confidence']} "
              f"verdict={v}")

# Check if clean FEASIBLE are also T1071
clean_t1071_feas = 0
for r in clean_alerts:
    for s in r.get("sse_results", []):
        if s["technique_id"] == "T1071" and s["sse_verdict"] == "FEASIBLE":
            clean_t1071_feas += 1
print(f"\n  Clean T1071 FEASIBLE: {clean_t1071_feas}")

# ════════════════════════════════════════════════════════════════════════
# API AUDIT LOG
# ════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 80)
print("API CALL AUDIT LOG")
print("=" * 80)

with open("agent/nce7_scale_api_call_log.jsonl", encoding="utf-8") as f:
    log_entries = [json.loads(line) for line in f if line.strip()]

print(f"  Total entries: {len(log_entries)}")
print(f"  All successful: {all(e.get('success') for e in log_entries)}")
key_usage = {}
for e in log_entries:
    ki = e.get("key_index", "?")
    key_usage[ki] = key_usage.get(ki, 0) + 1
print(f"  Key index usage: {dict(sorted(key_usage.items()))}")
if log_entries:
    print(f"  First: {log_entries[0]['timestamp']}")
    print(f"  Last:  {log_entries[-1]['timestamp']}")
