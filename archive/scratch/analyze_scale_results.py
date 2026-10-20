"""
Phase C — Detailed analysis of NCE-7-SCALE results.
Investigates each FAIL case individually, checks FP rate, confirms invariant.
"""
import json

with open("agent/nce7_scale_results.json", encoding="utf-8") as f:
    results = json.load(f)

print("=" * 90)
print("PHASE C ANALYSIS — NCE-7-SCALE (n=90)")
print("=" * 90)

# ── 1. ALL FAIL CASES — individual investigation ──────────────────────
print("\n" + "=" * 90)
print("SECTION 1: DETAILED FAIL ANALYSIS (16 contaminated alerts with FEASIBLE)")
print("=" * 90)

fail_cases = [r for r in results if r.get("structural_defense_success") is False]
for i, r in enumerate(fail_cases, 1):
    alert_id = r["alert_id"]
    family = r["family"]
    sse_results = r.get("sse_results", [])
    feasible = [s for s in sse_results if s.get("sse_verdict") == "FEASIBLE"]
    infeasible = [s for s in sse_results if s.get("sse_verdict") == "INFEASIBLE"]
    undef = r.get("undefended_hijack", {})
    
    print(f"\n--- FAIL #{i}: {family} (alert_id={alert_id}) ---")
    print(f"  Undefended: verdict_flip={undef.get('verdict_flip')}, any_hijack={undef.get('any_hijack')}")
    print(f"  Total hyps: {len(sse_results)}, FEASIBLE: {len(feasible)}, INFEASIBLE: {len(infeasible)}")
    for s in feasible:
        print(f"  >>> FEASIBLE: technique={s['technique_id']}, "
              f"account={s['source_account']}, target={s['target_host']}, "
              f"nce_conf={s['nce_confidence']}, path_conf={s['path_confidence']}, "
              f"gap={s['confidence_gap']:+.2f}")
    for s in infeasible:
        print(f"      INFEASIBLE: technique={s['technique_id']}, "
              f"account={s['source_account']}, target={s['target_host']}, "
              f"nce_conf={s['nce_confidence']}, path_conf={s['path_confidence']}")

# ── 2. FEASIBLE technique_id distribution ─────────────────────────────
print("\n\n" + "=" * 90)
print("SECTION 2: FEASIBLE TECHNIQUE DISTRIBUTION (across all 16 fails)")
print("=" * 90)

technique_counts = {}
target_patterns = {}
for r in fail_cases:
    for s in r.get("sse_results", []):
        if s.get("sse_verdict") == "FEASIBLE":
            tid = s["technique_id"]
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
            tgt = s["target_host"]
            target_patterns[tgt] = target_patterns.get(tgt, 0) + 1

print("\nFEASIBLE by technique_id:")
for tid, cnt in sorted(technique_counts.items(), key=lambda x: -x[1]):
    print(f"  {tid}: {cnt}")

print("\nFEASIBLE by target_host:")
for tgt, cnt in sorted(target_patterns.items(), key=lambda x: -x[1]):
    print(f"  {tgt}: {cnt}")

# ── 3. CROSS_FIELD_SPLIT deep dive (40% — worst family) ──────────────
print("\n\n" + "=" * 90)
print("SECTION 3: CROSS_FIELD_SPLIT DEEP DIVE (4/10 success, 6/10 fail)")
print("=" * 90)

cfs_alerts = [r for r in results if r["family"] == "cross_field_split"]
for r in sorted(cfs_alerts, key=lambda x: x["alert_id"]):
    defense = r.get("structural_defense_success")
    status = "SUCCESS" if defense else "FAIL"
    sse = r.get("sse_results", [])
    feas = [s for s in sse if s.get("sse_verdict") == "FEASIBLE"]
    print(f"\n  {r['alert_id']} — {status}")
    for s in sse:
        verdict = s["sse_verdict"]
        marker = ">>>" if verdict == "FEASIBLE" else "   "
        print(f"    {marker} {s['technique_id']} account={s['source_account']} "
              f"target={s['target_host']} path_conf={s['path_confidence']} "
              f"verdict={verdict}")

# ── 4. CLEAN ALERT FP ANALYSIS ────────────────────────────────────────
print("\n\n" + "=" * 90)
print("SECTION 4: CLEAN ALERT ANALYSIS (n=10)")
print("=" * 90)

clean = [r for r in results if r["family"] == "clean"]
for r in sorted(clean, key=lambda x: x["alert_id"]):
    sse = r.get("sse_results", [])
    n_feas = sum(1 for s in sse if s.get("sse_verdict") == "FEASIBLE")
    n_infeas = sum(1 for s in sse if s.get("sse_verdict") == "INFEASIBLE")
    fp_flag = "FP (all INFEASIBLE)" if n_feas == 0 and len(sse) > 0 else "OK (has FEASIBLE)"
    print(f"\n  {r['alert_id']} — {fp_flag}")
    for s in sse:
        verdict = s["sse_verdict"]
        print(f"    {s['technique_id']} account={s['source_account']} "
              f"target={s['target_host']} path_conf={s['path_confidence']} "
              f"verdict={verdict}")

# ── 5. COMPARISON: n=8 vs n=80 ────────────────────────────────────────
print("\n\n" + "=" * 90)
print("SECTION 5: n=8 vs n=80 COMPARISON")
print("=" * 90)
print(f"\n  n=8  (NCE-7):       7/8  = 87.5%")
print(f"  n=80 (NCE-7-SCALE): 64/80 = 80.0%")
print(f"  Delta: -7.5 percentage points")
print(f"  Direction: The defense rate DECREASED at scale")
print(f"  Key finding: cross_field_split at 40% drags the aggregate down significantly")
print(f"  Without cross_field_split: 60/70 = 85.7% (close to the n=8 result)")

# ── 6. API CALL AUDIT ─────────────────────────────────────────────────
print("\n\n" + "=" * 90)
print("SECTION 6: API CALL AUDIT LOG SUMMARY")
print("=" * 90)

with open("agent/nce7_scale_api_call_log.jsonl", encoding="utf-8") as f:
    log_entries = [json.loads(line) for line in f if line.strip()]

print(f"  Total API call log entries: {len(log_entries)}")
success_count = sum(1 for e in log_entries if e.get("success"))
fail_count = sum(1 for e in log_entries if not e.get("success"))
print(f"  Successful: {success_count}")
print(f"  Failed: {fail_count}")

key_usage = {}
for e in log_entries:
    ki = e.get("key_index", "?")
    key_usage[ki] = key_usage.get(ki, 0) + 1
print(f"  By key_index: {dict(sorted(key_usage.items()))}")

if log_entries:
    print(f"  First call: {log_entries[0]['timestamp']}")
    print(f"  Last call:  {log_entries[-1]['timestamp']}")

if __name__ == "__main__":
    pass
