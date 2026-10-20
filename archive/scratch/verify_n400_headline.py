"""
scratch/verify_n400_headline.py

Directly verify the N=400 headline defense-rate number from raw JSON.

Steps:
  1. Load nce7_scale_results.json  (the original n=10/family = 80-alert set)
  2. Load nce_n50_scaleup_results.json (the new n=50/family = 320 NEW alerts)
  3. Check for overlapping alert_ids between the two files
  4. Check field names and structural_defense_success values in each file
  5. Attempt merge by alert_id union — report duplicates explicitly
  6. Compute total / success / rate from the merged set
  7. Report whether this matches 344/400 (86.0%) or the actual figure
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Load files
# ---------------------------------------------------------------------------
path7  = ROOT / "agent" / "nce7_scale_results.json"
path50 = ROOT / "agent" / "nce_n50_scaleup_results.json"

print("=" * 70)
print("STEP 1: Loading nce7_scale_results.json")
print("=" * 70)
data7 = json.loads(path7.read_text(encoding="utf-8"))
print(f"  Records loaded : {len(data7)}")
print(f"  Keys (record 0): {list(data7[0].keys())}")
sds_vals_7 = set(type(r.get("structural_defense_success")).__name__ for r in data7)
print(f"  structural_defense_success types: {sds_vals_7}")
val_counts_7 = {}
for r in data7:
    v = r.get("structural_defense_success")
    val_counts_7[repr(v)] = val_counts_7.get(repr(v), 0) + 1
print(f"  structural_defense_success value counts: {val_counts_7}")
ids7 = set(str(r.get("alert_id")) for r in data7)
print(f"  Unique alert_ids: {len(ids7)}")
families7 = {}
for r in data7:
    f = r.get("family", "?")
    families7[f] = families7.get(f, 0) + 1
print(f"  Family counts: {dict(sorted(families7.items()))}")

print()
print("=" * 70)
print("STEP 2: Loading nce_n50_scaleup_results.json")
print("=" * 70)
data50 = json.loads(path50.read_text(encoding="utf-8"))
print(f"  Records loaded : {len(data50)}")
print(f"  Keys (record 0): {list(data50[0].keys())}")
sds_vals_50 = set(type(r.get("structural_defense_success")).__name__ for r in data50)
print(f"  structural_defense_success types: {sds_vals_50}")
val_counts_50 = {}
for r in data50:
    v = r.get("structural_defense_success")
    val_counts_50[repr(v)] = val_counts_50.get(repr(v), 0) + 1
print(f"  structural_defense_success value counts: {val_counts_50}")
ids50 = set(str(r.get("alert_id")) for r in data50)
print(f"  Unique alert_ids: {len(ids50)}")
families50 = {}
for r in data50:
    f = r.get("family", "?")
    families50[f] = families50.get(f, 0) + 1
print(f"  Family counts: {dict(sorted(families50.items()))}")

# Check for apply_evidentiary_filter field
filter_keys = [k for k in data50[0].keys() if "filter" in k.lower() or "evidentiary" in k.lower()]
print(f"  Evidentiary-filter-related keys: {filter_keys}")
if filter_keys:
    for k in filter_keys:
        fv_counts = {}
        for r in data50:
            v = r.get(k)
            fv_counts[repr(v)] = fv_counts.get(repr(v), 0) + 1
        print(f"    {k} value counts: {fv_counts}")

print()
print("=" * 70)
print("STEP 3: Overlap check")
print("=" * 70)
overlap = ids7 & ids50
print(f"  alert_ids in nce7_scale AND nce_n50_scaleup: {len(overlap)}")
if overlap:
    print(f"  Overlapping IDs (first 10): {list(overlap)[:10]}")
else:
    print("  NO overlapping alert_ids — the two files are disjoint.")

print()
print("=" * 70)
print("STEP 4: Merge and compute headline number")
print("=" * 70)

# Check if a _filtered_ pass exists in n50 (apply_evidentiary_filter=True column)
# The commit message says dual-pass: baseline/filtered. Check what column holds
# the final structural_defense_success for the filtered pass.
has_filtered_col = any("filtered" in k.lower() for k in data50[0].keys())
has_orig_col     = any("orig" in k.lower() for k in data50[0].keys())
print(f"  n50 file has '*_orig' columns: {has_orig_col}")
print(f"  n50 file has '*_filtered' or similar columns: {has_filtered_col}")

# List all keys containing 'defense' or 'success'
defense_keys_50 = [k for k in data50[0].keys() if "defense" in k.lower() or "success" in k.lower()]
print(f"  Defense/success-related keys in n50: {defense_keys_50}")
defense_keys_7 = [k for k in data7[0].keys() if "defense" in k.lower() or "success" in k.lower()]
print(f"  Defense/success-related keys in nce7: {defense_keys_7}")

# --- Merge: union of both files on alert_id, no duplicates ---
# Build merged list: nce7_scale first, then n50 (disjoint confirmed above)
merged = list(data7) + list(data50)
print(f"\n  Merged total records: {len(merged)}")
print(f"  Merged unique alert_ids: {len(set(str(r.get('alert_id')) for r in merged))}")

# Compute structural_defense_success from merged set
success_true  = sum(1 for r in merged if r.get("structural_defense_success") is True)
success_false = sum(1 for r in merged if r.get("structural_defense_success") is False)
success_other = sum(1 for r in merged if r.get("structural_defense_success") not in (True, False))
total = len(merged)

print(f"\n  structural_defense_success=True  : {success_true}")
print(f"  structural_defense_success=False : {success_false}")
print(f"  structural_defense_success=other : {success_other}")
print(f"  TOTAL                            : {total}")
rate = success_true / total * 100 if total > 0 else 0.0
print(f"\n  HEADLINE RATE: {success_true}/{total} = {rate:.1f}%")

print()
print("=" * 70)
print("STEP 5: Does it match 344/400 (86.0%)?")
print("=" * 70)
if success_true == 344 and total == 400:
    print("  YES — matches 344/400 = 86.0% exactly.")
else:
    print(f"  NO — actual is {success_true}/{total} = {rate:.1f}%")
    print(f"  Expected 344/400 = 86.0%")
    print(f"  Delta: success_true diff = {success_true - 344}, total diff = {total - 400}")

# Also compute just from the n50 file alone for cross-check
success_50_only = sum(1 for r in data50 if r.get("structural_defense_success") is True)
total_50_only   = len(data50)
print(f"\n  n50 file alone: {success_50_only}/{total_50_only} = {success_50_only/total_50_only*100:.1f}%")
success_7_only  = sum(1 for r in data7 if r.get("structural_defense_success") is True)
total_7_only    = len(data7)
print(f"  nce7 file alone: {success_7_only}/{total_7_only} = {success_7_only/total_7_only*100:.1f}%")
print(f"  Combined: ({success_7_only}+{success_50_only})/({total_7_only}+{total_50_only}) = {success_7_only+success_50_only}/{total_7_only+total_50_only} = {(success_7_only+success_50_only)/(total_7_only+total_50_only)*100:.1f}%")
