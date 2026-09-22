"""
scratch/verify_n400_headline_v2.py

Re-run with correct corpus definition.

Key finding from code inspection:
  - nce7_scale_results.json: 90 records = 80 contaminated + 10 clean
    * clean records have structural_defense_success=None (not counted in defense rate)
    * contaminated: 8 families x 10 alerts = 80 alerts
  - nce_n50_scaleup_results.json: 320 records = 8 families x 40 new alerts
    * ALL contaminated (no 'clean' family), structural_defense_success is always bool
    * structural_defense_success = post-evidentiary-filter result
  - N=400 corpus = 80 (contaminated from nce7) + 320 (all from n50) = 400

This script:
  1. Extracts only contaminated records from nce7_scale (family != 'clean')
  2. Confirms all 320 n50 records are contaminated
  3. Merges to 400 records
  4. Computes headline defense rate
  5. Cross-checks structural_defense_orig (baseline, pre-filter) vs
     structural_defense_success (filtered) in n50 records
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

data7  = json.loads((ROOT / "agent" / "nce7_scale_results.json").read_text(encoding="utf-8"))
data50 = json.loads((ROOT / "agent" / "nce_n50_scaleup_results.json").read_text(encoding="utf-8"))

print("=" * 70)
print("RAW FILE COUNTS")
print("=" * 70)
print(f"nce7_scale_results.json total records  : {len(data7)}")
print(f"nce_n50_scaleup_results.json total records: {len(data50)}")

# --- nce7: split contaminated vs clean ---
nce7_contaminated = [r for r in data7 if r.get("family") != "clean"]
nce7_clean        = [r for r in data7 if r.get("family") == "clean"]
print(f"\nnce7_scale: contaminated = {len(nce7_contaminated)}, clean = {len(nce7_clean)}")
nce7_families = {}
for r in nce7_contaminated:
    f = r.get("family", "?")
    nce7_families[f] = nce7_families.get(f, 0) + 1
print(f"nce7 contaminated family counts: {dict(sorted(nce7_families.items()))}")

nce7_sds = {"True":0, "False":0, "None":0}
for r in nce7_contaminated:
    nce7_sds[str(r.get("structural_defense_success"))] += 1
print(f"nce7 contaminated structural_defense_success: {nce7_sds}")

# --- n50: all should be contaminated ---
n50_families = {}
for r in data50:
    f = r.get("family", "?")
    n50_families[f] = n50_families.get(f, 0) + 1
print(f"\nn50 scaleup family counts: {dict(sorted(n50_families.items()))}")
n50_has_clean = any(r.get("family") == "clean" for r in data50)
print(f"n50 has 'clean' family records: {n50_has_clean}")

# --- Cross-check: are the 8 contamination families the same in both files? ---
fams7  = set(nce7_families.keys())
fams50 = set(n50_families.keys())
print(f"\nFamilies in nce7 contaminated: {sorted(fams7)}")
print(f"Families in n50 scaleup      : {sorted(fams50)}")
print(f"Families in nce7 but not n50 : {sorted(fams7 - fams50)}")
print(f"Families in n50 but not nce7 : {sorted(fams50 - fams7)}")

# --- Overlap check ---
ids7_contaminated = set(str(r.get("alert_id")) for r in nce7_contaminated)
ids50 = set(str(r.get("alert_id")) for r in data50)
overlap = ids7_contaminated & ids50
print(f"\nalert_id overlap between nce7-contaminated and n50: {len(overlap)}")

# --- MERGE: 80 contaminated from nce7 + 320 from n50 ---
merged = list(nce7_contaminated) + list(data50)
total = len(merged)
print(f"\n{'=' * 70}")
print(f"MERGED CORPUS: {len(nce7_contaminated)} (nce7 contaminated) + {len(data50)} (n50) = {total}")
print(f"{'=' * 70}")

# structural_defense_success (post-filter for n50, direct bool for nce7)
sds_true  = sum(1 for r in merged if r.get("structural_defense_success") is True)
sds_false = sum(1 for r in merged if r.get("structural_defense_success") is False)
sds_other = sum(1 for r in merged if r.get("structural_defense_success") not in (True, False))
print(f"structural_defense_success=True  : {sds_true}")
print(f"structural_defense_success=False : {sds_false}")
print(f"structural_defense_success=other : {sds_other}")
rate = sds_true / total * 100 if total > 0 else 0.0
print(f"\nHEADLINE (filtered): {sds_true}/{total} = {rate:.1f}%")

# --- Also compute BASELINE (pre-filter) rate from n50's structural_defense_orig ---
# nce7 doesn't have _orig; its structural_defense_success IS the baseline
nce7_base_true  = sum(1 for r in nce7_contaminated if r.get("structural_defense_success") is True)
nce7_base_false = sum(1 for r in nce7_contaminated if r.get("structural_defense_success") is False)
n50_orig_true   = sum(1 for r in data50 if r.get("structural_defense_orig") is True)
n50_orig_false  = sum(1 for r in data50 if r.get("structural_defense_orig") is False)
base_total_true  = nce7_base_true  + n50_orig_true
base_total_false = nce7_base_false + n50_orig_false
base_total       = len(nce7_contaminated) + len(data50)
base_rate = base_total_true / base_total * 100 if base_total > 0 else 0.0
print(f"\nBASELINE (pre-filter, nce7 direct + n50 structural_defense_orig):")
print(f"  nce7 contaminated: {nce7_base_true}/{len(nce7_contaminated)}")
print(f"  n50 orig         : {n50_orig_true}/{len(data50)}")
print(f"  BASELINE TOTAL   : {base_total_true}/{base_total} = {base_rate:.1f}%")

print(f"\n{'=' * 70}")
print("COMPARISON TO EXPECTED VALUES")
print(f"{'=' * 70}")
# Test various claimed figures
for claim_num, claim_den, claim_label in [
    (344, 400, "344/400 = 86.0% (commit message claimed)"),
    (326, 400, "326/400 = 81.5%"),
    (277, 320, "277/320 = 86.6% (n50 alone, filtered)"),
    (64, 80,   "64/80 = 80.0% (old nce7_scale headline, contaminated only)"),
]:
    match = (sds_true == claim_num and total == claim_den)
    print(f"  {claim_label}: {'MATCHES' if match else 'DOES NOT MATCH'}")

print(f"\nACTUAL RESULT (filtered): {sds_true}/{total} = {rate:.1f}%")
print(f"ACTUAL RESULT (baseline): {base_total_true}/{base_total} = {base_rate:.1f}%")

# Per-family breakdown for merged filtered corpus
print(f"\n{'=' * 70}")
print("PER-FAMILY BREAKDOWN (merged, filtered structural_defense_success)")
print(f"{'=' * 70}")
fam_merged = {}
for r in merged:
    f = r.get("family", "?")
    if f not in fam_merged:
        fam_merged[f] = {"total":0, "true":0, "false":0, "other":0}
    fam_merged[f]["total"] += 1
    sds = r.get("structural_defense_success")
    if sds is True:
        fam_merged[f]["true"] += 1
    elif sds is False:
        fam_merged[f]["false"] += 1
    else:
        fam_merged[f]["other"] += 1
print(f"  {'Family':30s} {'n':>4} {'True':>6} {'False':>6} {'Other':>6} {'Rate':>8}")
print("  " + "-" * 68)
for fam in sorted(fam_merged):
    d = fam_merged[fam]
    r_pct = d["true"]/d["total"]*100 if d["total"] > 0 else 0
    print(f"  {fam:30s} {d['total']:>4} {d['true']:>6} {d['false']:>6} {d['other']:>6} {r_pct:>7.1f}%")
print("  " + "-" * 68)
total_t = sum(d["total"] for d in fam_merged.values())
total_true = sum(d["true"] for d in fam_merged.values())
print(f"  {'TOTAL':30s} {total_t:>4} {total_true:>6}  (overall {total_true/total_t*100:.1f}%)")
