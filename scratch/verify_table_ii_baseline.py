"""
scratch/verify_table_ii_baseline.py

Directly verify Table II's per-family baseline rates from the merged 400-alert corpus.
"""

import json
from pathlib import Path

ROOT = Path(r"c:\agentsoc")

# 1. Load data
data7  = json.loads((ROOT / "agent" / "nce7_scale_results.json").read_text(encoding="utf-8"))
data50 = json.loads((ROOT / "agent" / "nce_n50_scaleup_results.json").read_text(encoding="utf-8"))

# 2. Extract contaminated from nce7, all from n50
nce7_contaminated = [r for r in data7 if r.get("family") != "clean"]
n50_contaminated = data50 # all are contaminated

# Table II's current baseline claims
table_ii_claims = {
    "fabricated_evidence": 78.0,
    "cross_field_split": 70.0,
    "authority_escalation": 90.0,
    "direct_override": 88.0,
    "zero_imperative_evidence": 84.0,
    "native_format_mimicry": 86.0,
    "fake_output_injection": 78.0,
    "obfuscated_trigger": 78.0,
}

# 3. Compute baseline metrics per family
print("=" * 80)
print("PER-FAMILY BASELINE BREAKDOWN (Merged 400-Alert Corpus)")
print("=" * 80)
print(f"  {'Family':30s} {'n':>4} {'True':>6} {'False':>6} {'Rate':>8}  {'Table II Claim':>20}")
print("-" * 80)

fam_merged = {}
all_fams = set(r.get("family") for r in nce7_contaminated) | set(r.get("family") for r in n50_contaminated)

for fam in all_fams:
    fam_merged[fam] = {"total": 0, "true": 0, "false": 0}

# nce7 base (baseline is structural_defense_success)
for r in nce7_contaminated:
    fam = r.get("family", "?")
    sds = r.get("structural_defense_success")
    fam_merged[fam]["total"] += 1
    if sds is True:
        fam_merged[fam]["true"] += 1
    elif sds is False:
        fam_merged[fam]["false"] += 1

# n50 base (baseline is structural_defense_orig)
for r in n50_contaminated:
    fam = r.get("family", "?")
    orig = r.get("structural_defense_orig")
    fam_merged[fam]["total"] += 1
    if orig is True:
        fam_merged[fam]["true"] += 1
    elif orig is False:
        fam_merged[fam]["false"] += 1

total_n = 0
total_true = 0

for fam in sorted(fam_merged.keys()):
    d = fam_merged[fam]
    rate = d["true"] / d["total"] * 100 if d["total"] > 0 else 0
    claim = table_ii_claims.get(fam, "N/A")
    match_str = "MATCH" if (claim != "N/A" and abs(rate - claim) < 0.1) else "DOES NOT MATCH"
    
    total_n += d["total"]
    total_true += d["true"]
    
    print(f"  {fam:30s} {d['total']:>4} {d['true']:>6} {d['false']:>6} {rate:>7.1f}%   {str(claim) + '%':>10s}  [{match_str}]")

print("-" * 80)
overall_rate = total_true / total_n * 100 if total_n > 0 else 0
print(f"  {'AGGREGATE BASELINE':30s} {total_n:>4} {total_true:>6} {'N/A':>6} {overall_rate:>7.1f}%")

print("\n" + "=" * 80)
print("FINAL VERDICT (Mismatch Summary & Corrected Values)")
print("=" * 80)
for fam in sorted(fam_merged.keys()):
    d = fam_merged[fam]
    rate = d["true"] / d["total"] * 100 if d["total"] > 0 else 0
    claim = table_ii_claims.get(fam)
    if claim is not None and abs(rate - claim) >= 0.1:
        print(f"  {fam}: DOES NOT MATCH (Table II: {claim:.1f}%, Actual: {rate:.1f}%)")
    elif claim is not None:
        print(f"  {fam}: MATCH (Actual: {rate:.1f}%)")

print("\nAll values were computed directly from nce7_scale_results.json (contaminated) + nce_n50_scaleup_results.json.")
