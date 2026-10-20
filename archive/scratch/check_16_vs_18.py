"""Final reconciliation using family field."""
import json
from collections import Counter

with open("agent/nce7_scale_results.json", "r") as f:
    alerts = json.load(f)

# Correct split: contaminated = family != 'clean'
contam = [a for a in alerts if a.get("family") != "clean"]
clean = [a for a in alerts if a.get("family") == "clean"]
print(f"Total: {len(alerts)}, Contaminated: {len(contam)}, Clean: {len(clean)}")

# Contaminated FEASIBLE
contam_feas = 0
contam_feas_hyps = 0
for a in contam:
    sse = a.get("sse_results", [])
    feas = [h for h in sse if h.get("sse_verdict") == "FEASIBLE"]
    if feas:
        contam_feas += 1
        contam_feas_hyps += len(feas)

# Clean FEASIBLE
clean_feas = 0
clean_feas_hyps = 0
for a in clean:
    sse = a.get("sse_results", [])
    feas = [h for h in sse if h.get("sse_verdict") == "FEASIBLE"]
    if feas:
        clean_feas += 1
        clean_feas_hyps += len(feas)

print(f"Contaminated: {contam_feas} alerts with FEASIBLE, {contam_feas_hyps} FEASIBLE hypotheses")
print(f"Clean: {clean_feas} alerts with FEASIBLE, {clean_feas_hyps} FEASIBLE hypotheses")
print(f"Total: {contam_feas + clean_feas} alerts, {contam_feas_hyps + clean_feas_hyps} hypotheses")

# Contaminated failures
contam_fail = sum(1 for a in contam if a.get("structural_defense_success") is False)
contam_success = sum(1 for a in contam if a.get("structural_defense_success") is True)
print(f"\nContaminated structural_defense_success: {contam_fail} fail, {contam_success} pass, total={contam_fail+contam_success}")

# Per-family table (contaminated only)
print("\nPer-family (contaminated only):")
fam_total = Counter(a.get("family","?") for a in contam)
fam_fail = Counter(a.get("family","?") for a in contam if a.get("structural_defense_success") is False)
fam_feas = Counter()
for a in contam:
    sse = a.get("sse_results", [])
    feas = [h for h in sse if h.get("sse_verdict") == "FEASIBLE"]
    if feas:
        fam_feas[a.get("family","?")] += 1

for fam in sorted(fam_total.keys()):
    print(f"  {fam}: n={fam_total[fam]}, fail={fam_fail.get(fam,0)}, feasible={fam_feas.get(fam,0)}")
print(f"  TOTAL: n={sum(fam_total.values())}, fail={sum(fam_fail.values())}, feasible={sum(fam_feas.values())}")

# Now check: the PROJECT_STATUS per-family table sums:
# fabricated_evidence:2, cross_field_split:6, authority_escalation:1,
# direct_override:0, zero_imperative_evidence:1, native_format_mimicry:1,
# fake_output_injection:3, obfuscated_trigger:2 = 16
# But this data shows fail=12, feasible=12
# The discrepancy is likely because the 10 reused NCE-7 alerts
# had 4 more failures that aren't in this JSON's failure field

# Check the original NCE-7 results
with open("agent/nce7_comparative_results.json", "r") as f:
    nce7_orig = json.load(f)

print(f"\nOriginal NCE-7 (n=10): {len(nce7_orig)} alerts")
for slot in nce7_orig:
    feas = slot.get("sse_feasible_count", 0)
    defense = slot.get("structural_defense_success", "?")
    family = slot.get("family", "?")
    if feas > 0 or defense is False:
        print(f"  Slot {slot.get('slot','?')}: family={family}, feas_count={feas}, defense_success={defense}")
