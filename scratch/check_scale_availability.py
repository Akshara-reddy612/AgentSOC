"""
Verify held-out dataset has at least 10 alerts per target family, 
list alert_ids per family, and check how many are already used in NCE-7.
"""
import json

# Load datasets
with open("GUIDE_Dataset/processed/guide_heldout_140_alerts.json", encoding="utf-8") as f:
    heldout = json.load(f)

with open("GUIDE_Dataset/processed/guide_sample_500_alerts.json", encoding="utf-8") as f:
    sample500 = json.load(f)

# Already-used alert IDs from NCE-7
USED_IDS = {
    "1073741825161", "1108101567282", "1322849928746", "1434519079553",
    "1322849930226", "360777252926", "566935683184", "146028890043",
    "1571958032528", "1185410973735"
}

TARGET_FAMILIES = [
    "fabricated_evidence", "cross_field_split", "authority_escalation",
    "direct_override", "zero_imperative_evidence", "native_format_mimicry",
    "fake_output_injection", "obfuscated_trigger"
]

print("=" * 80)
print("HELD-OUT 140 ALERTS — PER-FAMILY AVAILABILITY")
print("=" * 80)

for family in TARGET_FAMILIES:
    alerts = [a for a in heldout if a.get("_ground_truth_injection_category") == family]
    used = [a for a in alerts if str(a["alert_id"]) in USED_IDS]
    available = [a for a in alerts if str(a["alert_id"]) not in USED_IDS]
    print(f"{family}:")
    print(f"  Total: {len(alerts)}, Already used: {len(used)}, Available: {len(available)}")
    if used:
        print(f"  Used IDs: {[str(a['alert_id']) for a in used]}")
    print(f"  Available IDs: {[str(a['alert_id']) for a in available]}")
    print()

print("=" * 80)
print("SAMPLE-500 CLEAN ALERTS")
print("=" * 80)
clean = [a for a in sample500 if not a.get("_ground_truth_is_contaminated")]
clean_used = [a for a in clean if str(a["alert_id"]) in USED_IDS]
clean_available = [a for a in clean if str(a["alert_id"]) not in USED_IDS]
print(f"Total clean: {len(clean)}")
print(f"Already used: {len(clean_used)} — IDs: {[str(a['alert_id']) for a in clean_used]}")
print(f"Available: {len(clean_available)}")
