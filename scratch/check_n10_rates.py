import json
from pathlib import Path

ROOT = Path(r"c:\agentsoc")
file_path = ROOT / "agent" / "nce7_scale_results.json"

with open(file_path, "r", encoding="utf-8") as f:
    data = json.load(f)

print("=" * 80)
print("1. LOADING agent/nce7_scale_results.json (n=80 contaminated + 10 clean)")
print("=" * 80)
print(f"Total records loaded: {len(data)}")

families_to_check = [
    "cross_field_split",
    "fake_output_injection",
    "direct_override",
    "zero_imperative_evidence"
]

print("\n" + "=" * 80)
print("2 & 3. CHECKING SPECIFIC FAMILIES (BASELINE & FILTERED)")
print("=" * 80)

keys_in_file = list(data[0].keys())
print(f"Keys present in record 0: {keys_in_file}")
has_filtered = any("filter" in k.lower() or "orig" in k.lower() for k in keys_in_file)
print(f"File contains separate filtered/baseline pass? {has_filtered}")

print("-" * 60)
for family in families_to_check:
    family_data = [r for r in data if r.get("family") == family]
    n = len(family_data)
    
    success_count = sum(1 for r in family_data if r.get("structural_defense_success") is True)
    false_count = sum(1 for r in family_data if r.get("structural_defense_success") is False)
    
    rate = (success_count / n * 100) if n > 0 else 0
    print(f"Family: {family}")
    print(f"  n: {n}")
    print(f"  structural_defense_success=True: {success_count}")
    print(f"  structural_defense_success=False: {false_count}")
    print(f"  Rate: {rate:.1f}%")
    print("-" * 60)

print("\n" + "=" * 80)
print("4 & 5. CROSS-CHECKS (Hardcoded comparison output)")
print("=" * 80)
print("TABLE II CLAIMS:")
print("  cross_field_split=70.0%")
print("  fake_output_injection=78.0%")
print("  direct_override=88.0%")
print("  zero_imperative_evidence=84.0%")
print("\nDISCUSSION PARAGRAPH CLAIMS:")
print("  cross_field_split: 60.0% -> 82.0%")
print("  fake_output_injection: 70.0% -> 82.0%")
print("  direct_override: 100.0% at n=10, both baseline and filtered")
print("  zero_imperative_evidence: 100.0% at n=10 filtered, falling to 86.0%")
