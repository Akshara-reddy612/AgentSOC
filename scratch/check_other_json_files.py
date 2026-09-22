import json
from pathlib import Path

ROOT = Path(r"c:\agentsoc")
json_files = [
    "agent/subtle_scale_results.json",
    "agent/strongblunt_hardersubtle_scale_results.json",
    "agent/fabricated_evidence_scale_results.json",
    "agent/defended_recovery_results.json",
    "agent/defended_recovery_delta_results.json",
    "agent/nce_n50_scaleup_results.json"
]

families_to_check = [
    "cross_field_split",
    "fake_output_injection",
    "direct_override",
    "zero_imperative_evidence"
]

for j_file in json_files:
    file_path = ROOT / j_file
    if not file_path.exists():
        continue
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to load {j_file}: {e}")
        continue
        
    print(f"\n{'='*80}\nFILE: {j_file} (Records: {len(data)})\n{'='*80}")
    
    keys_in_file = list(data[0].keys())
    has_filtered = any("filter" in k.lower() or "orig" in k.lower() for k in keys_in_file)
    print(f"Has separate filtered/baseline pass? {has_filtered}")

    for family in families_to_check:
        family_data = [r for r in data if r.get("family") == family or r.get("injection_category") == family]
        n = len(family_data)
        if n == 0:
            continue
            
        success_field = "structural_defense_success"
        if success_field not in keys_in_file:
            success_field = [k for k in keys_in_file if "defense" in k.lower() or "success" in k.lower()]
            success_field = success_field[0] if success_field else None

        if success_field:
            success_count = sum(1 for r in family_data if r.get(success_field) is True)
            rate = (success_count / n * 100) if n > 0 else 0
            print(f"  {family}: n={n}, success={success_count}/{n} ({rate:.1f}%) [Field: {success_field}]")
        
        orig_field = "structural_defense_orig"
        if orig_field in keys_in_file:
            success_orig = sum(1 for r in family_data if r.get(orig_field) is True)
            rate_orig = (success_orig / n * 100) if n > 0 else 0
            print(f"  {family} (ORIG): n={n}, success={success_orig}/{n} ({rate_orig:.1f}%)")
