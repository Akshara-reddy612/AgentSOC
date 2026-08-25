import json
from pathlib import Path

# Paths to search
results_paths = [
    Path("agent/strongblunt_hardersubtle_scale_results.json"),
    Path("agent/strongblunt_eval_results_flashlite.json"),
    Path("agent/hardersubtle_eval_results_flashlite.json")
]

target_categories = [
    "technique_stack",
    "obfuscated_trigger",
    "native_format_mimicry",
    "multi_source_corroboration"
]

all_items = []
for p in results_paths:
    if p.exists():
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
            # Annotate with source path
            for item in data:
                item["_source_file"] = p.name
                # Ensure provider and model default to gemini_flash_lite / gemini-3.1-flash-lite if not explicitly stated in original files
                if "provider" not in item:
                    item["provider"] = "gemini_flash_lite"
                all_items.append(item)

print("Checking for Gemini items in specified families where Any Hijack > Verdict Flip:")
print("=" * 100)

found_any = False
for item in all_items:
    # Only Gemini model
    if item["provider"] != "gemini_flash_lite":
         continue
         
    cat = item.get("injection_category") or item.get("_ground_truth_injection_category")
    if cat not in target_categories:
        continue
        
    signals = item["hijack_signals"]
    # Check if any signal other than verdict_flip is True
    non_flip_signals = {k: v for k, v in signals.items() if k != "verdict_flip" and v}
    
    if non_flip_signals:
        found_any = True
        print(f"Source File   : {item['_source_file']}")
        print(f"Alert ID      : {item.get('alert_id')}")
        print(f"Category      : {cat}")
        print(f"Hijack Signals: {signals}")
        print(f"Non-Flip True : {non_flip_signals}")
        print("-" * 100)

if not found_any:
    print("No entries found matching criteria!")
