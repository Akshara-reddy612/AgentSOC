"""
generate_strongblunt_hardersubtle_scale_42.py
---------------------------------------------
Generates guide_strongblunt_hardersubtle_scale_42_alerts.json — a 42-alert test subset
exercising the 6 strong-blunt and harder-subtle payload families:

  1. authority_escalation
  2. technique_stack
  3. obfuscated_trigger
  4. zero_imperative_evidence
  5. native_format_mimicry
  6. multi_source_corroboration

Pipeline:
  guide_sample_500.csv  ->  synth_fields.synthesize_dataframe()
                        ->  deterministic injection (seed=48)
                        ->  guide_to_alerts.convert_row()
                        ->  guide_strongblunt_hardersubtle_scale_42_alerts.json

Constraints:
  - seed=48
  - 42 alerts total, 7 per family
  - Verify zero alert_id overlap with the original 9+9 already tested.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).parent
RAW_CSV = HERE.parent / "raw" / "guide_sample_500" / "guide_sample_500.csv"
OUT_JSON = HERE / "guide_strongblunt_hardersubtle_scale_42_alerts.json"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent))

import pandas as pd
from synth_fields import synthesize_dataframe
from inject_payloads import (
    PAYLOADS,
    CROSS_FIELD_PAYLOADS,
    _rng as _make_rng
)
from guide_to_alerts import convert_row
from risk_assessment.exemplars import INJECTION_EXEMPLARS

FAMILIES = [
    "authority_escalation",
    "technique_stack",
    "obfuscated_trigger",
    "zero_imperative_evidence",
    "native_format_mimicry",
    "multi_source_corroboration",
]


def _inject_scale_42(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["raw_log_text_clean"] = df["raw_log_text"]

    cats, texts, flags = [], [], []
    reg_key_overrides = {}
    parent_process_overrides = {}

    for i, (idx, row) in enumerate(df.iterrows()):
        cat = FAMILIES[i % len(FAMILIES)]
        row_rng = _make_rng(row["Id"])

        if cat == "multi_source_corroboration":
            payloads_3 = [p for p in CROSS_FIELD_PAYLOADS if len(p) == 3]
            part_a_tmpl, part_b_tmpl, part_c = row_rng.choice(payloads_3)
            device = str(row.get("synth_device_name", "DEVICE-UNKNOWN"))
            process = str(row.get("synth_process_name", "proc-unknown"))
            part_a = part_a_tmpl.format(device=device, process=process)
            part_b = part_b_tmpl.format(device=device, process=process)
            reg_key_overrides[idx] = part_a
            parent_process_overrides[idx] = part_b
            new_text = f"{row['raw_log_text']} | {part_c}"
        else:
            template = row_rng.choice(PAYLOADS[cat])
            payload_text = template.format(n=row_rng.randint(1000, 9999))
            new_text = f"{row['raw_log_text']} | INJECTED_FIELD_VALUE=\"{payload_text}\""

        cats.append(cat)
        texts.append(new_text)
        flags.append(True)

    df["raw_log_text"] = texts
    df["is_contaminated"] = flags
    df["injection_category"] = cats

    for idx, new_key in reg_key_overrides.items():
        df.at[idx, "synth_registry_key"] = new_key
    for idx, new_parent in parent_process_overrides.items():
        df.at[idx, "synth_parent_process"] = new_parent

    return df


def main():
    print(f"Loading raw CSV: {RAW_CSV}")
    src = pd.read_csv(RAW_CSV)

    # Determine already tested alert IDs to exclude
    tested_ids = set()
    for filename in ["guide_strongblunt_9_alerts.json", "guide_hardersubtle_9_alerts.json"]:
        filepath = HERE / filename
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                for alert in data:
                    tested_ids.add(str(alert["alert_id"]))
        else:
            print(f"WARNING: Previously-tested file not found: {filepath}")

    print(f"Loaded {len(tested_ids)} previously-tested alert IDs to exclude.")

    # Filter candidates to avoid overlap
    src_filtered = src[~src["Id"].astype(str).isin(tested_ids)].reset_index(drop=True)
    print(f"Candidates remaining in guide_sample_500: {len(src_filtered)}")

    rng = random.Random(48)
    chosen_idx = rng.sample(range(len(src_filtered)), 42)
    subset = src_filtered.iloc[chosen_idx].reset_index(drop=True)
    print(f"Sampled 42 rows at indices from filtered pool (seed=48)")

    # Assert no overlap
    sampled_ids = set(subset["Id"].astype(str))
    overlap = sampled_ids.intersection(tested_ids)
    assert len(overlap) == 0, f"Error: Overlap detected! {overlap}"
    print("PASS: Verified zero alert_id overlap with previously-tested alerts.")

    synth = synthesize_dataframe(subset)
    contaminated = _inject_scale_42(synth)

    alerts = [convert_row(r) for _, r in contaminated.iterrows()]

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    print(f"Wrote {len(alerts)} alerts -> {OUT_JSON}")

    # Validation check for exemplars on all fields
    print("\nRunning validation check against exemplars...")
    violations = []
    for alert in alerts:
        cat = alert["_ground_truth_injection_category"]
        if cat not in ("obfuscated_trigger", "zero_imperative_evidence", "native_format_mimicry", "multi_source_corroboration"):
            continue
        fields_to_check = [
            alert.get("raw_log_line") or "",
            alert.get("registry_key") or "",
            alert.get("parent_process") or ""
        ]
        for field in fields_to_check:
            field_lower = field.lower()
            for phrase in INJECTION_EXEMPLARS:
                if phrase.lower() in field_lower:
                    violations.append((alert["alert_id"], cat, phrase))

    if violations:
        print("  FAIL: Found exemplar phrase matches in payload fields!")
        for aid, cat, phrase in violations:
            print(f"    Alert ID: {aid} ({cat}) matched phrase: '{phrase}'")
        sys.exit(1)
    else:
        print("  PASS: All payloads have ZERO literal matches in exemplars.")

    print("\n" + "="*70)
    print("EXAMPLE ALERTS (one per family)")
    print("="*70)
    for family in FAMILIES:
        ex = next((a for a in alerts if a["_ground_truth_injection_category"] == family), None)
        if ex:
            print(f"\n--- {family.upper()} ---")
            print(f"  alert_id       : {ex['alert_id']}")
            print(f"  registry_key   : {ex.get('registry_key', 'N/A')}")
            print(f"  parent_process : {ex.get('parent_process', 'N/A')}")
            print(f"  raw_log_line   : {ex.get('raw_log_line', 'N/A')}")


if __name__ == "__main__":
    main()
