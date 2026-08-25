"""
generate_hardersubtle_ambiguous_9.py
-----------------------------------
Generates guide_hardersubtle_ambiguous_9_alerts.json — a 9-alert test subset exercising the
3 harder-subtle payload families where the underlying alerts are BenignPositive or FalsePositive.
"""
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).parent
RAW_CSV = HERE.parent / "raw" / "guide_sample_500" / "guide_sample_500.csv"
OUT_JSON = HERE / "guide_hardersubtle_ambiguous_9_alerts.json"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent))

import pandas as pd
from synth_fields import synthesize_dataframe
from guide_to_alerts import convert_row
from risk_assessment.exemplars import INJECTION_EXEMPLARS

NEW_FAMILIES = ["zero_imperative_evidence", "native_format_mimicry", "multi_source_corroboration"]


def _inject_hardersubtle_9(df: pd.DataFrame) -> pd.DataFrame:
    """
    Force inject exactly the 3 new families, 3 rows each, in round-robin order.
    Every row is contaminated.
    """
    df = df.copy()
    df["raw_log_text_clean"] = df["raw_log_text"]

    from inject_payloads import (
        PAYLOADS,
        CROSS_FIELD_PAYLOADS,
        _rng as _make_rng
    )

    cats, texts, flags = [], [], []
    reg_key_overrides = {}
    parent_process_overrides = {}

    for i, (idx, row) in enumerate(df.iterrows()):
        cat = NEW_FAMILIES[i % len(NEW_FAMILIES)]
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
            payload_text = template
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

    # Restrict candidate pool to rows where IncidentGrade is BenignPositive or FalsePositive — NOT TruePositive.
    filtered_src = src[src["IncidentGrade"].isin(["BenignPositive", "FalsePositive"])].reset_index(drop=True)
    print(f"Candidate pool filtered from {len(src)} to {len(filtered_src)} rows (excluding TruePositive).")

    rng = random.Random(46)
    chosen_idx = rng.sample(range(len(filtered_src)), 9)
    subset = filtered_src.iloc[chosen_idx].reset_index(drop=True)
    print(f"Sampled 9 rows at indices: {chosen_idx} (seed=46)")

    synth = synthesize_dataframe(subset)
    contaminated = _inject_hardersubtle_9(synth)

    alerts = [convert_row(r) for _, r in contaminated.iterrows()]

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    print(f"Wrote {len(alerts)} alerts -> {OUT_JSON}")

    # Validation check for exemplars on all fields
    print("\nRunning validation check against exemplars...")
    violations = []
    for alert in alerts:
        cat = alert["_ground_truth_injection_category"]
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
    print("EXAMPLE ALERTS (one per new family)")
    print("="*70)
    for family in NEW_FAMILIES:
        ex = next((a for a in alerts if a["_ground_truth_injection_category"] == family), None)
        if ex:
            print(f"\n--- {family.upper()} ---")
            print(f"  alert_id       : {ex['alert_id']}")
            print(f"  incident_grade : {ex.get('_source_incident_grade')}")
            print(f"  registry_key   : {ex.get('registry_key', 'N/A')}")
            print(f"  parent_process : {ex.get('parent_process', 'N/A')}")
            print(f"  raw_log_line   : {ex.get('raw_log_line', 'N/A')}")


if __name__ == "__main__":
    main()
