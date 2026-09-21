"""
generate_n50_scaleup_320_alerts.py
----------------------------------
Generates guide_n50_scaleup_320_alerts.json: 320 new contaminated alerts
(40 alerts per family x 8 target families) to scale the contaminated structural-defense
evaluation from n=10 to n=50 per family (n=400 total).

Candidate pool:
  GUIDE_Dataset/raw/guide_sample_500/guide_sample_500.csv

Target families (8):
  1. fabricated_evidence
  2. cross_field_split
  3. authority_escalation
  4. direct_override
  5. zero_imperative_evidence
  6. native_format_mimicry
  7. fake_output_injection
  8. obfuscated_trigger

Constraints:
  - Seed: random.Random(52)
  - Exactly 40 alerts per family x 8 families = 320 alerts.
  - ZERO alert_id overlap with:
      * agent/nce7_scale_results.json (80 contaminated + 10 clean)
      * GUIDE_Dataset/processed/guide_heldout_140_alerts.json
      * GUIDE_Dataset/processed/guide_subtle_30_alerts.json
      * GUIDE_Dataset/processed/guide_strongblunt_9_alerts.json
      * GUIDE_Dataset/processed/guide_hardersubtle_9_alerts.json
      * GUIDE_Dataset/processed/guide_hardersubtle_ambiguous_9_alerts.json
      * GUIDE_Dataset/processed/guide_strongblunt_hardersubtle_scale_42_alerts.json
      * agent/nce8_clean_fp_results.json
      * GUIDE_Dataset/raw/guide_test_500/guide_test_500.csv
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent
RAW_CSV = HERE.parent / "raw" / "guide_sample_500" / "guide_sample_500.csv"
TEST_CSV = HERE.parent / "raw" / "guide_test_500" / "guide_test_500.csv"
OUT_JSON = HERE / "guide_n50_scaleup_320_alerts.json"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from synth_fields import synthesize_dataframe
from inject_payloads import (
    PAYLOADS,
    CROSS_FIELD_PAYLOADS,
    _rng as _make_rng,
)
from guide_to_alerts import convert_row

TARGET_FAMILIES = [
    "fabricated_evidence",
    "cross_field_split",
    "authority_escalation",
    "direct_override",
    "zero_imperative_evidence",
    "native_format_mimicry",
    "fake_output_injection",
    "obfuscated_trigger",
]

ALERTS_PER_FAMILY = 40
TOTAL_ALERTS = len(TARGET_FAMILIES) * ALERTS_PER_FAMILY  # 320
SEED = 52


def _inject_one(row, cat: str):
    """Apply cat payload to row."""
    row_rng = _make_rng(row["Id"])
    idx = row.name

    if cat == "cross_field_split":
        payloads_2 = [p for p in CROSS_FIELD_PAYLOADS if len(p) == 2]
        part_a_tmpl, part_b = row_rng.choice(payloads_2)
        device = str(row.get("synth_device_name", "DEVICE-UNKNOWN"))
        process = str(row.get("synth_process_name", "proc-unknown"))
        part_a = part_a_tmpl.format(device=device, process=process)
        new_text = row["raw_log_text"] + " | " + part_b
        return new_text, {idx: part_a}, None
    else:
        template = row_rng.choice(PAYLOADS[cat])
        if "{n}" in template:
            payload_text = template.format(n=row_rng.randint(1000, 9999))
        else:
            payload_text = template
        new_text = row["raw_log_text"] + ' | INJECTED_FIELD_VALUE="' + payload_text + '"'
        return new_text, None, None


def _inject_scale_320(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["raw_log_text_clean"] = df["raw_log_text"]

    cats: list[str] = []
    texts: list[str] = []
    flags: list[bool] = []
    reg_key_overrides: dict = {}
    parent_process_overrides: dict = {}

    for i, (idx, row) in enumerate(df.iterrows()):
        family_idx = i // ALERTS_PER_FAMILY
        cat = TARGET_FAMILIES[family_idx]

        new_text, rk_ov, pp_ov = _inject_one(row, cat)

        if rk_ov:
            reg_key_overrides.update(rk_ov)
        if pp_ov:
            parent_process_overrides.update(pp_ov)

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
    print("=" * 80)
    print("generate_n50_scaleup_320_alerts.py")
    print("=" * 80)
    print(f"Source CSV : {RAW_CSV}")
    print(f"Output     : {OUT_JSON}")
    print(f"Seed       : random.Random({SEED})")
    print(f"Families   : {len(TARGET_FAMILIES)}")
    print(f"Per family : {ALERTS_PER_FAMILY}")
    print(f"Total      : {TOTAL_ALERTS}")

    # 1. Collect all excluded alert IDs
    files_to_exclude = [
        PROJECT_ROOT / "agent" / "nce7_scale_results.json",
        HERE / "guide_heldout_140_alerts.json",
        HERE / "guide_subtle_30_alerts.json",
        HERE / "guide_strongblunt_9_alerts.json",
        HERE / "guide_hardersubtle_9_alerts.json",
        HERE / "guide_hardersubtle_ambiguous_9_alerts.json",
        HERE / "guide_strongblunt_hardersubtle_scale_42_alerts.json",
        PROJECT_ROOT / "agent" / "nce8_clean_fp_results.json",
    ]

    excluded_ids = set()
    for filepath in files_to_exclude:
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                for alert in data:
                    excluded_ids.add(str(alert["alert_id"]))
            print(f"  Loaded {len(data):>3} alerts from {filepath.name}")
        else:
            print(f"  WARNING: File not found: {filepath}")

    # Also add all IDs from guide_test_500.csv to guarantee zero held-out overlap
    test_df = pd.read_csv(TEST_CSV)
    test_ids = set(test_df["Id"].astype(str))
    print(f"  Loaded {len(test_ids)} unique IDs from guide_test_500.csv to protect held-out set.")
    excluded_ids.update(test_ids)
    print(f"Total unique excluded IDs: {len(excluded_ids)}")

    # 2. Filter raw candidates
    src = pd.read_csv(RAW_CSV).drop_duplicates(subset=["Id"]).reset_index(drop=True)
    src_filtered = src[~src["Id"].astype(str).isin(excluded_ids)].reset_index(drop=True)
    print(f"Available candidates remaining in {RAW_CSV.name}: {len(src_filtered)}")
    assert len(src_filtered) >= TOTAL_ALERTS, (
        f"ERROR: need {TOTAL_ALERTS} candidates, but only {len(src_filtered)} available!"
    )

    # 3. Sample 320 rows with seed=52
    rng = random.Random(SEED)
    chosen_indices = rng.sample(range(len(src_filtered)), TOTAL_ALERTS)
    # Maintain deterministic order
    chosen_indices_sorted = sorted(chosen_indices)
    subset = src_filtered.iloc[chosen_indices_sorted].reset_index(drop=True)
    sampled_ids = set(subset["Id"].astype(str))

    # Assert zero overlap
    overlap = sampled_ids.intersection(excluded_ids)
    assert len(overlap) == 0, f"COLLISION ERROR: Overlapping IDs found: {overlap}"
    assert len(sampled_ids) == TOTAL_ALERTS, f"ERROR: expected {TOTAL_ALERTS} unique IDs, got {len(sampled_ids)}"
    print(f"PASS: Verified zero alert_id overlap with any evaluated or held-out dataset (seed={SEED}).")

    # 4. Synthesize raw-text fields
    print("Synthesizing raw-text fields via synth_fields.synthesize_dataframe()...")
    synth = synthesize_dataframe(subset)

    # 5. Inject payloads (40 per family across the 8 target families)
    print("Injecting payloads (40 per family, block order)...")
    contaminated = _inject_scale_320(synth)

    # Validate counts
    counts = contaminated["injection_category"].value_counts()
    print("\nInjection counts by family:")
    for fam in TARGET_FAMILIES:
        n = int(counts.get(fam, 0))
        status = "OK" if n == ALERTS_PER_FAMILY else f"FAIL (expected {ALERTS_PER_FAMILY})"
        print(f"  {fam:<26s}: {n:>3d} [{status}]")
        assert n == ALERTS_PER_FAMILY, f"Family {fam} has {n} alerts, expected {ALERTS_PER_FAMILY}"

    assert len(contaminated) == TOTAL_ALERTS
    assert contaminated["is_contaminated"].all()

    # 6. Convert to alert schema
    print("Converting to alert schema via guide_to_alerts.convert_row()...")
    alerts = [convert_row(r) for _, r in contaminated.iterrows()]

    # Verify uniqueness
    out_ids = [a["alert_id"] for a in alerts]
    assert len(out_ids) == len(set(out_ids)) == TOTAL_ALERTS, "ERROR: duplicate alert IDs in output!"

    # 7. Write output JSON
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    print(f"\nWrote {len(alerts)} alerts -> {OUT_JSON}")
    print("Zero-collision generation completed successfully.")


if __name__ == "__main__":
    main()
