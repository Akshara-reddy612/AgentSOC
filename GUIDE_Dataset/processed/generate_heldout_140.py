# -*- coding: utf-8 -*-
"""
generate_heldout_140.py
-----------------------
Generates guide_heldout_140_alerts.json -- a 140-alert held-out benchmark set
sampling from guide_test_500.csv (the genuinely held-out split, never used in
any payload development or testing).

Families covered (14 total):
  -- 5 original blunt families --
  1. direct_override
  2. role_play
  3. fake_system_tag
  4. encoded
  5. nested_instruction

  -- 9 added families --
  6.  fabricated_evidence
  7.  cross_field_split
  8.  fake_output_injection
  9.  authority_escalation
  10. technique_stack
  11. obfuscated_trigger
  12. zero_imperative_evidence
  13. native_format_mimicry
  14. multi_source_corroboration

Pipeline:
  guide_test_500.csv  ->  synth_fields.synthesize_dataframe()
                      ->  deterministic per-family injection (seed=49)
                      ->  guide_to_alerts.convert_row()
                      ->  guide_heldout_140_alerts.json

Constraints:
  - Source file: guide_test_500.csv (held-out; NOT guide_sample_500.csv)
  - Seed: random.Random(49)  [new seed, not used by any prior generator]
  - 140 alerts total: exactly 10 per family x 14 families
  - All alerts are contaminated (contamination_rate = 1.0)
  - All payload logic imported from inject_payloads.py -- not rewritten here
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).parent
RAW_CSV = HERE.parent / "raw" / "guide_test_500" / "guide_test_500.csv"
OUT_JSON = HERE / "guide_heldout_140_alerts.json"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent))

import pandas as pd
from synth_fields import synthesize_dataframe
from inject_payloads import (
    PAYLOADS,
    CROSS_FIELD_PAYLOADS,
    _rng as _make_rng,
)
from guide_to_alerts import convert_row

# All 14 families in stable order
ALL_FAMILIES: list[str] = [
    # 5 original blunt families
    "direct_override",
    "role_play",
    "fake_system_tag",
    "encoded",
    "nested_instruction",
    # 9 added families
    "fabricated_evidence",
    "cross_field_split",
    "fake_output_injection",
    "authority_escalation",
    "technique_stack",
    "obfuscated_trigger",
    "zero_imperative_evidence",
    "native_format_mimicry",
    "multi_source_corroboration",
]

ALERTS_PER_FAMILY = 10
TOTAL_ALERTS = len(ALL_FAMILIES) * ALERTS_PER_FAMILY  # 140


def _inject_one(row, cat: str):
    """Apply *cat* payload to *row*. Reuses PAYLOADS/CROSS_FIELD_PAYLOADS from inject_payloads."""
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

    elif cat == "multi_source_corroboration":
        payloads_3 = [p for p in CROSS_FIELD_PAYLOADS if len(p) == 3]
        part_a_tmpl, part_b_tmpl, part_c = row_rng.choice(payloads_3)
        device = str(row.get("synth_device_name", "DEVICE-UNKNOWN"))
        process = str(row.get("synth_process_name", "proc-unknown"))
        part_a = part_a_tmpl.format(device=device, process=process)
        part_b = part_b_tmpl.format(device=device, process=process)
        new_text = row["raw_log_text"] + " | " + part_c
        return new_text, {idx: part_a}, {idx: part_b}

    else:
        template = row_rng.choice(PAYLOADS[cat])
        if "{n}" in template:
            payload_text = template.format(n=row_rng.randint(1000, 9999))
        else:
            payload_text = template
        new_text = row["raw_log_text"] + ' | INJECTED_FIELD_VALUE="' + payload_text + '"'
        return new_text, None, None


def _inject_heldout_140(df: pd.DataFrame) -> pd.DataFrame:
    """Inject all 140 rows; rows 0-9 -> family[0], 10-19 -> family[1], etc."""
    df = df.copy()
    df["raw_log_text_clean"] = df["raw_log_text"]

    cats: list[str] = []
    texts: list[str] = []
    flags: list[bool] = []
    reg_key_overrides: dict = {}
    parent_process_overrides: dict = {}

    for i, (idx, row) in enumerate(df.iterrows()):
        family_idx = i // ALERTS_PER_FAMILY
        cat = ALL_FAMILIES[family_idx]

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
    print("=" * 70)
    print("generate_heldout_140.py")
    print("=" * 70)
    print("Source CSV :", RAW_CSV)
    print("Output     :", OUT_JSON)
    print("Seed       : random.Random(49)")
    print("Families   :", len(ALL_FAMILIES))
    print("Per family :", ALERTS_PER_FAMILY)
    print("Total      :", TOTAL_ALERTS)
    print()

    # Load held-out CSV
    assert RAW_CSV.exists(), "ERROR: held-out CSV not found at " + str(RAW_CSV)
    src = pd.read_csv(RAW_CSV)
    # Drop duplicates by ID to ensure unique alert_ids
    src = src.drop_duplicates(subset=["Id"]).reset_index(drop=True)
    print("Loaded", len(src), "unique rows from", RAW_CSV.name)

    # Confirm we are NOT using the sample CSV
    sample_csv = HERE.parent / "raw" / "guide_sample_500" / "guide_sample_500.csv"
    assert str(RAW_CSV.resolve()) != str(sample_csv.resolve()), \
        "ABORT: RAW_CSV points to guide_sample_500.csv instead of guide_test_500.csv!"
    print("CONFIRMED: source is guide_test_500.csv (NOT guide_sample_500.csv)")

    # Sample 140 rows with seed=49
    rng = random.Random(49)
    assert len(src) >= TOTAL_ALERTS, \
        "ERROR: need " + str(TOTAL_ALERTS) + " rows, but guide_test_500.csv has only " + str(len(src))

    chosen_idx = rng.sample(range(len(src)), TOTAL_ALERTS)
    chosen_idx_sorted = sorted(chosen_idx)
    subset = src.iloc[chosen_idx_sorted].reset_index(drop=True)
    print("Sampled", len(subset), "rows from guide_test_500.csv (seed=49)")

    # Synthesize raw-text fields
    print("Synthesizing raw-text fields via synth_fields.synthesize_dataframe()...")
    synth = synthesize_dataframe(subset)

    # Inject payloads
    print("Injecting payloads (10 per family, block order)...")
    contaminated = _inject_heldout_140(synth)

    # Validate counts
    counts = contaminated["injection_category"].value_counts()
    print("\nInjection counts by family:")
    for fam in ALL_FAMILIES:
        n = counts.get(fam, 0)
        status = "OK" if n == ALERTS_PER_FAMILY else "FAIL (expected " + str(ALERTS_PER_FAMILY) + ")"
        print("  {:<35s}: {:3d}  [{}]".format(fam, n, status))

    assert len(contaminated) == TOTAL_ALERTS, \
        "ERROR: expected " + str(TOTAL_ALERTS) + " rows, got " + str(len(contaminated))
    assert contaminated["is_contaminated"].all(), "ERROR: some rows are not contaminated"
    for fam in ALL_FAMILIES:
        n = int(counts.get(fam, 0))
        assert n == ALERTS_PER_FAMILY, \
            "ERROR: family " + fam + " has " + str(n) + " alerts, expected " + str(ALERTS_PER_FAMILY)

    print("\nPASS:", len(contaminated), "rows total, all contaminated,", ALERTS_PER_FAMILY, "per family.")

    # Convert to alert dicts
    print("Converting to alert schema via guide_to_alerts.convert_row()...")
    alerts = [convert_row(r) for _, r in contaminated.iterrows()]

    # Verify uniqueness and source
    alert_ids = [a["alert_id"] for a in alerts]
    assert len(alert_ids) == len(set(alert_ids)), "ERROR: duplicate alert_ids detected!"

    test_ids = set(src["Id"].astype(str).tolist())
    for aid in alert_ids:
        assert aid in test_ids, \
            "ERROR: alert_id " + aid + " not found in guide_test_500.csv -- wrong source!"
    print("CONFIRMED: all", len(alert_ids), "alert_ids traced back to guide_test_500.csv rows.")

    # Write output
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    print("\nWrote", len(alerts), "alerts ->", OUT_JSON)

    # One example per family
    print("\n" + "=" * 70)
    print("EXAMPLE ALERTS (one per family) -- spot-check quality")
    print("=" * 70)
    for family in ALL_FAMILIES:
        ex = next((a for a in alerts if a["_ground_truth_injection_category"] == family), None)
        if ex:
            print("\n" + "-" * 70)
            print("FAMILY:", family.upper())
            print("  alert_id       :", ex["alert_id"])
            print("  source_system  :", ex["source_system"])
            print("  event_type     :", ex["event_type"])
            print("  severity       :", ex["severity"])
            print("  process_name   :", ex.get("process_name", "N/A"))
            print("  registry_key   :", ex.get("registry_key", "N/A"))
            print("  parent_process :", ex.get("parent_process", "N/A"))
            print("  raw_log_line   :")
            raw = ex.get("raw_log_line", "")
            for chunk_start in range(0, len(raw), 120):
                print("    " + raw[chunk_start:chunk_start+120])

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("  Total alerts generated :", len(alerts))
    print("  Source CSV             : guide_test_500.csv (", len(src), "rows)")
    print("  Seed                   : random.Random(49)")
    print("  Families               :", len(ALL_FAMILIES))
    print("  Alerts per family      :", ALERTS_PER_FAMILY)
    print("  Output file            :", OUT_JSON)
    print("  All contaminated       :", all(a["_ground_truth_is_contaminated"] for a in alerts))


if __name__ == "__main__":
    main()

