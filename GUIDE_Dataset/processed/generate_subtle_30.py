"""
generate_subtle_30.py
----------------------
Generates guide_subtle_30_alerts.json — a 30-alert test subset exercising the
3 new "evasive" payload families added in inject_payloads.py:

  6. fabricated_evidence
  7. cross_field_split
  8. fake_output_injection

Pipeline mirrors the existing one:
  guide_sample_500.csv  ->  synth_fields.synthesize_dataframe()
                        ->  deterministic new-family injection (seed=43)
                        ->  guide_to_alerts.convert_row()
                        ->  guide_subtle_30_alerts.json

Constraints enforced:
  - seed=43 (different from seed=42 used for the 500-row datasets)
  - 30 rows total, 10 per new family (all contaminated; contamination_rate=1.0)
  - DOES NOT touch guide_sample_500_alerts.json or guide_test_500_alerts.json
  - No LLM API calls; pure data generation

After generation, a vocabulary check confirms that no payload text contains
any phrase from risk_assessment/exemplars.INJECTION_EXEMPLARS (case-insensitive
substring match).
"""
import json
import random
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
HERE = Path(__file__).parent                               # .../processed/
RAW_CSV = HERE.parent / "raw" / "guide_sample_500" / "guide_sample_500.csv"
OUT_JSON = HERE / "guide_subtle_30_alerts.json"
EXEMPLARS_MODULE = HERE.parent.parent / "risk_assessment" / "exemplars.py"

# Make sure both the processed dir and repo root are on sys.path
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
from risk_assessment.exemplars import INJECTION_EXEMPLARS

# ---------------------------------------------------------------------------
# New-family-only injection
# ---------------------------------------------------------------------------

NEW_FAMILIES = ["fabricated_evidence", "cross_field_split", "fake_output_injection"]


def _inject_subtle_30(df: pd.DataFrame) -> pd.DataFrame:
    """
    Inject exactly 30 rows, 10 per new family, in round-robin order, seeded
    with random.seed(43).  Every row is contaminated (contamination_rate=1.0).
    Returns a copy with raw_log_text_clean, is_contaminated, injection_category
    added, and synth_registry_key overwritten for cross_field_split rows.
    """
    rng = random.Random(43)
    df = df.copy()
    df["raw_log_text_clean"] = df["raw_log_text"]

    cats, texts, flags = [], [], []
    reg_key_overrides: dict = {}

    for i, (idx, row) in enumerate(df.iterrows()):
        cat = NEW_FAMILIES[i % len(NEW_FAMILIES)]  # round-robin: fe, cfs, foi, fe, cfs, foi, ...
        row_rng = _make_rng(row["Id"])

        if cat == "fabricated_evidence":
            template = row_rng.choice(PAYLOADS["fabricated_evidence"])
            payload_text = template  # no {n} placeholder in these
            new_text = f"{row['raw_log_text']} | INJECTED_FIELD_VALUE=\"{payload_text}\""

        elif cat == "cross_field_split":
            part_a_tmpl, part_b = row_rng.choice(CROSS_FIELD_PAYLOADS)
            device = str(row.get("synth_device_name", "DEVICE-UNKNOWN"))
            process = str(row.get("synth_process_name", "proc-unknown"))
            part_a = part_a_tmpl.format(device=device, process=process)
            reg_key_overrides[idx] = part_a
            new_text = f"{row['raw_log_text']} | {part_b}"

        elif cat == "fake_output_injection":
            template = row_rng.choice(PAYLOADS["fake_output_injection"])
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

    return df


# ---------------------------------------------------------------------------
# Vocabulary validation
# ---------------------------------------------------------------------------

def check_exemplar_violations(alerts: list[dict]) -> list[dict]:
    """
    For every contaminated alert, check whether raw_log_line contains any
    phrase from INJECTION_EXEMPLARS (case-insensitive substring match).
    Returns a list of violation dicts (empty = pass).
    """
    violations = []
    for alert in alerts:
        if not alert.get("_ground_truth_is_contaminated"):
            continue
        field_val = (alert.get("raw_log_line") or "").lower()
        for phrase in INJECTION_EXEMPLARS:
            if phrase.lower() in field_val:
                violations.append({
                    "alert_id": alert["alert_id"],
                    "injection_category": alert["_ground_truth_injection_category"],
                    "matched_exemplar": phrase,
                    "raw_log_line_snippet": alert["raw_log_line"][:200],
                })
    return violations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Loading raw CSV: {RAW_CSV}")
    src = pd.read_csv(RAW_CSV)
    print(f"  Total rows available: {len(src)}")

    # Pick 30 rows with seed=43 (no overlap with the seed=42 sample)
    rng = random.Random(43)
    chosen_idx = rng.sample(range(len(src)), 30)
    subset = src.iloc[chosen_idx].reset_index(drop=True)
    print(f"  Sampled 30 rows at indices: {chosen_idx[:5]}... (seed=43)")

    print("Synthesizing raw-text fields...")
    synth = synthesize_dataframe(subset)

    print("Injecting new-family payloads (10 per family, round-robin)...")
    contaminated = _inject_subtle_30(synth)

    print(f"\nInjection summary:")
    print(contaminated["injection_category"].value_counts().to_string())
    print(f"All contaminated: {contaminated['is_contaminated'].all()}")

    # Convert to alert dicts using the same logic as guide_to_alerts.py
    alerts = [convert_row(r) for _, r in contaminated.iterrows()]

    # Write output
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    print(f"\nWrote {len(alerts)} alerts -> {OUT_JSON}")

    # ---------------------------------------------------------------------------
    # Exemplar vocabulary check
    # ---------------------------------------------------------------------------
    print("\nRunning exemplar-vocabulary violation check...")
    violations = check_exemplar_violations(alerts)
    if violations:
        print(f"  VIOLATIONS FOUND ({len(violations)}):")
        for v in violations:
            print(f"    alert_id={v['alert_id']} cat={v['injection_category']} "
                  f"phrase='{v['matched_exemplar']}' snippet='{v['raw_log_line_snippet']}'")
    else:
        print(f"  PASS — 0 exemplar-phrase violations across all {len(alerts)} contaminated alerts.")

    # ---------------------------------------------------------------------------
    # Print one example per new family
    # ---------------------------------------------------------------------------
    print("\n" + "="*70)
    print("EXAMPLE ALERTS (one per new family)")
    print("="*70)
    for family in NEW_FAMILIES:
        ex = next((a for a in alerts if a["_ground_truth_injection_category"] == family), None)
        if ex:
            print(f"\n--- {family.upper()} ---")
            print(f"  alert_id       : {ex['alert_id']}")
            print(f"  source_host    : {ex['source_host']}")
            print(f"  registry_key   : {ex.get('registry_key', 'N/A')}")
            print(f"  raw_log_line   : {ex.get('raw_log_line', 'N/A')}")

    return violations  # return for programmatic use


if __name__ == "__main__":
    violations = main()
    sys.exit(1 if violations else 0)
