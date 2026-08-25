"""
generate_strongblunt_9.py
-------------------------
Generates guide_strongblunt_9_alerts.json — a 9-alert test subset exercising the
3 new strong-blunt payload families:

  9. authority_escalation
  10. technique_stack
  11. obfuscated_trigger

Pipeline:
  guide_sample_500.csv  ->  synth_fields.synthesize_dataframe()
                        ->  deterministic injection (seed=44)
                        ->  guide_to_alerts.convert_row()
                        ->  guide_strongblunt_9_alerts.json

Constraints:
  - seed=44
  - 9 alerts total, 3 per family
  - Validate that obfuscated_trigger payloads do NOT match any phrase in
    INJECTION_EXEMPLARS case-insensitively.
"""
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).parent
RAW_CSV = HERE.parent / "raw" / "guide_sample_500" / "guide_sample_500.csv"
OUT_JSON = HERE / "guide_strongblunt_9_alerts.json"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent))

import pandas as pd
from synth_fields import synthesize_dataframe
from inject_payloads import PAYLOADS, _rng as _make_rng
from guide_to_alerts import convert_row
from risk_assessment.exemplars import INJECTION_EXEMPLARS

NEW_FAMILIES = ["authority_escalation", "technique_stack", "obfuscated_trigger"]


def _inject_strongblunt_9(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["raw_log_text_clean"] = df["raw_log_text"]

    cats, texts, flags = [], [], []

    for i, (idx, row) in enumerate(df.iterrows()):
        cat = NEW_FAMILIES[i % len(NEW_FAMILIES)]
        row_rng = _make_rng(row["Id"])

        template = row_rng.choice(PAYLOADS[cat])
        payload_text = template
        new_text = f"{row['raw_log_text']} | INJECTED_FIELD_VALUE=\"{payload_text}\""

        cats.append(cat)
        texts.append(new_text)
        flags.append(True)

    df["raw_log_text"] = texts
    df["is_contaminated"] = flags
    df["injection_category"] = cats

    return df


def main():
    print(f"Loading raw CSV: {RAW_CSV}")
    src = pd.read_csv(RAW_CSV)

    rng = random.Random(44)
    chosen_idx = rng.sample(range(len(src)), 9)
    subset = src.iloc[chosen_idx].reset_index(drop=True)
    print(f"Sampled 9 rows at indices: {chosen_idx} (seed=44)")

    synth = synthesize_dataframe(subset)
    contaminated = _inject_strongblunt_9(synth)

    alerts = [convert_row(r) for _, r in contaminated.iterrows()]

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    print(f"Wrote {len(alerts)} alerts -> {OUT_JSON}")

    # Validation check for obfuscated_trigger (family 3)
    print("\nRunning validation check for obfuscated_trigger against exemplars...")
    violations = []
    for alert in alerts:
        if alert["_ground_truth_injection_category"] == "obfuscated_trigger":
            raw_log = alert["raw_log_line"].lower()
            for phrase in INJECTION_EXEMPLARS:
                if phrase.lower() in raw_log:
                    violations.append((alert["alert_id"], phrase))

    if violations:
        print("  FAIL: Found exemplar phrase matches in obfuscated_trigger payloads!")
        for aid, phrase in violations:
            print(f"    Alert ID: {aid} matched phrase: '{phrase}'")
        sys.exit(1)
    else:
        print("  PASS: Obfuscated trigger payloads have ZERO literal matches in exemplars.")

    print("\n" + "="*70)
    print("EXAMPLE ALERTS (one per new family)")
    print("="*70)
    for family in NEW_FAMILIES:
        ex = next((a for a in alerts if a["_ground_truth_injection_category"] == family), None)
        if ex:
            print(f"\n--- {family.upper()} ---")
            print(f"  alert_id       : {ex['alert_id']}")
            print(f"  raw_log_line   : {ex.get('raw_log_line', 'N/A')}")


if __name__ == "__main__":
    main()
