"""
experiments/build_clean_twins.py

Builds true clean twins for the 320 contaminated alerts in
GUIDE_Dataset/processed/guide_n50_scaleup_320_alerts.json.

Why: Experiment 1 looked up "clean twins" by alert_id in
guide_sample_500_alerts.json, which contains 150 contaminated rows and 17
duplicated ids (last row wins).  For 108 of the 320 alerts the twin carried a
different injection payload, and for 8 it was a different GUIDE row.

How: replays exactly what generate_n50_scaleup_320_alerts.py did to create the
contaminated alerts -- raw CSV, first row per Id (drop_duplicates), synth_fields
.synthesize_dataframe(), guide_to_alerts.convert_row() -- but without the
injection step.  Every twin is then verified against its contaminated alert:
  * same alert_id, every structured field identical;
  * every free-text field identical except raw_log_line, and registry_key for
    cross_field_split (where the generator writes payload part A);
  * contaminated raw_log_line == clean raw_log_line + " | " + payload.
Any mismatch aborts without writing.

Usage:
    python -m experiments.build_clean_twins            # verify only
    python -m experiments.build_clean_twins --write    # verify and write output
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED = PROJECT_ROOT / "GUIDE_Dataset" / "processed"
RAW_CSV = PROJECT_ROOT / "GUIDE_Dataset" / "raw" / "guide_sample_500" / "guide_sample_500.csv"
CONTAM_JSON = PROCESSED / "guide_n50_scaleup_320_alerts.json"
OUT_JSON = PROCESSED / "guide_n50_scaleup_320_clean_twins.json"

# Fields the injection may change, per family.
_ALWAYS_DIFFERENT = {"raw_log_line"}
_CROSS_FIELD_EXTRA = {"registry_key"}
# Ground-truth metadata that legitimately differs between twin and contaminated alert.
_GT_FIELDS = {"_ground_truth_is_contaminated", "_ground_truth_injection_category"}


def build_clean_twins() -> list[dict]:
    sys.path.insert(0, str(PROCESSED))
    import pandas as pd
    from synth_fields import synthesize_dataframe
    from guide_to_alerts import convert_row

    contam = json.loads(CONTAM_JSON.read_text(encoding="utf-8"))
    order = [str(a["alert_id"]) for a in contam]

    # Same row selection as the generator: first occurrence of each Id.
    src = pd.read_csv(RAW_CSV).drop_duplicates(subset=["Id"]).reset_index(drop=True)
    subset = src[src["Id"].astype(str).isin(set(order))].reset_index(drop=True)
    if len(subset) != len(order):
        raise SystemExit(f"Expected {len(order)} source rows, found {len(subset)}")

    synth = synthesize_dataframe(subset)
    synth["is_contaminated"] = False
    synth["injection_category"] = None
    by_id = {str(r["Id"]): convert_row(r) for _, r in synth.iterrows()}
    return [by_id[i] for i in order]


def verify(twins: list[dict], contam: list[dict]) -> list[str]:
    """Return a list of human-readable problems (empty = all twins valid)."""
    problems: list[str] = []
    ids = [str(t["alert_id"]) for t in twins]
    if len(ids) != len(set(ids)):
        problems.append("duplicate alert_id in twins")
    for t, c in zip(twins, contam):
        aid = str(c["alert_id"])
        if str(t["alert_id"]) != aid:
            problems.append(f"{aid}: order/id mismatch ({t['alert_id']})")
            continue
        if t["_ground_truth_is_contaminated"] is not False or t["_ground_truth_injection_category"] is not None:
            problems.append(f"{aid}: twin flagged contaminated")
        family = c.get("_ground_truth_injection_category")
        allowed = _ALWAYS_DIFFERENT | _GT_FIELDS
        if family == "cross_field_split":
            allowed |= _CROSS_FIELD_EXTRA
        for key in set(t) | set(c):
            if key in allowed:
                continue
            if str(t.get(key)) != str(c.get(key)):
                problems.append(f"{aid}: field {key!r} differs: {t.get(key)!r} vs {c.get(key)!r}")
        clean_line, contam_line = t.get("raw_log_line") or "", c.get("raw_log_line") or ""
        if not contam_line.startswith(clean_line + " | ") or len(contam_line) <= len(clean_line) + 3:
            problems.append(f"{aid}: contaminated raw_log_line is not clean line + ' | ' + payload")
        if "INJECTED" in json.dumps(t):
            problems.append(f"{aid}: twin contains an injection marker")
    return problems


def main() -> None:
    contam = json.loads(CONTAM_JSON.read_text(encoding="utf-8"))
    twins = build_clean_twins()
    problems = verify(twins, contam)
    print(f"Built {len(twins)} clean twins for {len(contam)} contaminated alerts.")
    if problems:
        print(f"VERIFICATION FAILED ({len(problems)} problems); nothing written. First 20:")
        for p in problems[:20]:
            print("  " + p)
        sys.exit(1)
    print("Verification passed: every twin matches its contaminated alert except the injected payload.")
    if "--write" in sys.argv:
        OUT_JSON.write_text(json.dumps(twins, indent=2), encoding="utf-8")
        print(f"Wrote {OUT_JSON}")
    else:
        print("Verify-only run (pass --write to save).")


if __name__ == "__main__":
    main()
