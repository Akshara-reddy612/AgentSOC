"""
corpus/build_v2.py

Builds corpus v2 (Phase 3 step 3.2, 2026-10-11): for every GUIDE row a
clean/contaminated PAIR that differs only at the injection site.

    python -m corpus.build_v2                 # writes GUIDE_Dataset/processed/v2/*.json
    python -m corpus.build_v2 --allow-overwrite

Outputs (offline, deterministic, seed 79 for family assignment):
    guide_v2_dev.json      from GUIDE_Dataset/raw/guide_sample_500 (500 pairs)
    guide_v2_heldout.json  from GUIDE_Dataset/raw/guide_test_500   (500 pairs)

Each alert carries `_pair_id` and `_variant` ("clean" / "contaminated").
Ground-truth keys start with "_" and are never shown to the pipeline.
IncidentGrade is kept only as `_source_incident_grade`; `severity` comes from
Category (evidence.CATEGORY_TO_SEVERITY).
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pandas as pd

from agent.run_guard import confirm_overwrite
from corpus import evidence, payloads

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW = PROJECT_ROOT / "GUIDE_Dataset" / "raw"
OUT_DIR = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2"
SEED = 79
SETS = {
    "dev": (RAW / "guide_sample_500" / "guide_sample_500.csv", "v2d"),
    "heldout": (RAW / "guide_test_500" / "guide_test_500.csv", "v2h"),
}


def _val(v):
    return None if pd.isna(v) else v


def _assign_families(network_flags: list[bool], rng: random.Random) -> list[str]:
    """Balanced, shuffled family assignment; destination_spoof only on alerts with destination telemetry."""
    all_fams = list(payloads.FAMILIES)
    non_net = [f for f in all_fams if not payloads.FAMILIES[f].get("network_only")]
    out: list[str | None] = [None] * len(network_flags)
    for flag, fams in ((True, all_fams), (False, non_net)):
        idx = [i for i, n in enumerate(network_flags) if n == flag]
        pool = (fams * (len(idx) // len(fams) + 1))[: len(idx)]
        rng.shuffle(pool)
        for i, f in zip(idx, pool):
            out[i] = f
    return out  # type: ignore[return-value]


def build_set(csv_path: Path, prefix: str, rng: random.Random) -> list[dict]:
    df = pd.read_csv(csv_path)
    seen: dict[str, int] = {}
    cleans = []
    for _, row in df.iterrows():
        rid = str(row["Id"])
        k = seen.get(rid, 0)
        seen[rid] = k + 1
        pair_id = f"{prefix}-{rid}" + (f".{k}" if k else "")
        f = evidence.synthesize(pair_id, _val(row["Category"]), _val(row["MitreTechniques"]),
                                _val(row["EntityType"]), _val(row["Timestamp"]), _val(row["LastVerdict"]))
        clean = {
            "alert_id": f"{pair_id}-clean",
            "timestamp": _val(row["Timestamp"]),
            **f,
            "_pair_id": pair_id,
            "_variant": "clean",
            "_corpus_version": "v2",
            "_source_row": {"Id": rid, "AlertId": str(row["AlertId"]), "Category": _val(row["Category"]),
                            "EntityType": _val(row["EntityType"])},
            "_source_incident_grade": _val(row["IncidentGrade"]),
            "_ground_truth_is_contaminated": False,
            "_ground_truth_injection_category": None,
            "_attack_goal": None,
            "_injection_site": None,
            "_steered_entities": None,
        }
        cleans.append(clean)

    fams = _assign_families([c["destination_ip"] is not None for c in cleans], rng)
    alerts = []
    for clean, fam in zip(cleans, fams):
        contam = payloads.apply(clean, fam, evidence.row_rng(clean["_pair_id"], "payload"))
        contam["alert_id"] = f"{clean['_pair_id']}-contaminated"
        contam["_variant"] = "contaminated"
        alerts += [clean, contam]
    return alerts


def main() -> None:
    outs = {name: OUT_DIR / f"guide_v2_{name}.json" for name in SETS}
    confirm_overwrite(*outs.values())
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    for name, (csv_path, prefix) in SETS.items():
        alerts = build_set(csv_path, prefix, rng)
        ids = [a["alert_id"] for a in alerts]
        assert len(ids) == len(set(ids)), "duplicate alert ids"
        outs[name].write_text(json.dumps(alerts, indent=1, ensure_ascii=False), encoding="utf-8")
        print(f"{name}: {len(alerts) // 2} pairs -> {outs[name]}")


if __name__ == "__main__":
    sys.exit(main())
