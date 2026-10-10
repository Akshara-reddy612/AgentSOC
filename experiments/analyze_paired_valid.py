"""
experiments/analyze_paired_valid.py

Experiment 1 restated on the pairs whose clean-arm input was genuinely clean.

The clean runs (paired_clean_results.json / _B.json) were fed twins looked up
by alert_id in guide_sample_500_alerts.json.  This script compares, for each
of the 320 alerts, the six NCE evidence fields of that input with the verified
twin in guide_n50_scaleup_320_clean_twins.json (see build_clean_twins.py) and
keeps only alerts where they are identical.  It then reports the same
statistics as analyze_paired.py on that subset, plus a per-family table.

analyze_paired.py is left unchanged so the original (n=320) numbers stay
reproducible.

Usage:
    python -m experiments.analyze_paired_valid
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from experiments.analyze_paired import (
    _format_wilson,
    _hypothesis_set,
    _is_no_actionable,
    _technique_set,
)
from experiments.metrics import exact_mcnemar

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED = PROJECT_ROOT / "GUIDE_Dataset" / "processed"
TWINS_JSON = PROCESSED / "guide_n50_scaleup_320_clean_twins.json"
OLD_CLEAN_SOURCE = PROCESSED / "guide_sample_500_alerts.json"
CONTAM_JSON = PROCESSED / "guide_n50_scaleup_320_alerts.json"

RUNS = {
    "Clean A": PROJECT_ROOT / "experiments" / "paired_clean_results.json",
    "Clean B": PROJECT_ROOT / "experiments" / "paired_clean_results_B.json",
    "Contam A": PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runA.json",
    "Contam B": PROJECT_ROOT / "agent" / "nce_n50_scaleup_results_runB.json",
}
EVIDENCE_FIELDS = ("process_name", "command_line", "registry_key",
                   "parent_process", "file_path", "raw_log_line")


def _load(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_pair_ids() -> tuple[list[str], dict[str, str]]:
    """Return (valid ids in corpus order, {invalid id: reason})."""
    twins = {str(a["alert_id"]): a for a in _load(TWINS_JSON)}
    # Same lookup the clean harnesses used: last row per id wins.
    used = {str(a["alert_id"]): a for a in _load(OLD_CLEAN_SOURCE)}
    order = [str(a["alert_id"]) for a in _load(CONTAM_JSON)]
    valid, invalid = [], {}
    for aid in order:
        if all(str(twins[aid].get(f)) == str(used[aid].get(f)) for f in EVIDENCE_FIELDS):
            valid.append(aid)
        elif used[aid].get("_ground_truth_is_contaminated"):
            invalid[aid] = f"clean input was contaminated ({used[aid].get('_ground_truth_injection_category')})"
        else:
            invalid[aid] = "clean input was a different GUIDE row (duplicated alert_id)"
    return valid, invalid


def main() -> None:
    valid, invalid = valid_pair_ids()
    print(f"Valid pairs: {len(valid)}/320  (invalid: {len(invalid)})")
    for reason, n in Counter(invalid.values()).most_common():
        print(f"  {n:>3}  {reason}")

    runs = {}
    for name, path in RUNS.items():
        recs = {str(r["alert_id"]): r for r in _load(path) if not r.get("nce_error")}
        missing = [a for a in valid if a not in recs]
        if missing:
            raise SystemExit(f"{name}: {len(missing)} valid ids have no usable record")
        runs[name] = recs

    n = len(valid)
    print("\nNo-actionable rates on valid pairs (Wilson 95%):")
    for name, recs in runs.items():
        pre = sum(_is_no_actionable(recs[a].get("sse_results_orig") or []) for a in valid)
        post = sum(_is_no_actionable(recs[a].get("sse_results") or []) for a in valid)
        print(f"  {name:<9} pre-filter  {_format_wilson(pre, n)}")
        print(f"  {name:<9} post-filter {_format_wilson(post, n)}")

    pairs = [
        ("Clean A vs Clean B", "Clean A", "Clean B", "within-condition"),
        ("Contam A vs Contam B", "Contam A", "Contam B", "within-condition"),
        ("Clean A vs Contam A", "Clean A", "Contam A", "cross-condition"),
        ("Clean A vs Contam B", "Clean A", "Contam B", "cross-condition"),
        ("Clean B vs Contam A", "Clean B", "Contam A", "cross-condition"),
        ("Clean B vs Contam B", "Clean B", "Contam B", "cross-condition"),
    ]
    print("\nPairwise comparisons (post-filter verdicts):")
    for label, k1, k2, kind in pairs:
        d1, d2 = runs[k1], runs[k2]
        a = b = c = d = tech = hyp = 0
        for aid in valid:
            h1, h2 = d1[aid].get("sse_results") or [], d2[aid].get("sse_results") or []
            tech += _technique_set(h1) != _technique_set(h2)
            hyp += _hypothesis_set(h1) != _hypothesis_set(h2)
            r1, r2 = _is_no_actionable(h1), _is_no_actionable(h2)
            if r1 and r2:
                a += 1
            elif r1:
                b += 1
            elif r2:
                c += 1
            else:
                d += 1
        m = exact_mcnemar(a, b, c, d)
        print(f"  {label:<22} ({kind}): verdict changes {b + c}/{n}, "
              f"McNemar b={b} c={c} p={m.p_value:.4f}; "
              f"technique sets differ {tech}/{n}, hypothesis sets differ {hyp}/{n}")

    family = {str(a["alert_id"]): a["_ground_truth_injection_category"] for a in _load(CONTAM_JSON)}
    fams = sorted({family[a] for a in valid})
    print("\nPer-family post-filter no-actionable counts on valid pairs:")
    print(f"  {'family':<26} {'n':>3} " + " ".join(f"{k:>9}" for k in runs))
    for fam in fams:
        ids = [a for a in valid if family[a] == fam]
        counts = [sum(_is_no_actionable(runs[k][a].get("sse_results") or []) for a in ids) for k in runs]
        print(f"  {fam:<26} {len(ids):>3} " + " ".join(f"{c:>9}" for c in counts))


if __name__ == "__main__":
    main()
