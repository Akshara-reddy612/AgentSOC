"""
experiments/accuracy_by_grade.py

Pipeline response vs the GUIDE IncidentGrade on corpus v2 clean alerts
(Phase 4 step 4.4, 2026-10-11).  "Responded" = REVIEW or AUTO_APPROVED.

Read with care: corpus v2 deliberately carries no grade information in its
synthetic evidence or destination reputation (that was label leakage in v1).
The only grade-related signals left are genuine GUIDE fields (Category,
EntityType, LastVerdict).  A flat response rate across grades is therefore
expected and says the corpus cannot measure detection accuracy — not that the
pipeline is accurate or inaccurate.

    python -m experiments.accuracy_by_grade [RESCORED_RESULTS.json --set dev]
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESPONDED = {"REVIEW", "AUTO_APPROVED"}
GRADES = ("TruePositive", "BenignPositive", "FalsePositive")


def table(results: list[dict], alerts: dict[str, dict]) -> dict:
    by_grade: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        if r.get("variant") != "clean" or "outcome" not in r:
            continue
        by_grade[alerts[r["alert_id"]]["_source_incident_grade"]][r["outcome"]] += 1
    out = {}
    for g in GRADES:
        c = by_grade[g]
        n = sum(c.values())
        out[g] = {"n": n, "responded": sum(c[o] for o in RESPONDED), **dict(c)}
    tp, neg = out["TruePositive"], [out["BenignPositive"], out["FalsePositive"]]
    out["recall_tp"] = tp["responded"] / tp["n"] if tp["n"] else None
    nn = sum(x["n"] for x in neg)
    out["response_rate_non_tp"] = sum(x["responded"] for x in neg) / nn if nn else None
    return out


def main() -> None:
    args = sys.argv[1:]
    sets = ["dev", "heldout"]
    for s in sets:
        path = Path(args[0]) if args else PROJECT_ROOT / "agent" / "v2_results" / f"v2_{s}_live_results_rescored.json"
        if args and "--set" in args and args[args.index("--set") + 1] != s:
            continue
        alerts = {a["alert_id"]: a for a in json.loads(
            (PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2" / f"guide_v2_{s}.json").read_text(encoding="utf-8"))}
        t = table(json.loads(path.read_text(encoding="utf-8")), alerts)
        print(f"== {s}")
        for g in GRADES:
            print(f"  {g:<15} n={t[g]['n']:>3} responded={t[g]['responded']:>3} ({t[g]['responded'] / t[g]['n']:.1%})")
        print(f"  TP recall {t['recall_tp']:.1%} | response rate on non-TP {t['response_rate_non_tp']:.1%}")


if __name__ == "__main__":
    main()
