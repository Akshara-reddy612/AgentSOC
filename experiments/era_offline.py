"""
experiments/era_offline.py

ERA (Evidence Risk Assessment) on corpus v2, offline (Phase 4 step 4.8,
2026-10-11).  Each alert goes through the real PerceptionPipeline and
risk_assessment.orchestrator.assess exactly as monitoring/pipeline_adapter.py
does (one alert at a time, cluster representative's evidence).  No API call;
the semantic detector uses the local sentence-transformer model.

    python -m experiments.era_offline            # scores dev + heldout, writes agent/v2_results/era_scores_<set>.json
    python -m experiments.era_offline --report   # detection table from the stored scores

Per alert: incident score/level (what Monitoring records), max field score and
the field that produced it, and which detectors fired.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
V2 = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2"
OUT = PROJECT_ROOT / "agent" / "v2_results"


def score_alert(alert: dict, pipeline, assess) -> dict:
    pub = {k: v for k, v in alert.items() if not k.startswith("_")}
    res = pipeline.run([pub])
    if not res.clusters:
        return {"alert_id": alert["alert_id"], "error": "no cluster"}
    bundle = assess(res.clusters[0].representative.evidence)
    fields = [(name, r.overall_score, r.risk_level, r.detector_results) for name, r in bundle.field_results.items()]
    top = max(fields, key=lambda f: f[1]) if fields else (None, 0.0, "LOW", [])
    inc = bundle.incident_result
    fired = sorted({d.detector for f in fields for d in f[3] if d.score > 0}
                   | ({d.detector for d in inc.detector_results if d.score > 0} if inc else set()))
    return {
        "alert_id": alert["alert_id"],
        "incident_score": round(inc.overall_score, 4) if inc else 0.0,
        "incident_level": inc.risk_level if inc else "LOW",
        "max_field_score": round(top[1], 4),
        "max_field_level": top[2],
        "max_field": top[0],
        "detectors_fired": fired,
    }


def score_set(set_name: str) -> list[dict]:
    from perception.pipeline import PerceptionPipeline
    from risk_assessment.orchestrator import assess
    pipeline = PerceptionPipeline(emit_logs=False)
    alerts = json.loads((V2 / f"guide_v2_{set_name}.json").read_text(encoding="utf-8"))
    return [score_alert(a, pipeline, assess) for a in alerts]


def level_of(rec: dict) -> str:
    """The alert's ERA level: the higher of incident level and max field level."""
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    return max(rec.get("incident_level", "LOW"), rec.get("max_field_level", "LOW"), key=lambda x: order.get(x, 0))


def report(set_name: str) -> dict:
    alerts = {a["alert_id"]: a for a in json.loads((V2 / f"guide_v2_{set_name}.json").read_text(encoding="utf-8"))}
    scores = json.loads((OUT / f"era_scores_{set_name}.json").read_text(encoding="utf-8"))
    by_fam: dict[str, Counter] = defaultdict(Counter)
    for s in scores:
        a = alerts[s["alert_id"]]
        fam = a["_ground_truth_injection_category"] or "CLEAN"
        lvl = level_of(s)
        by_fam[fam]["n"] += 1
        by_fam[fam][lvl] += 1
    return by_fam


def main() -> None:
    sets = ["dev", "heldout"]
    if "--report" not in sys.argv:
        for s in sets:
            recs = score_set(s)
            (OUT / f"era_scores_{s}.json").write_text(json.dumps(recs, indent=1), encoding="utf-8")
            print(f"{s}: scored {len(recs)} alerts")
    for s in sets:
        by_fam = report(s)
        print(f"== {s}: ERA level per family (share HIGH | share MEDIUM-or-HIGH)")
        for fam, c in sorted(by_fam.items(), key=lambda x: (x[0] != "CLEAN", x[0])):
            n = c["n"]
            print(f"  {fam:<26} n={n:>3}  HIGH {c['HIGH']:>3} ({c['HIGH'] / n:5.1%})  "
                  f"MEDIUM+ {c['HIGH'] + c['MEDIUM']:>3} ({(c['HIGH'] + c['MEDIUM']) / n:5.1%})")


if __name__ == "__main__":
    main()
