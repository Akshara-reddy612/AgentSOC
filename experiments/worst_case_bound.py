"""
experiments/worst_case_bound.py

Checklist A4 (2026-11-23): the worst case over every possible attacker text on GUIDE, under asymmetric trust. The
outcome is never below the model-free decision on the contaminated twin, so an attacker can suppress a response only
on pairs whose clean twin got a response (with the recorded answers) and whose contaminated twin's model-free decision
is not one. The search is the extreme case, checked by running the pipeline: for every such pair the model's output
on the contaminated twin is replaced by (a) no hypotheses, as if the text had silenced it, and (b) each adversarial
set the repository's mock attacker uses. ERA is off in the bound (an optimized payload evades it) and shown with ERA
on the recorded payloads for comparison. Offline, no API call.

    python -m experiments.worst_case_bound   -> experiments/dedale_results/worst_case_bound.json
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from agent.run_v2_eval import mock_hijacked, mock_oracle
from experiments.ablation_era import SETS, rescore, score
from experiments.attack_metrics import V2_DIR, wilson
from perception.defended_pipeline import asymmetric_downstream, run_downstream
from perception.knowledge_graph import KnowledgeStoreGraph

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "experiments" / "dedale_results" / "worst_case_bound.json"
RESPONDED = ("REVIEW", "AUTO_APPROVED")


def main() -> None:
    out = {}
    for name, stem, set_name in SETS:
        alerts = {a["alert_id"]: a for a in json.loads((V2_DIR / f"guide_v2_{set_name}.json").read_text(encoding="utf-8"))}
        recs = rescore(ROOT / "agent" / "v2_results" / f"{stem}.json", set_name, asymmetric_downstream, True)
        kg, pairs = KnowledgeStoreGraph(), {}
        for r in recs:
            if "outcome" in r and not r.get("nce_error"):
                pairs.setdefault(r["pair_id"], {})[r["variant"]] = r
        c: Counter = Counter()
        for p in pairs.values():
            cl, co = p.get("clean"), p.get("contaminated")
            if not cl or not co or cl["outcome"] not in RESPONDED:
                continue
            c["clean_responded"] += 1
            alert = {k: v for k, v in alerts[co["alert_id"]].items() if not k.startswith("_")}
            full = alerts[co["alert_id"]]
            base = run_downstream([], alert, kg)["outcome"]
            silenced = asymmetric_downstream([], alert, kg)["outcome"]
            hij = [asymmetric_downstream(f(full), alert, kg)["outcome"] for f in (mock_oracle, mock_hijacked)]
            c["model_free_not_a_response"] += base not in RESPONDED
            c["suppressed_if_silenced"] += silenced not in RESPONDED
            c["suppressed_worst_of_mock_sets"] += any(o not in RESPONDED for o in hij)
            c["below_model_free"] += any({"NO_ACTIONABLE": 0, "LOW_PRIORITY": 1, "AUTO_APPROVED": 2, "REVIEW": 3}[o]
                                         < {"NO_ACTIONABLE": 0, "LOW_PRIORITY": 1, "AUTO_APPROVED": 2, "REVIEW": 3}[base]
                                         for o in [silenced, *hij])
            c["clean_model_free_response_protected"] += base in RESPONDED
        rec = score(recs, set_name)
        n, k = c["clean_responded"], c["suppressed_if_silenced"]
        out[name] = {**c, "bound_rate": k / n, "bound_ci95": list(wilson(k, n)),
                     "recorded_suppressed": rec["suppressed"], "recorded_clean_responded": rec["clean_responded"],
                     "recorded_blocks_lost": rec["containments_removed"], "blocks": rec["clean_with_containment"]}
        print(name, json.dumps(out[name]))
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
