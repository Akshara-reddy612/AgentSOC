"""
experiments/ablation_era.py

Checklist A3 (ablation, 2026-11-22): GUIDE with ERA switched off. The same recorded LLM answers as the C1 table
(agent/v2_results/*_live*_results.json), re-scored exactly as experiments/rescore_v2.py does but with no ERA level,
under both rules (acting / asymmetric trust). Offline, no API call; writes nothing under agent/v2_results/.

    python -m experiments.ablation_era   -> prints; writes experiments/dedale_results/ablation_era.json
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from experiments.attack_metrics import V2_DIR, summarize
from experiments.build_results import _containment_removed, _induced_by_era
from experiments.rescore_v2 import rebuild
from experiments.undefended_metrics import mcnemar
from perception.defended_pipeline import asymmetric_downstream, run_downstream
from perception.knowledge_graph import KnowledgeStoreGraph

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "experiments" / "dedale_results" / "ablation_era.json"
SETS = [("dev, gemini-3.1-flash-lite", "v2_dev_live_results", "dev"),
        ("held-out, gemini-3.1-flash-lite", "v2_heldout_live_results", "heldout"),
        ("dev, gpt-oss-20b", "v2_dev_live_groq-openai-gpt-oss-20b_results", "dev")]


def rescore(src: Path, set_name: str, downstream, use_era: bool) -> list[dict]:
    alerts = {a["alert_id"]: a for a in json.loads((V2_DIR / f"guide_v2_{set_name}.json").read_text(encoding="utf-8"))}
    era = {}
    if use_era:
        from experiments.era_offline import level_of
        era_path = ROOT / "agent" / "v2_results" / f"era_scores_{set_name}.json"
        era = {r["alert_id"]: level_of(r) for r in json.loads(era_path.read_text(encoding="utf-8"))}
    kg = KnowledgeStoreGraph()
    out = []
    for rec in json.loads(src.read_text(encoding="utf-8")):
        if rec.get("nce_error") or "outcome" not in rec:
            out.append(rec)
            continue
        alert = {k: v for k, v in alerts[rec["alert_id"]].items() if not k.startswith("_")}
        new = {k: v for k, v in rec.items() if k not in ("hypotheses", "outcome", "outcome_reasons")}
        new.update(downstream(rebuild(rec), alert, kg, era_level=era.get(rec["alert_id"])))
        new["era_level"] = era.get(rec["alert_id"])
        out.append(new)
    return out


def score(results: list[dict], set_name: str) -> dict:
    alerts = json.loads((V2_DIR / f"guide_v2_{set_name}.json").read_text(encoding="utf-8"))
    t = Counter()
    for f in summarize(results, alerts)["families"].values():
        for k in ("pairs", "clean_responded", "suppressed", "induced_response", "misdirect_executed", "misdirect_gated"):
            t[k] += f.get(k, 0)
    era = _induced_by_era(results, alerts)
    removed, with_one, _ = _containment_removed(results)
    oc = Counter(r["outcome"] for r in results if "outcome" in r and not r.get("nce_error"))
    return {"pairs": t["pairs"], "clean_responded": t["clean_responded"], "suppressed": t["suppressed"],
            "induced_by_era": era, "induced_otherwise": t["induced_response"] - era,
            "mcnemar_p": mcnemar(t["suppressed"], t["induced_response"] - era),
            "misdirect_executed": t["misdirect_executed"], "misdirect_gated": t["misdirect_gated"],
            "containments_removed": removed, "clean_with_containment": with_one, "outcomes": dict(oc)}


def main() -> None:
    out = {}
    for name, stem, set_name in SETS:
        src = ROOT / "agent" / "v2_results" / f"{stem}.json"
        for rule, ds in (("acting", run_downstream), ("asymmetric", asymmetric_downstream)):
            for era in (True, False):
                key = f"{name} | {rule} | ERA {'on' if era else 'off'}"
                r = out[key] = score(rescore(src, set_name, ds, era), set_name)
                print(f"{key:55s} suppressed {r['suppressed']:3}/{r['clean_responded']} | induced ERA {r['induced_by_era']:2} "
                      f"other {r['induced_otherwise']:2} | misdirected exec/gated {r['misdirect_executed']}/"
                      f"{r['misdirect_gated']} | containments removed {r['containments_removed']}/"
                      f"{r['clean_with_containment']} | REVIEW {r['outcomes'].get('REVIEW', 0)}")
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
