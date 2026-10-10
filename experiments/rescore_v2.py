"""
experiments/rescore_v2.py

Offline re-score of a corpus-v2 live results file with the CURRENT downstream
code (Phase 4 step 4.2, 2026-10-11).  No API call: NCE's stored hypotheses
are replayed through perception.defended_pipeline.run_downstream.

Records with `nce_hypotheses` (raw NCE output, stored since step 4.2) are
replayed exactly.  Older records (the step-4.1 pilot) are rebuilt from their
hypothesis rows; NCE confidence and evidence refs are not stored there, and
neither is used downstream (grounding is re-labelled from the alert).

    python -m experiments.rescore_v2 agent/v2_results/v2_dev_live_results.json [--set dev]
    -> logs/<input stem>_rescored.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from perception.defended_pipeline import run_downstream
from perception.entity_binding import TELEMETRY_REF
from perception.knowledge_graph import KnowledgeStoreGraph
from perception.nce_contract import MissingContextFlag, NCEHypothesis

PROJECT_ROOT = Path(__file__).resolve().parent.parent
V2_DIR = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2"


def rebuild(rec: dict) -> list[NCEHypothesis]:
    if "nce_hypotheses" in rec:
        rows = rec["nce_hypotheses"]
    else:
        rows = [h for h in rec.get("hypotheses", []) if TELEMETRY_REF not in (h.get("supporting_evidence_refs") or [])]
    return [NCEHypothesis(
        technique_id=h["technique_id"], source_account=h.get("source_account") or "",
        source_host=h.get("source_host") or "", target_host=h.get("target_host") or "",
        nce_confidence=float(h.get("nce_confidence", 0.5)),
        supporting_evidence_refs=list(h.get("supporting_evidence_refs") or ["raw_log_line"]),
        missing_context_flags=[MissingContextFlag(f) for f in h.get("missing_context_flags") or []],
    ) for h in rows]


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    src = Path(args[0])
    set_name = args[args.index("--set") + 1] if "--set" in args else "dev"
    alerts = {a["alert_id"]: a for a in json.loads((V2_DIR / f"guide_v2_{set_name}.json").read_text(encoding="utf-8"))}
    kg = KnowledgeStoreGraph()
    out = []
    for rec in json.loads(src.read_text(encoding="utf-8")):
        if rec.get("nce_error") or "outcome" not in rec:
            out.append(rec)
            continue
        alert = {k: v for k, v in alerts[rec["alert_id"]].items() if not k.startswith("_")}
        new = {k: v for k, v in rec.items() if k not in ("hypotheses", "outcome", "outcome_reasons")}
        new.update(run_downstream(rebuild(rec), alert, kg))
        out.append(new)
    dst = PROJECT_ROOT / "logs" / f"{src.stem}_rescored.json"
    dst.parent.mkdir(exist_ok=True)
    dst.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"{len(out)} records -> {dst}")


if __name__ == "__main__":
    main()
