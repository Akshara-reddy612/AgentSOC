"""
experiments/a8_gate_runs.py

Checklist A8, poisoning through the learning gate itself (2026-11-23). Training on the first clean week only, gated
operation from 2024-12-30, no analyst, NCE off. The attacker plants harmless runs (experiments/dedale_plant.py):
"slow" over the week before the attack (one per host every 3 h), or "last-minute" on the first attack day. Gate delay
1 / 24 / 72 / 168 h; rule D7 off (an unreasoned case is dismissed, so the gate has candidates) or on (the design).
Offline.

    python -m experiments.a8_gate_runs [--score]   -> experiments/dedale_results/a8_gate_scores.json
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "experiments" / "dedale_results" / "a8_gate_scores.json"
BASE = ["--mode", "gated", "--gate-from", "2024-12-30"]
P = ["--plant-detectors", "lineage", "exec_file_write", "pipe", "powershell"]
OFF = ["--unreasoned", "no_actionable"]
DELAYS = (1, 24, 72, 168)
JOBS: dict[str, list[str]] = {}
for d in DELAYS:
    g = ["--gate-delay", str(d)]
    JOBS[f"A8g_off_none_{d}"] = [*BASE, *OFF, *g]
    JOBS[f"A8g_off_slow_{d}"] = [*BASE, *OFF, *g, "--plant", "slow", *P]
    JOBS[f"A8g_off_last_{d}"] = [*BASE, *OFF, *g, "--plant", "test", *P]
for d in (1, 24):
    JOBS[f"A8g_on_slow_{d}"] = [*BASE, "--gate-delay", str(d), "--plant", "slow", *P]
JOBS["A8g_on_none_24"] = list(BASE)
JOBS["A8g_check_gated"] = ["--mode", "gated"]          # defaults: must equal F_gated


def run(tag: str) -> tuple[str, int]:
    with open(ROOT / "logs" / f"replay_{tag}.txt", "w", encoding="utf-8") as out:
        return tag, subprocess.call([sys.executable, "-m", "experiments.dedale_host_replay", *JOBS[tag], "--tag", tag,
                                     "--overwrite"], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)


def score() -> None:
    from dedale import data_dir
    from experiments.dedale_host_novelty import load_host_labels
    from experiments.dedale_plant import _t, plants
    from experiments.tier1_score import _host
    from perception.host_detection import DETECTORS
    from perception.knowledge_db import KnowledgeDB
    keys = [(DETECTORS[p["planted"]].edge(DETECTORS[p["planted"]].key(p)), _t(p["planted_for"]))
            for _, p in plants("slow", tuple(P[1:]))]
    labels, out, runs = load_host_labels(), {}, data_dir().parent / "runs"
    for tag in JOBS:
        s = json.loads((runs / f"dedale_host_gated_{tag}" / "summary.json").read_text(encoding="utf-8"))
        tmp = tempfile.mkdtemp()                       # the store is read from a copy
        db = KnowledgeDB(shutil.copy(s["store"], tmp))
        prov = {(a, b, k): (pr, at) for a, b, k, pr, at in db.learned_edges({"closed_benign", "training"})}
        hits = [(prov.get((e.src, e.dst, e.key)), first) for e, first in keys]
        r = out[tag] = {"attack_keys": len(keys),
                        "attack_keys_from_training": sum(h is not None and h[0] == "training" for h, _ in hits),
                        "attack_keys_gate_learned_before_first_use": sum(
                            h is not None and h[0] == "closed_benign" and h[1] < first for h, first in hits),
                        "run": f"gated_{tag}", **_host(f"gated_{tag}", labels), "planted_events": s.get("planted_events", 0),
                        "planted_learned": s.get("planted_learned")}
        print(f"{tag:18s} planted learned through gate {r['planted_learned']} of {r['planted_events']} | attack cases "
              f"reviewed {r['attack_cases_reviewed']} raised {r['attack_cases_raised']} events {r['class1_events_alerted']} "
              f"| gate learned {r['gate_learned_closed_benign']} dropped {r['gate_dropped']} | reviews/day {r['reviews_per_day']}")
    out["default_identical_to_F_gated"] = ((runs / "dedale_host_gated_A8g_check_gated" / "cases.jsonl").read_bytes()
                                           == (runs / "dedale_host_gated_F_gated" / "cases.jsonl").read_bytes())
    print("default identical to F_gated:", out["default_identical_to_F_gated"])
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")


def main() -> None:
    if "--score" not in sys.argv:
        with ThreadPoolExecutor(6) as ex:
            for tag, rc in ex.map(run, JOBS):
                if rc:
                    raise SystemExit(f"{tag} failed")
    score()


if __name__ == "__main__":
    main()
