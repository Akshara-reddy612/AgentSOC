"""
experiments/a8_foothold_runs.py

Checklist A8, the in-threat-model attacker (2026-11-23): plants only after its own first labelled event on each host
(`--plant foothold`, experiments/dedale_plant.py), PowerShell keys included. Offline, NCE off. Scores every run with
the host scorer of experiments/tier1_score.py.

    python -m experiments.a8_foothold_runs          -> replays, then experiments/dedale_results/a8_foothold_scores.json
    python -m experiments.a8_foothold_runs --score  -> scoring only
"""
from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "experiments" / "dedale_results" / "a8_foothold_scores.json"
P = ["--plant", "foothold", "--plant-detectors", "lineage", "exec_file_write", "pipe", "powershell"]
A = ["--mode", "gated", "--analyst", "oracle"]


def miss(seed: int) -> list[str]:
    return ["--analyst-miss", "0.2", "--analyst-seed", str(seed)]


JOBS = {
    "A8f_gated": ["--mode", "gated", *P],
    "A8f_d4": [*A, *P],
    "A8f_d4_nob5": [*A, *P, "--no-unlearn"],
    "A8f_d4_xh": [*A, *P, "--unlearn-scope", "all"],
    **{f"A8f_m20_s{s}": [*A, *P, *miss(s)] for s in range(6)},
    **{f"A8f_m20_nob5_s{s}": [*A, *P, *miss(s), "--no-unlearn"] for s in range(6)},
}


def run(tag: str) -> tuple[str, int]:
    with open(ROOT / "logs" / f"replay_{tag}.txt", "w", encoding="utf-8") as out:
        return tag, subprocess.call([sys.executable, "-m", "experiments.dedale_host_replay", *JOBS[tag], "--tag", tag,
                                     "--overwrite"], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)


def score() -> None:
    from experiments.a8_score import planting_cost
    from experiments.dedale_host_novelty import load_host_labels
    from experiments.tier1_score import _host
    labels, out = load_host_labels(), {}
    for tag, args in JOBS.items():
        name = ("gated_analyst_" if "--analyst" in args else "gated_") + tag
        out[tag] = {"run": name, **_host(name, labels), **planting_cost(name)}
        r = out[tag]
        print(f"{tag:18s} cases {r['attack_cases_raised']:3} events {r['class1_events_alerted']:3} learned "
              f"{r['attack_cases_learned']:3} reviews/day {r['reviews_per_day']} TTD {r['time_to_detect_min']} plants "
              f"{r['planted_alerted']}/{r['planted_events']}")
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")


def main() -> None:
    if "--score" not in sys.argv:
        with ThreadPoolExecutor(6) as ex:
            for tag, rc in ex.map(run, JOBS):
                print(f"{tag}: rc={rc}", flush=True)
                if rc:
                    raise SystemExit(f"{tag} failed")
    score()


if __name__ == "__main__":
    main()
