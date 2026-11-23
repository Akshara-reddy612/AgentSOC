"""
experiments/ps_fulltext_runs.py

2026-11-23: fingerprint the whole PowerShell script (`--script-full-text`, off by default) instead of its first 160
characters, against planted scripts that share the attack scripts' prefix (experiments/dedale_plant.py). Offline, NCE
off. Designed after the prefix weakness was found, on the same campaign.

    python -m experiments.ps_fulltext_runs [--score]   -> experiments/dedale_results/ps_fulltext_scores.json
"""
from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "experiments" / "dedale_results" / "ps_fulltext_scores.json"
A = ["--mode", "gated", "--analyst", "oracle"]
P = ["--plant", "test", "--plant-detectors", "lineage", "exec_file_write", "pipe", "powershell"]
XH, FULL = ["--unlearn-scope", "all"], ["--script-full-text"]
JOBS = {
    "PS_check_gated": ["--mode", "gated"],              # default: must equal F_gated
    "PS_160_test_d4_xh": [*A, *P, *XH],                 # prefix-sharing plants, 160 characters
    "PS_full_gated": ["--mode", "gated", *FULL],
    "PS_full_d4": [*A, *FULL],
    "PS_full_test_d4": [*A, *P, *FULL],
    "PS_full_test_d4_xh": [*A, *P, *XH, *FULL],
}


def run(tag: str) -> tuple[str, int]:
    with open(ROOT / "logs" / f"replay_{tag}.txt", "w", encoding="utf-8") as out:
        return tag, subprocess.call([sys.executable, "-m", "experiments.dedale_host_replay", *JOBS[tag], "--tag", tag,
                                     "--overwrite"], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)


def main() -> None:
    if "--score" not in sys.argv:
        with ThreadPoolExecutor(6) as ex:
            for tag, rc in ex.map(run, JOBS):
                if rc:
                    raise SystemExit(f"{tag} failed")
    from dedale import data_dir
    from experiments.dedale_host_novelty import load_host_labels
    from experiments.tier1_score import _host
    labels, out, runs = load_host_labels(), {}, data_dir().parent / "runs"
    for tag, args in JOBS.items():
        name = ("gated_analyst_" if "--analyst" in args else "gated_") + tag
        r = out[tag] = {"run": name, **_host(name, labels)}
        print(f"{tag:20s} cases {r['attack_cases_raised']:3} events {r['class1_events_alerted']:3} reviews/day "
              f"{r['reviews_per_day']} TTD {r['time_to_detect_min']}")
    out["default_identical_to_F_gated"] = ((runs / "dedale_host_gated_PS_check_gated" / "cases.jsonl").read_bytes()
                                           == (runs / "dedale_host_gated_F_gated" / "cases.jsonl").read_bytes())
    print("default identical to F_gated:", out["default_identical_to_F_gated"])
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
