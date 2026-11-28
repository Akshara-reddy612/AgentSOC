"""
experiments/p9b_runs.py

Decision P9 B (2026-11-28): corroborated learning against the precursor attack, offline replays (no API call,
NCE off). Design: experiments/P9B_CORROBORATED_LEARNING_DESIGN.md. Rules (replay flags, all off by default):
R1 `--corroboration fleet`, R1b `--corroboration fleet_verdicts`, R4 `--train-corroboration`, R6
`--follow-patterns`. Each job's baseline is the recorded run with the same arguments and no rule (BASELINES).

    python -m experiments.p9b_runs [--workers 7] [--redo]   -> D:/agentsoc_data/runs/dedale_host_*_P9B_*
    (a job whose summary.json exists is skipped unless --redo; logs in logs/replay_P9B_*.txt)
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dedale import data_dir

ROOT = Path(__file__).resolve().parent.parent
RUNS = data_dir().parent / "runs"
RULES = {"R1": ["--corroboration", "fleet"], "R1b": ["--corroboration", "fleet_verdicts"],
         "R4": ["--train-corroboration"], "R6": ["--follow-patterns"]}
ORACLE = ["--analyst", "oracle", "--case-store"]                   # as the frozen F_ runs and tier1_runs
ANALYST = ["--mode", "gated", "--analyst", "oracle"]               # as a8_runs / a8_foothold_runs
P_ALL = ["--plant-detectors", "lineage", "exec_file_write", "pipe", "powershell"]
SLOW = ["--gate-from", "2024-12-30", "--plant", "slow", *P_ALL]    # as a8_gate_runs (plants from 2024-12-30)

JOBS: dict[str, list[str]] = {}
BASELINES: dict[str, str] = {}      # job tag -> recorded run name (dedale_host_<name>)


def _add(tag: str, args: list[str], baseline: str) -> None:
    JOBS[tag] = args
    BASELINES[tag] = baseline


# Cost on clean traffic: analyst 4 h (deterministic at 0% misses) and 20% misses over the six recorded seeds.
for rule in ("R1", "R1b", "R4"):
    _add(f"P9B_{rule}_d4", ["--mode", "gated", *ORACLE, *RULES[rule]], "gated_analyst_F_d4")
    _add(f"P9B_{rule}_m20_s0", ["--mode", "gated", *ORACLE, "--analyst-miss", "0.2", *RULES[rule]],
         "gated_analyst_F_m20")
    for s in range(1, 6):
        _add(f"P9B_{rule}_m20_s{s}", ["--mode", "gated", *ORACLE, "--analyst-miss", "0.2", "--analyst-seed", str(s),
                                      *RULES[rule]], f"gated_analyst_T1_m20_s{s}")
_add("P9B_R6_d4", ["--mode", "gated", *ORACLE, *RULES["R6"]], "gated_analyst_F_d4")   # R6 cost (added after the first scoring)
# The precursor attack with the analyst (4 h, B5 on).
for rule in ("R1", "R1b", "R4", "R6"):
    _add(f"P9B_{rule}_test", [*ANALYST, "--plant", "test", *RULES[rule]], "gated_analyst_A8_test_d4")
    _add(f"P9B_{rule}_train", [*ANALYST, "--plant", "train", *RULES[rule]], "gated_analyst_A8_train_d4")
    _add(f"P9B_{rule}_foothold", [*ANALYST, "--plant", "foothold", *P_ALL, *RULES[rule]], "gated_analyst_A8f_d4")
_add("P9B_base_slow", [*ANALYST, *SLOW], "gated_analyst_P9B_base_slow")       # no recorded slow + analyst run
for rule in ("R1", "R1b", "R6"):                                               # R4 acts on training, before the slow plants
    _add(f"P9B_{rule}_slow", [*ANALYST, *SLOW, *RULES[rule]], "gated_analyst_P9B_base_slow")
# The gate path: slow plants with D7 off and no analyst (as a8_gate_runs A8g_off_slow_24).
for rule in ("R1", "R1b"):
    _add(f"P9B_{rule}_gate_slow", ["--mode", "gated", "--gate-from", "2024-12-30", "--unreasoned", "no_actionable",
                                   "--gate-delay", "24", "--plant", "slow", *P_ALL, *RULES[rule]],
         "gated_A8g_off_slow_24")


# Added 2026-11-28 (later): R1b against the host-wide persuaded analyst (A10, recorded NCE answers, no API call),
# and R1b with one corroborating host (M = 1) instead of two.
PERSUADED = ["--mode", "gated", "--nce", "cache", "--analyst", "oracle", "--case-store", "--llm-authority", "escalate",
             "--inject", "fake_approval", "--analyst-persuaded", "1.0", "--persuasion", "host", "--analyst-seed", "0"]
_add("P9B_R1b_persuaded", [*PERSUADED, *RULES["R1b"]], "gated_nce_analyst_Phost_q100_m00_s0_fake_approval")
_add("P9B_R1b_persuaded_nob5", [*PERSUADED, "--no-unlearn", *RULES["R1b"]],
     "gated_nce_analyst_Phost_q100_m00_nob5_s0_fake_approval")
M1 = [*RULES["R1b"], "--corroboration-hosts", "1"]
_add("P9B_R1bM1_d4", ["--mode", "gated", *ORACLE, *M1], "gated_analyst_F_d4")
_add("P9B_R1bM1_test", [*ANALYST, "--plant", "test", *M1], "gated_analyst_A8_test_d4")
_add("P9B_R1bM1_slow", [*ANALYST, *SLOW, *M1], "gated_analyst_P9B_base_slow")


def run_name(tag: str) -> str:
    """dedale_host_<run> name the replay gives this job (dedale_host_replay: mode, _nce, _analyst, _tag)."""
    a = JOBS[tag]
    nce = "--nce" in a and a[a.index("--nce") + 1] != "off"
    return a[a.index("--mode") + 1] + ("_nce" if nce else "") + ("_analyst" if "oracle" in a else "") + f"_{tag}"


def run(tag: str, redo: bool) -> tuple[str, int | str]:
    if not redo and (RUNS / f"dedale_host_{run_name(tag)}" / "summary.json").exists():
        return tag, "skipped (done)"
    with open(ROOT / "logs" / f"replay_{tag}.txt", "w", encoding="utf-8") as out:
        rc = subprocess.call([sys.executable, "-m", "experiments.dedale_host_replay", *JOBS[tag], "--tag", tag,
                              "--overwrite"], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    return tag, rc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=7)
    ap.add_argument("--redo", action="store_true")
    ap.add_argument("--only", nargs="+", default=None, help="job tags to run (default: all)")
    args = ap.parse_args()
    tags = args.only or list(JOBS)
    with ThreadPoolExecutor(args.workers) as ex:
        for tag, rc in ex.map(lambda t: run(t, args.redo), tags):
            print(f"{tag}: rc={rc}", flush=True)


if __name__ == "__main__":
    main()
