"""
experiments/a4_optimized_summary.py

Checklist A4 (2026-11-24): what the optimized attacker's log says beyond a4_optimized.py's per-pair score. Offline.
The 20 attackable pairs split into the 7 whose recorded contaminated twin was suppressed and the 13 others. Counted: the
fresh answers on the clean twin (controls) and on the attacker's payloads that gave no response.

    python -m experiments.a4_optimized_summary   -> experiments/dedale_results/a4_optimized_summary.json
"""
from __future__ import annotations

import json
from pathlib import Path

from experiments.a4_optimized import LOG, RESPONDED, Run, build, offline_era, targets

OUT = Path(__file__).resolve().parent / "dedale_results" / "a4_optimized_summary.json"


def main() -> None:
    run, out = Run(None, None, offline_era(), LOG, 0), {"answered_calls": 0, "nce_failed": 0, "groups": {}}
    out["answered_calls"] = len(run.cache)
    out["nce_failed"] = sum(r["kind"] == "nce" and r["hypotheses"] is None for r in run.cache.values())
    out["era_not_low"] = 0
    for t in targets():
        pid, clean = t["pair_id"], t["clean"]
        g = out["groups"].setdefault(f"{t['set']}/{'recorded suppressed' if t['recorded_suppressed'] else 'not recorded suppressed'}",
                                     {"pairs": 0, "pairs_control_suppressed": 0, "pairs_attack_suppressed": 0, "pairs_attack_confirmed": 0,
                                      "control_answers": 0, "control_suppressed": 0, "attack_answers": 0, "attack_suppressed": 0,
                                      "first_control_responded": 0, "attack_confirmed_control_responded": 0})
        ctrl, att, conf = [], [], False
        era0 = run.level(clean)
        byit: dict = {}
        for k, r in run.cache.items():
            if not k.startswith(pid + "|"):
                continue
            kind = k.split("|")[1]
            if kind == "control":
                ctrl.append(run.judge(clean, r, era0)["outcome"] not in RESPONDED)
            elif r["kind"] == "nce":
                a = build(clean, r["payload"]["site"], r["payload"]["text"])
                lv = run.level(a)
                out["era_not_low"] += lv != "LOW"
                s = run.judge(a, r, lv)["outcome"] not in RESPONDED
                att.append(s)
                it = k.split("|")[2] if kind == "query" else kind.removeprefix("confirm")
                byit.setdefault(it, []).append(s)
        conf = any(sum(v) >= 2 for v in byit.values())
        g["pairs"] += 1
        g["pairs_control_suppressed"] += any(ctrl)
        g["pairs_attack_suppressed"] += any(att)
        g["pairs_attack_confirmed"] += conf
        g["control_answers"] += len(ctrl)
        g["control_suppressed"] += sum(ctrl)
        g["attack_answers"] += len(att)
        g["attack_suppressed"] += sum(att)
        g["attack_confirmed_control_responded"] += conf and not any(ctrl)
    for v in out["groups"].values():
        v.pop("first_control_responded")
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
