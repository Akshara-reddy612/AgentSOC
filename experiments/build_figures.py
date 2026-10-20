"""
experiments/build_figures.py

The paper's figure data, built only from frozen result files (like
experiments/build_results.py): no number is typed by hand.

  paper/fig_reviews_by_day.dat  reviews per day over the 14 DEDALE test days,
                                per learning mode (Fig. 2)
  paper/fig_analyst_delay.dat   analyst delay vs reviews per day (host logs)
                                and the attacker server's containment time
                                (network alerts) (Fig. 3)

    python -m experiments.build_figures
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "experiments" / "dedale_results"
PAPER = ROOT / "paper"

MODES = {"static": "static_F_static", "gated": "gated_F_gated", "ungated": "ungated_F_ungated",
         "analyst": "gated_analyst_F_d4"}
DELAYS = {1: "gated_analyst_F_d1", 4: "gated_analyst_F_d4", 24: "gated_analyst_F_d24", 72: "gated_analyst_F_d72"}


def main() -> None:
    host = json.loads((RESULTS / "final_host_scores.json").read_text(encoding="utf-8"))["runs"]
    net = json.loads((RESULTS / "final_network_scores.json").read_text(encoding="utf-8"))["runs"]

    series = {k: host[r]["reviews_per_day"]["by_day"] for k, r in MODES.items()}
    days = len(series["gated"])
    lines = ["day " + " ".join(MODES)]
    lines += [f"{d + 1} " + " ".join(str(series[k][d]) for k in MODES) for d in range(days)]
    (PAPER / "fig_reviews_by_day.dat").write_text("\n".join(lines) + "\n", encoding="utf-8")

    lines = ["delay_h reviews_per_day contained_after_min no_analyst"]
    base = host["gated_F_gated"]["reviews_per_day"]["mean"]
    for h, r in DELAYS.items():
        lines.append(f"{h} {host[r]['reviews_per_day']['mean']} {net[r]['attacker_server_contained_after_min']} {base}")
    (PAPER / "fig_analyst_delay.dat").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"-> {PAPER / 'fig_reviews_by_day.dat'}, {PAPER / 'fig_analyst_delay.dat'}")


if __name__ == "__main__":
    main()
