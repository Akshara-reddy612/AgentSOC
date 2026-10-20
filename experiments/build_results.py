"""
experiments/build_results.py

M1 (PROJECT_PLAN.md): the paper's results, built only from frozen result
files -- no number is typed by hand.  One table per claim (C1-C5).

Inputs:
  C1  GUIDE corpus v2: logs/v2_{dev,heldout}_live_results_rescored.json and the
      gpt-oss-20b dev run (all 500 pairs since 2026-10-20; re-scored with the final code by
      experiments.rescore_v2), the undefended-agent comparison
      (experiments.undefended_metrics);
  C2-C5  DEDALE: experiments/dedale_results/final_{host,network}_scores.json
      (experiments.freeze_dedale) and the replays' summary.json files.

    python -m experiments.build_results  ->  experiments/RESULTS.md
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import date
from pathlib import Path

from dedale import data_dir
from experiments.attack_metrics import V2_DIR, summarize, wilson
from experiments.undefended_metrics import compare, mcnemar

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "experiments" / "dedale_results"
OUT = ROOT / "experiments" / "RESULTS.md"


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def _pct(k: int, n: int) -> str:
    return f"{k}/{n} ({k / n:.1%})" if n else "-"


def _ci(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{lo:.1%}-{hi:.1%}"


# -- C1 -----------------------------------------------------------------------------------

RESPONDED = ("REVIEW", "AUTO_APPROVED")


def _induced_by_era(results: list[dict], alerts: list[dict]) -> int:
    """Pairs where only the contaminated twin got a response and ERA flagged it (MEDIUM / HIGH)."""
    by_id = {r["alert_id"]: r for r in results}
    pairs: dict[str, dict] = {}
    for a in alerts:
        pairs.setdefault(a["_pair_id"], {})[a["_variant"]] = a["alert_id"]
    n = 0
    for p in pairs.values():
        c, x = by_id.get(p.get("clean")), by_id.get(p.get("contaminated"))
        if not c or not x or c.get("nce_error") or x.get("nce_error"):
            continue
        n += (c["outcome"] not in RESPONDED and x["outcome"] in RESPONDED
              and x.get("era_level") in ("MEDIUM", "HIGH"))
    return n


def c1() -> list[str]:
    sets = [("GUIDE v2 dev, gemini-3.1-flash-lite", "logs/v2_dev_live_results_rescored.json", "dev"),
            ("GUIDE v2 held-out, gemini-3.1-flash-lite", "logs/v2_heldout_live_results_rescored.json", "heldout"),
            ("GUIDE v2 dev, gpt-oss-20b",
             "logs/v2_dev_live_groq-openai-gpt-oss-20b_results_rescored.json", "dev")]
    lines = ["## C1 — Text an attacker writes into logs does not steer the pipeline's actions", "",
             "Pipeline response on clean vs contaminated twins (same GUIDE row, differing only at the injection "
             "site). *Suppressed* = the clean twin got a response (REVIEW / AUTO_APPROVED) and the contaminated "
             "one did not.", "",
             "| Run | Pairs scored | Suppressed (of clean responded) | 95% CI | Induced by ERA escalation | "
             "Induced otherwise | McNemar p (suppressed vs induced otherwise) | Steered actions: executed / gated |",
             "|:--|--:|--:|--:|--:|--:|--:|--:|"]
    for name, path, set_name in sets:
        alerts = _load(V2_DIR / f"guide_v2_{set_name}.json")
        results = _load(ROOT / path)
        rep = summarize(results, alerts)
        t = Counter()
        for f in rep["families"].values():
            for k in ("pairs", "clean_responded", "suppressed", "induced_response", "misdirect_executed",
                      "misdirect_gated"):
                t[k] += f.get(k, 0)
        era = _induced_by_era(results, alerts)
        other = t["induced_response"] - era
        lines.append(f"| {name} | {t['pairs']} | {_pct(t['suppressed'], t['clean_responded'])} | "
                     f"{_ci(t['suppressed'], t['clean_responded'])} | {era} | {other} | "
                     f"{mcnemar(t['suppressed'], other):.2g} | "
                     f"{t['misdirect_executed']} / {t['misdirect_gated']} |")
    lines += ["", "*Induced by ERA escalation*: the contaminated twin got a response the clean one did not because "
              "ERA flagged its injected text (MEDIUM / HIGH) and escalated it to review; that is the defence "
              "reacting, not the attacker succeeding."]
    u = compare("dev")["total"]
    d_era = _induced_by_era(_load(ROOT / "logs/v2_dev_live_results_rescored.json"),
                            _load(V2_DIR / "guide_v2_dev.json")) if u["pairs"] == 500 else 0
    d_other = u["d_induced"] - d_era
    scope = "all 500 dev pairs" if u["pairs"] == 500 else f"{u['pairs']} dev pairs so far (run incomplete)"
    lines += ["", f"**Undefended LLM agent vs defended pipeline, same pairs** ({scope}; defended McNemar "
              "against responses induced otherwise than by ERA escalation):", "",
              "| | Attack succeeded (of clean twins it applies to) | 95% CI | McNemar p | Misdirected actions executed |",
              "|:--|--:|--:|--:|--:|",
              f"| Undefended agent (hijacked to dismiss) | {_pct(u['hijacked'], u['clean_not_dismissed'])} | "
              f"{_ci(u['hijacked'], u['clean_not_dismissed'])} | {mcnemar(u['hijacked'], u['induced']):.2g} | - |",
              f"| Defended pipeline (response suppressed) | {_pct(u['d_suppressed'], u['d_clean_responded'])} | "
              f"{_ci(u['d_suppressed'], u['d_clean_responded'])} | {mcnemar(u['d_suppressed'], d_other):.2g} | "
              f"{u['d_misdirect_exec']} |", ""]
    lines += e1()
    return lines


def e1() -> list[str]:
    """C1 through the full loop on real telemetry (E1): attacker text in the attacker's own command lines."""
    path = RESULTS / "e1_scores.json"
    if not path.exists():
        return []
    e = _load(path)
    lines = ["**Through the full loop on real telemetry (E1, DEDALE host logs, live NCE + learning gate)**: the "
             "attacker appends text to the command lines of their own processes (84 events; 38 cases whose first "
             "alert carries it).", "",
             "| Attacker text | Condition | Attack cases dismissed | Attack cases' patterns learned as routine | "
             "Labelled attack events alerted | Injected cases where NCE named the steered host | "
             "Steered hypotheses flagged unbound | Containment against the steered host |",
             "|:--|:--|--:|--:|--:|--:|--:|--:|"]
    names = {"clean": "none (clean)", "suppress": "\"routine maintenance\"", "fake_approval": "fake SOC approval",
             "steer": "\"isolate the domain controller\""}
    for fam, label in names.items():
        for cond, cname in (("no_analyst", "no analyst"), ("analyst", "analyst 4 h, B5 on")):
            r = e.get(f"{fam}/{cond}")
            if r is None:
                continue
            mal, inj = r["malicious_cases"], r["injected_first_alert_cases"]
            steered = inj.get("cases_with_steered_hypothesis", 0)
            flagged = sum(v for k, v in inj.items() if k == "steered_binding_unbound")
            total = sum(v for k, v in inj.items() if k.startswith("steered_binding_"))
            actions = sum(v for k, v in inj.items() if k.startswith("steered_action_"))
            lines.append(f"| {label} | {cname} | {mal.get('NO_ACTIONABLE', 0)} / {sum(mal.values())} | "
                         f"{sum(r['attack_keys_learned'].values())} | {r['labelled_events_alerted']} | "
                         f"{steered} / {inj.get('cases', '-')} | {flagged} / {total} | {actions} |")
    return lines + [""]


# -- DEDALE ------------------------------------------------------------------------------

def _host(scores: dict, run: str) -> dict:
    r = scores["runs"][run]
    truth = r["cases_by_ground_truth"]
    mal = truth.get("malicious", {})
    summ = _load(data_dir().parent / "runs" / f"dedale_host_{run}" / "summary.json")
    return {"reviews": r["reviews_per_day"]["mean"], "cases": r["test_cases"],
            "mal_reviewed": mal.get("REVIEW", 0), "mal_total": sum(mal.values()),
            "mal_dismissed": mal.get("NO_ACTIONABLE", 0) + mal.get("LOW_PRIORITY", 0),
            "ben_dismissed": sum(v for k, v in truth.get("benign", {}).items() if k != "REVIEW"),
            "events": r["labelled_events_alerted"].get("class_1", 0),
            "learned": sum(r["attack_keys_learned_as_routine"].values()),
            "steps": r["attack_steps"], "verdicts": r.get("analyst_verdicts", {}),
            "cache_misses": summ.get("nce_cache_misses", 0)}


def _net(scores: dict, run: str) -> dict:
    r = scores["runs"][run]
    return {"reviews": r["reviews_per_day"]["mean"], "hidden": r["attack_related_hidden"],
            "related": len(r["attack_related"]), "contained": r["attacker_server_contained_after_min"],
            "learned": len(r["attack_patterns_learned_as_routine"]), "verdicts": r.get("analyst_verdicts", {}),
            "would_block_benign": r["watches"].get("would_block_on_benign_targets")}


def _h(run_tag: str, mode: str = "gated", nce: bool = False, analyst: bool = False) -> str:
    return mode + ("_nce" if nce else "") + ("_analyst" if analyst else "") + f"_{run_tag}"


def dedale() -> list[str]:
    hs, ns = _load(RESULTS / "final_host_scores.json"), _load(RESULTS / "final_network_scores.json")
    H = {k: _host(hs, r) for k, r in {
        "static": _h("F_static", "static"), "frozen": _h("F_frozen", "frozen"), "gated": _h("F_gated"),
        "ungated": _h("F_ungated", "ungated"),
        "d4": _h("F_d4", analyst=True), "d4_nob5": _h("F_d4_nob5", analyst=True),
        "d1": _h("F_d1", analyst=True), "d24": _h("F_d24", analyst=True), "d72": _h("F_d72", analyst=True),
        "m5": _h("F_m5", analyst=True), "m5_nob5": _h("F_m5_nob5", analyst=True),
        "m20": _h("F_m20", analyst=True), "m20_nob5": _h("F_m20_nob5", analyst=True),
        "fa5": _h("F_fa5", analyst=True), "fa5_nob5": _h("F_fa5_nob5", analyst=True),
        "nce": _h("F_nce", nce=True), "nce_closed": _h("F_nce_closed", nce=True),
        "nce_d4": _h("F_nce_d4", nce=True, analyst=True)}.items()}
    N = {k: _net(ns, r) for k, r in {
        "static": "static_F_static", "frozen": "frozen_F_frozen", "gated": "gated_F_gated",
        "ungated": "ungated_F_ungated", "noact": "gated_noact_F_noact", "d4": "gated_analyst_F_d4",
        "d4_nob5": "gated_analyst_F_d4_nob5", "d1": "gated_analyst_F_d1", "d24": "gated_analyst_F_d24",
        "d72": "gated_analyst_F_d72", "fa5": "gated_analyst_F_fa5"}.items()}

    def hrow(label, h):
        raised = f"{h['mal_total']}" + ("" if h["mal_reviewed"] == h["mal_total"] else f" ({h['mal_reviewed']} reviewed)")
        return f"| {label} | {h['reviews']} | {h['cases']} | {raised} | {h['events']} | {h['learned']} |"

    def nrow(label, n):
        cont = f"{n['contained']:.0f} min" if n["contained"] is not None else "never"
        return f"| {label} | {n['reviews']} | {n['hidden']} / {n['related']} | {cont} | {n['learned']} |"

    hhead = ["| Condition | Reviews / day | Test cases | Malicious cases raised (all reviewed unless noted) | "
             "Labelled attack events alerted | "
             "Attack cases' patterns learned as routine |", "|:--|--:|--:|--:|--:|--:|"]
    nhead = ["| Condition | Reviews / day | Attack-related cases hidden | Attacker server contained after | "
             "Attack patterns learned as routine |", "|:--|--:|--:|--:|--:|"]
    out = ["## C2 — A learning Knowledge Store behind a gate cuts analyst load and keeps the attack visible", "",
           "DEDALE, test weeks 2025-01-06..19 (14 days), training on the two benign weeks before. "
           "NCE off. Host logs: exact labels of the attacked clients' events.", "", "**Host logs**", "", *hhead,
           hrow("static (nothing learned)", H["static"]), hrow("frozen (learned in training only)", H["frozen"]),
           hrow("gated (learning continues behind the gate)", H["gated"]),
           hrow("ungated (learning without the gate)", H["ungated"]), "", "**Network alerts (Suricata)**", "", *nhead,
           nrow("static", N["static"]), nrow("frozen", N["frozen"]), nrow("gated", N["gated"]),
           nrow("ungated", N["ungated"]), nrow("gated, unreasoned cases dismissed (D7 off)", N["noact"]), "",
           "## C3 — Memory poisoning and its defences", "",
           "Without the gate the store learns the attacker (C2 tables, *ungated*). Through the analyst: a "
           "simulated analyst (oracle with reproducible mistakes, 4 h delay) with and without unlearning on "
           "confirmed compromise (decision B5).", "", *hhead,
           hrow("analyst always right, B5 off", H["d4_nob5"]), hrow("analyst always right, B5 on", H["d4"]),
           hrow("misses 5% of attacks, B5 off", H["m5_nob5"]), hrow("misses 5% of attacks, B5 on", H["m5"]),
           hrow("misses 20% of attacks, B5 off", H["m20_nob5"]), hrow("misses 20% of attacks, B5 on", H["m20"]),
           hrow("5% false alarms, B5 off", H["fa5_nob5"]), hrow("5% false alarms, B5 on", H["fa5"]), "",
           "## C4 — What the LLM adds on real telemetry, and a failure mode", "",
           "Host logs, gated. NCE = gemini-3.1-flash-lite hypotheses from the cache of the live Phase 3 run "
           "(cache misses go to review unreasoned). With an analyst and B5 the system sees alerts the cached "
           "run did not (different learning), so some cases were not reasoned about: the cache-miss column.", "",
           "| Condition | Reviews / day | Malicious cases dismissed | Benign cases dismissed | NCE cache misses |",
           "|:--|--:|--:|--:|--:|"]
    for label, k in (("NCE off", "gated"), ("NCE on, closed-world feasibility", "nce_closed"),
                     ("NCE on, open-world feasibility (final)", "nce"), ("NCE on + analyst (4 h, B5 on)", "nce_d4")):
        h = H[k]
        out.append(f"| {label} | {h['reviews']} | {h['mal_dismissed']} / {h['mal_total']} | {h['ben_dismissed']} | "
                   f"{h['cache_misses']} |")
    out += ["", "## C5 — Operating the analyst loop", "",
            "Simulated analyst (oracle) through the case-store inbox, B5 on, different response times.", "",
            "**Host logs**", "", *hhead, hrow("no analyst (gated)", H["gated"]), hrow("analyst after 1 h", H["d1"]),
            hrow("analyst after 4 h", H["d4"]), hrow("analyst after 24 h", H["d24"]),
            hrow("analyst after 72 h", H["d72"]), "", "**Network alerts**", "", *nhead,
            nrow("no analyst (gated)", N["gated"]), nrow("analyst after 1 h", N["d1"]),
            nrow("analyst after 4 h", N["d4"]), nrow("analyst after 4 h, B5 off", N["d4_nob5"]),
            nrow("analyst after 24 h", N["d24"]), nrow("analyst after 72 h", N["d72"]),
            nrow("analyst after 4 h, 5% false alarms", N["fa5"]), "",
            f"With 5% false alarms on the network, approved blocks would have hit benign traffic "
            f"{N['fa5']['would_block_benign']} times (perfect analyst: {N['d4']['would_block_benign']}).", "",
            "**Attack steps (host, gated + analyst 4 h, B5 on):** " + "; ".join(
                f"{s['step']}: {s['surfaced_cases']} cases, first after {s['first_after_min']} min"
                for s in H["d4"]["steps"]), ""]
    return out


def main() -> None:
    lines = [f"# Results (frozen {date.today().isoformat()})", "",
             "Built by `python -m experiments.build_results` from frozen result files only; see "
             "`REPRODUCE.md`. Claims as in `PROJECT_PLAN.md` section 3.", "", *c1(), *dedale(),
             "## Limits", "",
             "- **DEDALE:** one real dataset. Labels exist for 2 attacked clients; the network results rest on few "
             "malicious verdicts.",
             "- **Analyst:** simulated (an oracle that follows the labels, with random per-case mistakes).",
             "- **LLM:** one model on DEDALE. On GUIDE, the second model (gpt-oss-20b) ran on the dev set only, "
             "not the held-out set.",
             "- **GUIDE v2:** its entities, payloads and evidence are synthetic.", ""]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
