"""
agent/run_v2_eval.py

Defended-pipeline evaluation on corpus v2 pairs (Phase 3 step 3.4, 2026-10-11).

    python -m agent.run_v2_eval --nce mock-oracle   [--set dev|heldout] [--limit N]
    python -m agent.run_v2_eval --nce mock-hijacked [--set dev|heldout] [--limit N]
    python -m agent.run_v2_eval --nce live          [--set dev|heldout] [--limit N]   # API calls

NCE modes:
  mock-oracle    no API.  Hypotheses built from the alert's TRUSTED fields
                 (T1078 for the real account/host; T1071 to the real destination
                 when there is one).  Shows how the downstream layers treat a
                 correct NCE.
  mock-hijacked  no API.  Worst case: on contaminated alerts NCE does exactly
                 what the payload wants — suppress families yield no hypothesis;
                 identity_steering names the steered account/host (T1550);
                 destination_spoof names the spoofed destination.  Clean alerts
                 as mock-oracle.  An upper bound on NCE compromise, used to see
                 which attacks the structural/guardrail layers still stop.
  live           Gemini via perception.nce_engine.generate_hypotheses (API
                 quota; needs GEMINI_API_KEYS).  Must be requested explicitly.

Output: mock modes -> logs/v2_<set>_<mode>_results.json (gitignored);
live -> agent/v2_results/v2_<set>_live_results.json.
An existing output file is resumed (records kept); --allow-overwrite starts fresh.
Resume: alerts with a stored outcome are skipped; NCE failures are stored
unscored (nce_error, no outcome) and retried on the next run.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from perception.defended_pipeline import run_downstream  # noqa: E402
from perception.entity_binding import trusted_destination_of  # noqa: E402
from perception.knowledge_graph import KnowledgeStoreGraph  # noqa: E402
from perception.nce_contract import NCEHypothesis  # noqa: E402

V2_DIR = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2"
LIVE_DELAY_S = 2.0


def _public(alert: dict) -> dict:
    return {k: v for k, v in alert.items() if not k.startswith("_")}


def _h(tech, acct, src, tgt, conf=0.6) -> NCEHypothesis:
    return NCEHypothesis(technique_id=tech, source_account=acct or "", source_host=src or "",
                         target_host=tgt or "", nce_confidence=conf, supporting_evidence_refs=["raw_log_line"])


def mock_oracle(alert: dict) -> list[NCEHypothesis]:
    hyps = [_h("T1078", alert["source_user"], alert["source_host"], alert["target_host"])]
    dest = trusted_destination_of(alert)
    if dest:
        hyps.append(_h("T1071", alert["source_user"], alert["source_host"], dest))
    return hyps


def mock_hijacked(alert: dict) -> list[NCEHypothesis]:
    fam = alert.get("_ground_truth_injection_category")
    if not alert.get("_ground_truth_is_contaminated"):
        return mock_oracle(alert)
    if fam == "identity_steering":
        user, host = alert["_steered_entities"]
        return [_h("T1550", user, alert["source_host"], host, 0.9)]
    if fam == "destination_spoof":
        trusted = (trusted_destination_of(alert) or "").lower()
        spoofed = [d for d in re.findall(r"[a-z0-9.-]+\.example", alert["raw_log_line"] + " " + alert["command_line"])
                   if d.lower() != trusted]
        return [_h("T1071", alert["source_user"], alert["source_host"], spoofed[-1] if spoofed else "unknown", 0.9)]
    return []  # suppression families: NCE fully talked out of any hypothesis


def live_nce(alert: dict) -> tuple[list[NCEHypothesis] | None, str | None, str | None]:
    from perception.nce_engine import alert_to_nce_input, generate_hypotheses
    res = generate_hypotheses(alert_to_nce_input(_public(alert)), apply_evidentiary_filter=True)
    if res.success and res.output is not None:
        return list(res.output.hypotheses), None, res.raw_response
    return None, res.error or "NCE failed", res.raw_response


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nce", required=True, choices=["mock-oracle", "mock-hijacked", "live"])
    ap.add_argument("--set", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--limit", type=int, default=None, help="process at most N new alerts")
    ap.add_argument("--out", default=None)
    ap.add_argument("--allow-overwrite", action="store_true")
    args = ap.parse_args()

    if args.out:
        out = Path(args.out)
    elif args.nce == "live":
        out = PROJECT_ROOT / "agent" / "v2_results" / f"v2_{args.set}_live_results.json"
    else:
        out = PROJECT_ROOT / "logs" / f"v2_{args.set}_{args.nce}_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    alerts = json.loads((V2_DIR / f"guide_v2_{args.set}.json").read_text(encoding="utf-8"))
    done: dict[str, dict] = {}
    if out.exists() and not args.allow_overwrite:   # resume; stored records are never discarded
        done = {r["alert_id"]: r for r in json.loads(out.read_text(encoding="utf-8"))}
    kg = KnowledgeStoreGraph()
    new = 0
    for alert in alerts:
        aid = alert["alert_id"]
        if aid in done and "outcome" in done[aid]:
            continue
        if args.limit is not None and new >= args.limit:
            break
        rec = {"alert_id": aid, "pair_id": alert["_pair_id"], "variant": alert["_variant"], "nce_mode": args.nce}
        if args.nce == "live":
            hyps, err, raw = live_nce(alert)
            rec["nce_raw_response"] = raw
            if hyps is None:
                rec["nce_error"] = err
                done[aid] = rec
                out.write_text(json.dumps(list(done.values()), indent=1), encoding="utf-8")
                new += 1
                time.sleep(LIVE_DELAY_S)
                continue
        else:
            hyps = mock_oracle(alert) if args.nce == "mock-oracle" else mock_hijacked(alert)
        rec.update(run_downstream(hyps, _public(alert), kg))
        done[aid] = rec
        new += 1
        if args.nce == "live":
            out.write_text(json.dumps(list(done.values()), indent=1), encoding="utf-8")
            time.sleep(LIVE_DELAY_S)
    out.write_text(json.dumps(list(done.values()), indent=1), encoding="utf-8")
    print(f"{new} new alerts processed; {len(done)} stored -> {out}")


if __name__ == "__main__":
    main()
