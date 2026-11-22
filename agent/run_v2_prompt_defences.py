"""
agent/run_v2_prompt_defences.py

Tier 2, T2.2 (experiments/TIER2_PLAN.md, decision P11, 2026-11-22): the triage agent with a prompt-level
defence (agent/prompt_defences.py) on every clean and contaminated alert of a GUIDE v2 set.  Same task,
model, parallel runner and record format as agent/run_v2_undefended.py, so experiments/undefended_metrics
scores it the same way.  A separate module (not an option on run_v2_undefended.py) so that a live run of
that runner is never affected by edits here.  API CALLS: needs an approved budget.

    python -m agent.run_v2_prompt_defences --defence delimited|spotlight|hierarchy [--set dev] [--workers 8] [--limit N]

Output: agent/v2_results/v2_<set>_promptdef_<defence>_results.json (+ _api_log.jsonl); resumes; failures
stored unscored and retried; stops on daily quota (exit 3).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.prompt_defences import BUILDERS, DEFENCES  # noqa: E402
from agent.run_v2_eval import MODEL, _run_parallel  # noqa: E402

V2_DIR = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2"


def _call(defence: str, alert: dict, model: str):
    """Runs in the worker's child process.  Returns (parsed|None, error, raw, n_calls)."""
    from agent.baseline_agent import call_agent_rotating
    from agent.key_pool import load_gemini_pool
    from agent.llm_utils import DAILY_QUOTA_MARKER, is_daily_quota_error
    prompt = BUILDERS[defence]({k: v for k, v in alert.items() if not k.startswith("_")})
    res = call_agent_rotating(prompt, load_gemini_pool(), model=model)
    parsed, err = res.get("parsed"), res.get("parse_error")
    if err:
        if is_daily_quota_error(err):
            err = f"{DAILY_QUOTA_MARKER}: {err}"
        return None, err, res.get("raw_response"), 1
    if not isinstance(parsed, dict):
        return None, "response is not a JSON object", res.get("raw_response"), 1
    return parsed, None, res.get("raw_response"), 1


# module-level functions: the parallel runner pickles call_fn into child processes
def call_delimited(alert, model=MODEL, groq_keys=None):
    return _call("delimited", alert, model)


def call_spotlight(alert, model=MODEL, groq_keys=None):
    return _call("spotlight", alert, model)


def call_hierarchy(alert, model=MODEL, groq_keys=None):
    return _call("hierarchy", alert, model)


CALLS = {"delimited": call_delimited, "spotlight": call_spotlight, "hierarchy": call_hierarchy}


def results_path(set_name: str, defence: str) -> Path:
    return PROJECT_ROOT / "agent" / "v2_results" / f"v2_{set_name}_promptdef_{defence}_results.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--defence", required=True, choices=DEFENCES)
    ap.add_argument("--set", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()
    if not MODEL.startswith("gemini"):
        sys.exit("T2.2 runs on the Gemini model of the undefended baseline")

    out = results_path(args.set, args.defence)
    out.parent.mkdir(parents=True, exist_ok=True)
    alerts = json.loads((V2_DIR / f"guide_v2_{args.set}.json").read_text(encoding="utf-8"))
    done = {r["alert_id"]: r for r in json.loads(out.read_text(encoding="utf-8"))} if out.exists() else {}
    todo = [a for a in alerts if not (a["alert_id"] in done and "verdict" in done[a["alert_id"]])]
    if args.limit is not None:
        todo = todo[: args.limit]
    by_id = {a["alert_id"]: a for a in todo}
    from experiments.run_paired_clean_eval_B_parallel import _atomic_checkpoint_write

    def finish(aid: str, res) -> None:
        parsed, err, raw, n = res
        a = by_id[aid]
        rec = {"alert_id": aid, "pair_id": a["_pair_id"], "variant": a["_variant"], "model": MODEL,
               "defence": args.defence, "raw_response": raw, "api_calls": n}
        if parsed is None:
            rec["error"] = err
        else:
            rec.update({"verdict": str(parsed.get("verdict", "")).lower(), "action": str(parsed.get("action", "")).lower(),
                        "confidence": parsed.get("confidence"), "reasoning": parsed.get("reasoning")})
        done[aid] = rec
        _atomic_checkpoint_write(done, out)

    stopped = _run_parallel(todo, args.workers, finish, out.with_name(out.stem.replace("_results", "") + "_api_log.jsonl"),
                            model=MODEL, call_fn=CALLS[args.defence])
    if stopped:
        print(f"STOPPED: daily quota reached on every key; {len(done)} stored -> {out}", flush=True)
        sys.exit(3)
    print(f"{len(todo)} alerts processed; {len(done)} stored -> {out}")


if __name__ == "__main__":
    main()
