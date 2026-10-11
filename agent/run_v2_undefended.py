"""
agent/run_v2_undefended.py

Undefended baseline on corpus v2 pairs (Phase 4 step 4.9, 2026-10-11): the
original triage agent (agent/baseline_agent.build_undefended_prompt — alert
fields pasted into the prompt, no checks) asked for verdict/action on every
clean and contaminated alert.  Gives the "before" number for the defended
pipeline's "after" results.  Same parallel system as agent/run_v2_eval.py.

    python -m agent.run_v2_undefended [--set dev] [--model gemini-3.1-flash-lite] [--workers 5] [--limit N]

Output: agent/v2_results/v2_<set>_undefended[_<model>]_results.json (+ _api_log.jsonl);
resumes; failures stored unscored and retried; stops on daily quota (exit 3).
The Gemini caller is the original baseline one (call_agent_rotating), unchanged,
so these numbers are comparable with the project's earlier baselines.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.run_v2_eval import MODEL, _run_parallel  # noqa: E402

V2_DIR = PROJECT_ROOT / "GUIDE_Dataset" / "processed" / "v2"


def undefended_call(alert: dict, model: str = MODEL, groq_keys: list[str] | None = None):
    """Runs in the worker's child process.  Returns (parsed|None, error, raw, n_calls)."""
    from agent.baseline_agent import build_undefended_prompt, call_agent_groq_rotating, call_agent_rotating
    from agent.key_pool import load_gemini_pool, load_groq_pool
    prompt = build_undefended_prompt({k: v for k, v in alert.items() if not k.startswith("_")})
    if model.startswith("groq:"):
        import os
        if groq_keys:
            os.environ["GROQ_API_KEYS"] = ",".join(groq_keys)
        res = call_agent_groq_rotating(prompt, load_groq_pool(), model=model[len("groq:"):])
    else:
        res = call_agent_rotating(prompt, load_gemini_pool(), model=model)
    parsed = res.get("parsed")
    if res.get("parse_error") or not isinstance(parsed, dict):
        return None, res.get("parse_error") or "response is not a JSON object", res.get("raw_response"), 1
    return parsed, None, res.get("raw_response"), 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    tag = "" if args.model == MODEL else "_" + args.model.replace("groq:", "groq-").replace("/", "-")
    out = PROJECT_ROOT / "agent" / "v2_results" / f"v2_{args.set}_undefended{tag}_results.json"
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
        rec = {"alert_id": aid, "pair_id": a["_pair_id"], "variant": a["_variant"], "model": args.model,
               "raw_response": raw, "api_calls": n}
        if parsed is None:
            rec["error"] = err
        else:
            rec.update({"verdict": str(parsed.get("verdict", "")).lower(), "action": str(parsed.get("action", "")).lower(),
                        "confidence": parsed.get("confidence"), "reasoning": parsed.get("reasoning")})
        done[aid] = rec
        _atomic_checkpoint_write(done, out)

    stopped = _run_parallel(todo, args.workers, finish, out.with_name(out.stem.replace("_results", "") + "_api_log.jsonl"),
                            model=args.model, call_fn=undefended_call)
    if stopped:
        print(f"STOPPED: daily quota reached on every key; {len(done)} stored -> {out}", flush=True)
        sys.exit(3)
    print(f"{len(todo)} alerts processed; {len(done)} stored -> {out}")


if __name__ == "__main__":
    main()
