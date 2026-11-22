"""Run agent.run_v2_prompt_defences with a longer per-call timeout and back-off (2026-11-22: Gemini overloaded with
503 'high demand'; the default 60 s cutoff killed calls that would have succeeded). No project code changes:
agent.run_v2_eval reads these module globals when _run_parallel runs. Arguments pass through.
Run from the repository root with PYTHONPATH=. ; the __main__ guard matters, because spawned workers re-import this file."""
import sys

if __name__ == "__main__":
    import agent.run_v2_eval as ev
    import agent.run_v2_prompt_defences as pd

    ev.CALL_TIMEOUT_S = 180
    ev.MAX_ATTEMPTS = 4
    ev.RETRY_BACKOFF = [30, 60, 90, 90]
    sys.argv = ["agent.run_v2_prompt_defences", *sys.argv[1:]]
    pd.main()
