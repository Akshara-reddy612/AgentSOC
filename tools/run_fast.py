"""Run agent.run_v2_prompt_defences with one reused client per key (2026-11-23). Replaces tools/run_patient.py, where
every call started a new process, built a new client (8-11 s here, loading the CA file twice) and rebuilt it for each
key it tried on a 429, so many calls hit the 180 s cutoff. Only the transport changes: the prompts, model, temperature,
parsing and output files are those of agent.run_v2_prompt_defences.

- one genai.Client per key, created once, no SDK retries, 60 s HTTP timeout; calls run in the worker's thread;
- a call uses one key; a key at its DAILY quota is retired and the next live key is tried, and the run stops only when
  every key is retired (before, one exhausted key stopped the run).
Run from the repository root with PYTHONPATH=. ; arguments pass through."""
import sys
import threading


def install(client_factory=None):
    """Patch the module globals agent.run_v2_eval uses. Returns the shared state (tests)."""
    from google import genai
    from google.genai import types

    import agent.baseline_agent as ba
    import agent.key_pool as kp
    import agent.run_v2_eval as ev
    import experiments.run_paired_clean_eval_B_parallel as par
    from agent.llm_utils import is_daily_quota_error

    make = client_factory or genai.Client
    options = types.HttpOptions(timeout=60_000, retry_options=types.HttpRetryOptions(attempts=1))
    clients, locks, guard, dead, local = {}, {}, threading.Lock(), set(), threading.local()
    full_pool = kp.load_gemini_pool

    def client(api_key=None, **_):
        with guard:
            lock = locks.setdefault(api_key, threading.Lock())
        with lock:
            if api_key not in clients:
                clients[api_key] = make(api_key=api_key, http_options=options)
            return clients[api_key]

    def pool():
        key = getattr(local, "key", None)
        return kp.KeyPool([key]) if key else full_pool()

    def call(fn, *args, active_key="", all_keys=None, timeout=None, **kwargs):
        order = [active_key] + [k for k in (all_keys or []) if k != active_key]
        out = None
        for key in order:
            if key in dead:
                continue
            local.key = key
            try:
                out = fn(*args, **kwargs)
            finally:
                local.key = None
            if out[0] is None and out[1] and is_daily_quota_error(out[1]):
                dead.add(key)
                print(f"[run_fast] key ..{key[-4:]} is at its daily quota ({len(dead)} retired)", flush=True)
                continue
            return out, key[-4:]
        from agent.llm_utils import DAILY_QUOTA_MARKER
        return (None, f"{DAILY_QUOTA_MARKER}: every key is retired", None, 0), ""

    genai.Client = client
    kp.load_gemini_pool = pool
    ba._RETRY_DELAYS = []
    par._call_with_timeout = call
    ev.MAX_ATTEMPTS = 8
    ev.RETRY_BACKOFF = [5, 10, 20, 30, 30, 30, 30, 30]
    return {"clients": clients, "dead": dead, "call": call}


if __name__ == "__main__":
    import agent.run_v2_prompt_defences as pd

    install()
    sys.argv = ["agent.run_v2_prompt_defences", *sys.argv[1:]]
    pd.main()
