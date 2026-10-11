"""
agent/run_v2_eval.py --workers (2026-10-11): every alert is finished exactly
once by the main thread, failures are retried with key rotation, and an alert
that keeps failing is returned as an NCE error (stored unscored).  The API is
never called: the call helper is replaced.
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import agent.run_v2_eval as runner
import experiments.run_paired_clean_eval_B_parallel as helpers


def test_parallel_runner(monkeypatch, tmp_path):
    keys = ["k0aaaa", "k1bbbb", "k2cccc"]
    monkeypatch.setattr("agent.key_pool.load_gemini_pool", lambda: SimpleNamespace(keys=keys))
    monkeypatch.setattr(runner, "LIVE_DELAY_S", 0)
    monkeypatch.setattr(runner, "RETRY_BACKOFF", [0, 0, 0])
    calls: list[tuple[str, str]] = []
    lock = threading.Lock()

    def fake_call(fn, alert, active_key="", all_keys=None, timeout=0, **kw):
        with lock:
            calls.append((alert["alert_id"], active_key))
            n = sum(1 for a, _ in calls if a == alert["alert_id"])
        if alert["alert_id"] == "flaky" and n == 1:
            raise TimeoutError("Call timed out")
        if alert["alert_id"] == "dead":
            return (None, "quota", None, 1), active_key[-4:]
        return ([], None, "{}", 1), active_key[-4:]

    monkeypatch.setattr(helpers, "_call_with_timeout", fake_call)
    todo = [{"alert_id": f"a{i}"} for i in range(10)] + [{"alert_id": "flaky"}, {"alert_id": "dead"}]
    finished: dict[str, tuple] = {}
    main_thread = threading.current_thread()

    def finish(aid, res):
        assert threading.current_thread() is main_thread   # single writer
        assert aid not in finished
        finished[aid] = res

    runner._run_parallel(todo, 3, finish, tmp_path / "api.jsonl")
    assert set(finished) == {a["alert_id"] for a in todo}
    assert finished["flaky"][0] == []                       # succeeded on retry
    flaky_keys = [k for a, k in calls if a == "flaky"]
    assert len(flaky_keys) == 2 and flaky_keys[0] != flaky_keys[1]   # rotated key
    assert finished["dead"][0] is None and finished["dead"][1] == "quota"
    assert sum(1 for a, _ in calls if a == "dead") == runner.MAX_ATTEMPTS
    log = (tmp_path / "api.jsonl").read_text().splitlines()
    assert len(log) == len(calls) and all("k0aaaa" not in line for line in log)  # last-4 only


def test_parallel_runner_groq_rotates_groq_keys(monkeypatch, tmp_path):
    gkeys = ["g0wwww", "g1xxxx", "g2yyyy", "g3zzzz", "g4vvvv"]
    monkeypatch.setattr("agent.key_pool.load_groq_pool", lambda: SimpleNamespace(keys=gkeys))
    monkeypatch.setattr(runner, "LIVE_DELAY_S", 0)
    seen: list[tuple[str, list[str], str | None]] = []
    lock = threading.Lock()

    def fake_call(fn, alert, active_key="", all_keys=None, timeout=0, **kw):
        with lock:
            seen.append((kw.get("model"), kw.get("groq_keys"), active_key or None))
        time.sleep(0.1)   # keep each worker busy so every worker takes one alert
        return ([], None, "{}", 1), ""

    monkeypatch.setattr(helpers, "_call_with_timeout", fake_call)
    todo = [{"alert_id": f"a{i}"} for i in range(5)]
    runner._run_parallel(todo, 5, lambda aid, res: None, tmp_path / "api.jsonl", model="groq:openai/gpt-oss-20b")
    assert all(m == "groq:openai/gpt-oss-20b" and a is None for m, _, a in seen)   # Gemini env untouched
    assert {g[0] for _, g, _ in seen} == set(gkeys)                                 # each worker starts on its own key
    assert all(sorted(g) == sorted(gkeys) for _, g, _ in seen)
    assert all(json_line.count("****") == 0 for json_line in (tmp_path / "api.jsonl").read_text().splitlines())
