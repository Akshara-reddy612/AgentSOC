"""
2026-10-11: when every key is at its DAILY quota, the NCE callers return a
QUOTA_EXHAUSTED_DAILY error after one request per key (no retry rounds) and the
v2 runner stops all workers.  Earlier, the Groq run kept retrying all five keys
after the daily cap and inflated the dashboard usage to ~400 calls per key.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import agent.run_v2_eval as runner
import experiments.run_paired_clean_eval_B_parallel as helpers
from agent.llm_utils import DAILY_QUOTA_MARKER, is_daily_quota_error

GROQ_TPD = ("Error code: 429 - Rate limit reached for model `openai/gpt-oss-20b` in organization `org_x` "
            "service tier `on_demand` on tokens per day (TPD): Limit 200000, Used 199878, Requested 2855.")
GROQ_TPM = "Error code: 429 - Rate limit reached ... on tokens per minute (TPM): Limit 8000, Used 7990"
GEMINI_DAY = ("429 RESOURCE_EXHAUSTED quota exceeded, quotaId: "
              "GenerateRequestsPerDayPerProjectPerModel-FreeTier")


def test_detector_matches_daily_not_per_minute():
    assert is_daily_quota_error(GROQ_TPD) and is_daily_quota_error(GEMINI_DAY)
    assert not is_daily_quota_error(GROQ_TPM)
    assert not is_daily_quota_error("429 GenerateRequestsPerMinutePerProjectPerModel")


class _FakeOpenAI:
    calls: list[str] = []
    behaviour: dict[str, str] = {}

    def __init__(self, base_url, api_key):
        self.key = api_key
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        _FakeOpenAI.calls.append(self.key)
        if _FakeOpenAI.behaviour.get(self.key) == "daily":
            raise RuntimeError(GROQ_TPD)
        msg = SimpleNamespace(content='{"hypotheses": []}')
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def _setup(monkeypatch, behaviour):
    import openai
    from perception import nce_engine
    keys = [f"key{i}" for i in range(5)]
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
    monkeypatch.setattr("agent.key_pool.load_groq_pool",
                        lambda: __import__("agent.key_pool", fromlist=["KeyPool"]).KeyPool(keys))
    monkeypatch.setattr("time.sleep", lambda s: None)
    _FakeOpenAI.calls, _FakeOpenAI.behaviour = [], behaviour
    return nce_engine, keys


def test_groq_caller_stops_after_one_request_per_key(monkeypatch):
    nce_engine, keys = _setup(monkeypatch, {f"key{i}": "daily" for i in range(5)})
    out = nce_engine._call_groq_nce("prompt", "openai/gpt-oss-20b")
    assert DAILY_QUOTA_MARKER in out["parse_error"]
    assert sorted(_FakeOpenAI.calls) == keys            # exactly one request per key, no retry rounds


def test_groq_caller_skips_capped_key_and_uses_next(monkeypatch):
    nce_engine, _ = _setup(monkeypatch, {"key0": "daily"})
    out = nce_engine._call_groq_nce("prompt", "openai/gpt-oss-20b")
    assert out["parse_error"] is None and _FakeOpenAI.calls == ["key0", "key1"]


def test_runner_stops_all_workers_on_daily_quota(monkeypatch, tmp_path):
    monkeypatch.setattr("agent.key_pool.load_gemini_pool", lambda: SimpleNamespace(keys=["a1111", "b2222"]))
    monkeypatch.setattr(runner, "LIVE_DELAY_S", 0)
    monkeypatch.setattr(runner, "RETRY_BACKOFF", [0, 0, 0])
    calls = []
    lock = threading.Lock()

    def fake_call(fn, alert, active_key="", all_keys=None, timeout=0, **kw):
        with lock:
            calls.append(alert["alert_id"])
        return (None, f"API_ERROR: {DAILY_QUOTA_MARKER}: all keys capped", None, 1), active_key[-4:]

    monkeypatch.setattr(helpers, "_call_with_timeout", fake_call)
    finished = []
    todo = [{"alert_id": f"a{i}"} for i in range(50)]
    stopped = runner._run_parallel(todo, 2, lambda aid, res: finished.append(aid), tmp_path / "api.jsonl")
    assert stopped is True
    assert len(calls) <= 2 and len(finished) == len(calls)   # no retries, no further alerts taken
