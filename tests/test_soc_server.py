"""
M4.3 (2026-10-18): the demo server's routes -- live control by role, the
pipeline trace, read-only Knowledge Store views, metrics, and analysts'
actions stamped with the stream's clock.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from dedale.environment import DEDALE_PROFILE, seed_store  # noqa: E402
from perception.soc_loop import SocLoop  # noqa: E402
from review_api.accounts import AccountStore  # noqa: E402
from soc_server.app import build_app  # noqa: E402
from soc_server.runner import LiveRunner, stream_after  # noqa: E402

START = datetime(2024, 12, 30, tzinfo=timezone.utc)
TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
PW = "correct horse battery"


def _proc(t, image, rid):
    return {"t": t.isoformat().replace("+00:00", "Z"), "host": "CLIENT2", "rid": rid, "ch": "sysmon", "code": 1,
            "image": image, "parent_image": "C:\\Windows\\explorer.exe", "cmd": "x", "user": "BREACH\\client2"}


def _events():
    out, rid = [], 0
    for day in range(9):
        t = START + timedelta(days=day, hours=10)
        for image in ("C:\\x\\word.exe", f"C:\\x\\new{day}.exe" if t >= TRAIN_END else "C:\\x\\tool.exe"):
            rid += 1
            out.append((t, _proc(t, image, rid)))
    return out


class _Src:
    def events(self, after):
        return stream_after(_events(), after)


@pytest.fixture()
def server(tmp_path):
    runner = LiveRunner(tmp_path / "live", _Src(), profile=DEDALE_PROFILE, start=START,
                        make_loop=lambda db, cs: SocLoop(db, mode="gated", training_end=TRAIN_END, case_store=cs),
                        handle=lambda loop, ev, at: loop.process_host_event(ev, at),
                        seed=lambda db: seed_store(db, START), speed=86_400)
    runner.run_until(START + timedelta(days=8, hours=12))
    accounts = AccountStore(tmp_path / "auth.sqlite")
    accounts.create_user("lena", PW, "lead")
    accounts.create_user("alice", PW)
    client = TestClient(build_app(runner, accounts=accounts))
    tok = {u: client.post("/auth/login", json={"username": u, "password": PW}).json()["token"] for u in ("lena", "alice")}
    yield client, runner, {u: {"Authorization": f"Bearer {t}"} for u, t in tok.items()}
    runner.stop()
    accounts.close()


def test_live_control_needs_a_lead(server):
    client, runner, h = server
    assert client.get("/live/status", headers=h["alice"]).json()["state"] == "paused"
    assert client.post("/live/start", headers=h["alice"]).status_code == 403
    assert client.post("/live/speed", json={"speed": 3600}, headers=h["lena"]).json()["speed"] == 3600
    assert client.post("/live/speed", json={"speed": 0}, headers=h["lena"]).status_code == 422
    assert client.post("/live/pause", headers=h["lena"]).status_code == 200


def test_trace_knowledge_and_metrics(server):
    client, runner, h = server
    case_id = client.get("/queue", headers=h["alice"]).json()[0]["case_id"]
    trace = client.get(f"/cases/{case_id}/trace", headers=h["alice"]).json()
    assert [s["stage"] for s in trace["stages"]] == ["alert", "triage_gate", "reasoning", "structural_check",
                                                      "response", "decision", "actions", "learning"]
    assert trace["stages"][2]["llm_output"] is True and "instructions" in trace["stages"][0]["untrusted_notice"]
    summary = client.get("/knowledge/summary", headers=h["alice"]).json()
    assert summary["edges"]["SPAWNED"]["training"] >= 2
    host = client.get("/knowledge/hosts/CLIENT2", headers=h["alice"]).json()
    assert {e["learned_from"] for e in host} == {"training"} and all(e["type"] == "SPAWNED" for e in host)
    graph = client.get("/knowledge/graph/CLIENT2", headers=h["alice"]).json()
    assert graph["edges"] and any(n["id"] == "host:client2" for n in graph["nodes"])
    m = client.get("/metrics", headers=h["alice"]).json()
    assert set(m) >= {"cases_per_day", "review_status", "verdicts", "actions", "learning_per_day", "comparison"}
    assert "learning behind the gate" in m["comparison"]                       # frozen DEDALE runs
    assert client.get("/knowledge/summary").status_code == 401


def test_analysts_actions_use_the_stream_clock(server):
    client, runner, h = server
    case_id = client.get("/queue", headers=h["alice"]).json()[0]["case_id"]
    client.post(f"/cases/{case_id}/verdict", json={"verdict": "benign"}, headers=h["alice"])
    (cmd,) = runner.cases.commands(case_id)
    assert cmd["at"].startswith(runner.now().strftime("%Y-%m-%d"))          # 2025, not today's date
    assert cmd["actor"] == "analyst:alice"


def test_one_origin_with_the_built_frontend(server, tmp_path):
    from soc_server.app import with_frontend
    client, runner, h = server
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>app</html>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("no", encoding="utf-8")
    app = with_frontend(client.app, dist)
    c = TestClient(app)
    assert c.get("/cases/case-20").text == "<html>app</html>"                   # client route -> index.html
    assert c.get("/assets/app.js").text == "console.log(1)"
    assert "no" != c.get("/../secret.txt").text                                 # no traversal out of dist
    assert c.get("/api/live/status", headers=h["alice"]).json()["state"] == "paused"


def test_live_nce_never_writes_the_recorded_cache(tmp_path):
    from soc_server.__main__ import nce_cache

    recorded = tmp_path / "runs" / "nce_cache_host.jsonl"
    recorded.parent.mkdir()
    recorded.write_text('{"alert_id": "a"}\n')
    assert nce_cache(recorded, tmp_path / "home", live=False) == recorded
    own = nce_cache(recorded, tmp_path / "home", live=True)
    assert own == tmp_path / "home" / "nce_cache_host.jsonl" and own.read_text() == recorded.read_text()
    with open(own, "a") as f:                                  # what a live call does
        f.write('{"alert_id": "b"}\n')
    assert recorded.read_text() == '{"alert_id": "a"}\n'
    assert nce_cache(recorded, tmp_path / "home", live=True).read_text().count("alert_id") == 2   # kept


def test_injected_source_passes_events_through_the_injector():
    from soc_server.sources import InjectedSource

    class Src:
        def events(self, after):
            yield from [(1, "t1", {"cmd": "a"}), (2, "t2", {"cmd": "b"})][(after or 0):]

    out = list(InjectedSource(Src(), lambda e: dict(e, cmd=e["cmd"] + " # x")).events(1))
    assert out == [(2, "t2", {"cmd": "b # x"})]


def test_activity_queue_fields_and_techniques(server):
    client, runner, h = server
    act = client.get("/live/activity?hours=48", headers=h["alice"]).json()["hours"]
    assert len(act) == 48 and act[-1]["hour"].startswith("2025-01-07T12")
    assert sum(x["sent_to_analyst"] + x["closed_automatically"] for x in act) == len(runner.cases.cases())
    q = client.get("/queue", headers=h["alice"]).json()
    assert q and all({"kind", "host_tier", "group", "techniques"} <= set(i) for i in q)
    assert all(i["group"].startswith("host|") and "CLIENT2" not in i["group"] for i in q)
    t = client.get("/techniques", headers=h["alice"]).json()
    assert t["T1078"]["name"] == "Valid Accounts" and t["T1071"]["name"]


def test_group_key_drops_the_varying_endpoint():
    from perception.review_service import group_key
    a = {"case_key": [2016149, "172.17.0.5", "185.208.37.90"], "host": "vpnserver"}
    b = {"case_key": [2016149, "172.17.0.5", "64.131.63.216"], "host": "vpnserver"}
    r = {"case_key": [2016150, "64.131.63.216", "172.17.0.5"], "host": "vpnserver"}
    r2 = {"case_key": [2016150, "77.72.169.212", "172.17.0.5"], "host": "vpnserver"}
    c = {"case_key": [2016149, "172.17.0.9", "185.208.37.90"], "host": "webserver"}
    assert group_key(a) == group_key(b) != group_key(c)
    assert group_key(r) == group_key(r2) != group_key(a)
    h1 = {"case_key": ["host", "lineage", "CLIENT1", "-", "c:\\windows\\system32\\usoclient.exe"]}
    h2 = {"case_key": ["host", "lineage", "CLIENT9", "-", "c:\\windows\\system32\\usoclient.exe"]}
    assert group_key(h1) == group_key(h2)


def test_contamination_lab_reproduces_table_one(server):
    client, runner, h = server
    runs = client.get("/lab/runs", headers=h["alice"]).json()
    assert [r["id"] for r in runs] == ["dev_gemini", "heldout_gemini", "dev_gptoss"]
    expected = {"dev_gemini": (4, 428, 12, 4), "heldout_gemini": (3, 437, 10, 0), "dev_gptoss": (10, 437, 12, 5)}
    for run, (supp, resp, era, other) in expected.items():                     # experiments/RESULTS.md, C1
        t = client.get(f"/lab/{run}/summary", headers=h["alice"]).json()["total"]
        assert (t["suppressed"], t["clean_responded"], t["induced_by_era"], t["induced"]) == (supp, resp, era, other)
        assert t["pairs"] == 500 and t["misdirect_executed"] == 0
    und = client.get("/lab/dev_gemini/summary", headers=h["alice"]).json()["undefended"]
    assert (und["hijacked"], und["clean_not_dismissed"]) == (130, 439)
    rows = client.get("/lab/dev_gemini/pairs?change=suppressed", headers=h["alice"]).json()
    assert rows["total"] == 4
    pair = client.get(f"/lab/dev_gemini/pairs/{rows['items'][0]['pair_id']}", headers=h["alice"]).json()
    x = pair["variants"]["contaminated"]
    (field, (a, b)), = x["injected"].items()
    assert field == pair["metadata"]["site"] and 0 <= a < b <= len(x["untrusted"][field])
    assert not any(k.startswith("_") for k in {**x["trusted"], **x["untrusted"]})   # no ground truth in the alert
    assert client.get("/lab/nope/summary", headers=h["alice"]).status_code == 404


def test_host_timeline_lists_every_case_on_the_host_in_order(server):
    client, runner, h = server
    t = client.get("/hosts/CLIENT2/timeline", headers=h["alice"]).json()
    assert t["host"] == "CLIENT2" and t["total"] == len(runner.cases.cases(host="CLIENT2")) > 0
    opened = [c["opened"] for c in t["cases"]]
    assert opened == sorted(opened)
    assert {"techniques", "actions", "outcome", "verdict"} <= set(t["cases"][0])
    assert client.get("/hosts/nohost/timeline", headers=h["alice"]).json()["total"] == 0


def test_hostnames_in_natural_order_and_dataset_label(server):
    client, runner, h = server
    names = client.get("/knowledge/hostnames", headers=h["alice"]).json()
    assert "CLIENT2" in names and names.index("CLIENT9") < names.index("CLIENT10")
    assert client.get("/live/status", headers=h["alice"]).json()["dataset"] == "DEDALE"
