"""
tests/test_corroborated_learning.py

Decision P9 B (2026-11-28; experiments/P9B_CORROBORATED_LEARNING_DESIGN.md): corroborated learning (R1 fleet,
R1b fleet_verdicts), pattern-following unlearning (R6) and the replay's training filter (R4).  Every rule is an
option; the default must learn exactly as before.
"""
from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

import pytest

from dedale.environment import DEDALE_PROFILE, seed_store
from experiments.dedale_host_replay import _retract_single_host
from perception.host_detection import DETECTORS, edge_pattern, image_node_id, key_pattern
from perception.knowledge_db import KnowledgeDB
from perception.soc_loop import SocLoop

TRAIN_END = datetime(2025, 1, 6, tzinfo=timezone.utc)
T = TRAIN_END + timedelta(hours=10)
EXPLORER = "C:\\Windows\\explorer.exe"


def _proc(t, image, host="CLIENT2", rid=1):
    return {"t": t.isoformat().replace("+00:00", "Z"), "host": host, "rid": rid, "ch": "sysmon", "code": 1,
            "image": image, "parent_image": EXPLORER, "cmd": "x.exe", "user": f"BREACH\\{host.lower()}"}


@pytest.fixture()
def db(tmp_path):
    with KnowledgeDB(tmp_path / "ks.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14)) as store:
        seed_store(store, TRAIN_END - timedelta(days=14))
        yield store


def _learned(db, image, host="CLIENT2"):
    return db.edge_learned_from(image_node_id(EXPLORER), image_node_id(image), f"host:{host.lower()}")


def _run(db, events, verdict=lambda image, host: "benign", **opts):
    """Replay (time, event) in order through a gated loop with a simulated analyst (4 h); returns the loop."""
    def analyst(case, decision, at):
        a = case.first_alert
        return verdict(a["detector_key"][2], a["target_host"])
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, analyst=analyst, **opts)
    rid = 0
    for at, e in sorted(events, key=lambda x: x[0]):
        rid += 1
        loop.process_host_event({**e, "rid": rid}, at)
    if events:
        last = max(at for at, _ in events)
        loop.tick(last + timedelta(days=3))          # the clock moves on: gate releases and verdicts fall due
        loop.tick(last + timedelta(days=6))
    return loop


def _train(image, *hosts):
    return [(TRAIN_END - timedelta(days=3), _proc(TRAIN_END - timedelta(days=3), image, h)) for h in hosts]


def _test(image, host, hours):
    t = T + timedelta(hours=hours)
    return [(t, _proc(t, image, host))]


def _end(hours=200):
    return [(T + timedelta(hours=hours), _proc(T + timedelta(hours=hours), "C:\\pad\\end.exe", "CLIENT9"))]


def test_pattern_is_the_key_without_its_host():
    a = key_pattern("lineage", DETECTORS["lineage"].key(_proc(T, "C:\\T\\tool.exe", "CLIENT2")))
    b = key_pattern("lineage", DETECTORS["lineage"].key(_proc(T, "C:\\T\\tool.exe", "CLIENT17")))
    assert a[0] == b[0] and (a[1], b[1]) == ("client2", "client17")
    for name, e in (("logon", {"ch": "security", "code": 4624, "host": "CLIENT3", "user": "U", "logon_type": 3,
                               "ip": "172.16.1.4"}),
                    ("pipe", {"ch": "sysmon", "code": 17, "host": "CLIENT3", "image": "C:\\a.exe", "pipe": "\\p12"}),
                    ("powershell", {"ch": "powershell", "code": 4104, "host": "CLIENT3", "script": "Get-Date"})):
        k = DETECTORS[name].key(e)
        edge = DETECTORS[name].edge(k)
        pattern, host = edge_pattern(edge.edge_type, edge.src, edge.dst, edge.key)
        assert host == "client3" and "client3" not in str(pattern)
    assert edge_pattern("HAS_PRIOR_ACCESS", "account:u", "host:client3", "HAS_PRIOR_ACCESS") is None


def test_default_learns_a_single_host_pattern_as_before(db):
    _run(db, [*_test("C:\\T\\new.exe", "CLIENT2", 0), *_end()])
    assert _learned(db, "C:\\T\\new.exe") == "analyst"


def test_r1_learns_only_patterns_another_host_showed_in_training(db):
    events = [*_train("C:\\T\\fleet.exe", "CLIENT3"), *_test("C:\\T\\fleet.exe", "CLIENT2", 0),
              *_test("C:\\T\\lonely.exe", "CLIENT2", 1), *_end()]
    loop = _run(db, events, corroboration="fleet")
    assert _learned(db, "C:\\T\\fleet.exe") == "analyst"
    assert _learned(db, "C:\\T\\lonely.exe") is None
    assert loop.updater.uncorroborated == 2               # lonely.exe and the end marker (single-host too)


def test_r1_a_pattern_seen_in_training_only_on_the_same_host_is_not_corroboration(db):
    events = [*_train("C:\\T\\own.exe", "CLIENT3"), *_test("C:\\T\\own.exe", "CLIENT3", 0), *_end()]
    _run(db, events, corroboration="fleet")
    assert _learned(db, "C:\\T\\own.exe", "CLIENT3") == "training"     # known there already: no alert at all


def test_r1_also_holds_for_gate_learning(db):
    events = [*_test("C:\\T\\quiet.exe", "CLIENT2", 0), *_end()]
    _run(db, events, corroboration="fleet", gate_options={"unreasoned": "no_actionable"})   # D7 off: gate path
    assert _learned(db, "C:\\T\\quiet.exe") is None


def test_r1_gate_path_learns_a_corroborated_pattern(tmp_path):
    with KnowledgeDB(tmp_path / "k2.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14)) as db2:
        seed_store(db2, TRAIN_END - timedelta(days=14))
        events = [*_train("C:\\T\\quiet.exe", "CLIENT5"), *_test("C:\\T\\quiet.exe", "CLIENT2", 0), *_end()]
        _run(db2, events, corroboration="fleet", gate_options={"unreasoned": "no_actionable"})
        assert _learned(db2, "C:\\T\\quiet.exe") == "closed_benign"


def test_r1b_needs_benign_verdicts_on_m_other_hosts(db):
    image = "C:\\T\\rollout.exe"
    events = [*_test(image, "CLIENT3", 0), *_test(image, "CLIENT4", 10), *_test(image, "CLIENT2", 20), *_end()]
    _run(db, events, corroboration="fleet_verdicts", corroboration_hosts=2)
    assert _learned(db, image, "CLIENT3") is None          # 0 other hosts at its verdict
    assert _learned(db, image, "CLIENT4") is None          # 1 other host
    assert _learned(db, image, "CLIENT2") == "analyst"     # 2 other hosts


def test_r1b_ignores_verdicts_from_confirmed_hosts(db):
    image = "C:\\T\\rollout.exe"
    bad = "C:\\Users\\x\\evil.exe"
    events = [*_test(bad, "CLIENT3", 0), *_test(image, "CLIENT3", 10), *_test(image, "CLIENT4", 20),
              *_test(image, "CLIENT2", 30), *_end()]
    _run(db, events, verdict=lambda img, host: "malicious" if img == bad.lower() else "benign",
         corroboration="fleet_verdicts", corroboration_hosts=2)
    assert _learned(db, image, "CLIENT2") is None          # CLIENT3 was confirmed: only CLIENT4 counts


def test_r6_confirmation_retracts_the_same_pattern_on_other_hosts(db, tmp_path):
    bad = "C:\\Users\\x\\tool.exe"
    events = [*_test(bad, "CLIENT3", 0), *_test(bad, "CLIENT2", 10), *_end()]
    verdict = lambda img, host: "malicious" if host == "CLIENT2" else "benign"   # noqa: E731
    _run(db, events, verdict=verdict, follow_patterns=True)
    assert _learned(db, bad, "CLIENT3") is None             # learned at 4 h, retracted by CLIENT2's confirmation
    with KnowledgeDB(tmp_path / "k3.sqlite", DEDALE_PROFILE, created_at=TRAIN_END - timedelta(days=14)) as db3:
        seed_store(db3, TRAIN_END - timedelta(days=14))
        _run(db3, events, verdict=verdict)                  # default: B5 retracts on CLIENT2 only
        assert _learned(db3, bad, "CLIENT3") == "analyst"


def test_r4_forgets_training_patterns_only_one_host_showed(db):
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END)
    for rid, (at, e) in enumerate([*_train("C:\\T\\solo.exe", "CLIENT3"),
                                   *_train("C:\\T\\pair.exe", "CLIENT3", "CLIENT4")], 1):
        loop.process_host_event({**e, "rid": rid}, at)
    loop.tick(TRAIN_END)
    n = _retract_single_host(db)
    assert _learned(db, "C:\\T\\solo.exe", "CLIENT3") is None
    assert _learned(db, "C:\\T\\pair.exe", "CLIENT3") == "training" and n >= 1


def test_a_corroborating_loop_survives_the_safe_checkpoint_loader(db):
    from soc_server.runner import _Pickler, _Unpickler
    image = "C:\\T\\rollout.exe"
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END, corroboration="fleet_verdicts")   # as the server runs
    for rid, (at, e) in enumerate([*_test(image, "CLIENT3", 0), *_test(image, "CLIENT4", 10)], 1):   # it: no
        loop.process_host_event({**e, "rid": rid}, at)                                            # simulated analyst
    loop.updater._verdict_hosts[("SPAWNED", "a", "b")] = {"client3"}
    buf = io.BytesIO()
    _Pickler(buf, {id(db): "ks"}).dump(loop)
    buf.seek(0)
    back = _Unpickler(buf, {"ks": db}).load()
    assert back.updater.corroboration == "fleet_verdicts" and back.updater._monitor is back.monitor


def test_a_checkpoint_from_before_p9b_restores_with_the_rules_off(db):
    from soc_server.runner import _Pickler, _Unpickler
    loop = SocLoop(db, mode="gated", training_end=TRAIN_END)
    for attr in ("corroboration", "corroboration_hosts", "_monitor", "_fleet", "_verdict_hosts", "uncorroborated"):
        del loop.updater.__dict__[attr]                     # as pickled by the code before 2026-11-28
    del loop.__dict__["follow_patterns"]
    buf = io.BytesIO()
    _Pickler(buf, {id(db): "ks"}).dump(loop)
    buf.seek(0)
    back = _Unpickler(buf, {"ks": db}).load()
    assert back.follow_patterns is False and back.updater.corroboration == "none"
    assert back.updater.corroborated("lineage", ("CLIENT2", "a", "b"))      # "none": everything learnable, as before
