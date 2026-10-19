"""M4.1 (2026-10-18): accounts -- scrypt passwords, session tokens, roles, admin endpoints."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from perception.case_store import CaseStore  # noqa: E402
from review_api import create_app  # noqa: E402
from review_api.accounts import AccountError, AccountStore  # noqa: E402

PW = "correct horse battery"


class Clock:
    def __init__(self):
        self.t = datetime(2026, 10, 18, 9, tzinfo=timezone.utc)

    def __call__(self):
        return self.t


@pytest.fixture()
def acc(tmp_path):
    clock = Clock()
    store = AccountStore(tmp_path / "auth.sqlite", clock=clock)
    store.create_user("root", PW, "admin")
    store.create_user("alice", PW)
    yield store, clock, tmp_path
    store.close()


def test_passwords_are_hashed_and_sessions_expire(acc):
    store, clock, tmp = acc
    raw = sqlite3.connect(tmp / "auth.sqlite").execute("SELECT pw_hash FROM users").fetchall()
    assert all(PW.encode() not in r[0] for r in raw)
    assert store.login("alice", "wrong password!!") is None and store.login("nobody", PW) is None
    token, role, expires = store.login("alice", PW)
    assert role == "analyst" and store.resolve(token) == ("alice", "analyst")
    clock.t += timedelta(hours=13)
    assert store.resolve(token) is None                          # expired
    with pytest.raises(AccountError, match="at least"):
        store.create_user("bob", "short")
    with pytest.raises(AccountError, match="exists"):
        store.create_user("alice", PW)


def test_disable_and_password_change_end_sessions(acc):
    store, *_ = acc
    t1, *_ = store.login("alice", PW)
    store.set_password("alice", PW + "!")
    assert store.resolve(t1) is None and store.login("alice", PW) is None
    t2, *_ = store.login("alice", PW + "!")
    store.set_disabled("alice", True)
    assert store.resolve(t2) is None and store.login("alice", PW + "!") is None


def test_login_roles_and_admin_endpoints(acc):
    store, _, tmp = acc
    client = TestClient(create_app(CaseStore(tmp / "cases.sqlite"), accounts=store))
    assert client.post("/auth/login", json={"username": "alice", "password": "nope-nope-nope"}).status_code == 401
    alice = client.post("/auth/login", json={"username": "alice", "password": PW}).json()["token"]
    root = client.post("/auth/login", json={"username": "root", "password": PW}).json()["token"]
    h = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    assert client.get("/me", headers=h(alice)).json() == {"analyst": "alice", "role": "analyst"}
    assert client.get("/admin/users", headers=h(alice)).status_code == 403
    assert client.post("/admin/users", json={"username": "bob", "password": PW, "role": "lead"},
                       headers=h(root)).json() == {"created": "bob", "role": "lead"}
    assert {u["username"] for u in client.get("/admin/users", headers=h(root)).json()} == {"root", "alice", "bob"}
    assert client.post("/admin/users/root/disable", headers=h(root)).status_code == 400
    client.post("/admin/users/alice/disable", headers=h(root))
    assert client.get("/queue", headers=h(alice)).status_code == 401
    client.post("/auth/logout", headers=h(root))
    assert client.get("/me", headers=h(root)).status_code == 401


def test_failed_logins_are_throttled(acc):
    from review_api.accounts import LoginThrottle
    store, clock, tmp = acc
    throttle = LoginThrottle(clock=clock)
    client = TestClient(create_app(CaseStore(tmp / "cases.sqlite"), accounts=store, throttle=throttle))
    for _ in range(5):
        assert client.post("/auth/login", json={"username": "alice", "password": "wrong-password!"}).status_code == 401
    r = client.post("/auth/login", json={"username": "alice", "password": PW})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0          # locked, even with the right password
    assert client.post("/auth/login", json={"username": "root", "password": PW}).status_code == 200  # other user ok
    clock.t += timedelta(minutes=16)
    assert client.post("/auth/login", json={"username": "alice", "password": PW}).status_code == 200


def test_throttle_by_address_and_no_remote_lockout():
    from review_api.accounts import LoginThrottle
    clock = Clock()
    t = LoginThrottle(clock=clock)
    for i in range(20):                                          # password spraying from one address
        t.failed(f"user{i}", "10.0.0.9")
    assert t.retry_after("someone-else", "10.0.0.9") is not None
    for _ in range(10):                                          # guessing alice's password from elsewhere
        t.failed("alice", "10.0.0.66")
    assert t.retry_after("alice", "10.0.0.1") is None            # alice herself is not locked out


def test_first_run_setup_creates_one_admin_only(tmp_path):
    store = AccountStore(tmp_path / "auth.sqlite")
    client = TestClient(create_app(CaseStore(tmp_path / "cases.sqlite"), accounts=store))
    assert client.get("/auth/setup").json() == {"needed": True}
    assert client.post("/auth/setup", json={"username": "boss", "password": "short"}).status_code == 400
    r = client.post("/auth/setup", json={"username": "boss", "password": "a long enough pw"})
    assert r.status_code == 200 and r.json()["role"] == "admin"
    assert client.get("/me", headers={"Authorization": f"Bearer {r.json()['token']}"}).json()["role"] == "admin"
    assert client.get("/auth/setup").json() == {"needed": False}
    again = client.post("/auth/setup", json={"username": "mallory", "password": "a long enough pw"})
    assert again.status_code == 409 and [u["username"] for u in store.users()] == ["boss"]


def test_own_password_and_admin_account_management(tmp_path):
    store = AccountStore(tmp_path / "auth.sqlite")
    store.create_user("boss", "admin password 1", "admin")
    store.create_user("alice", "alice password 1", "analyst")
    client = TestClient(create_app(CaseStore(tmp_path / "cases.sqlite"), accounts=store))

    def login(u, pw):
        r = client.post("/auth/login", json={"username": u, "password": pw})
        return {"Authorization": f"Bearer {r.json()['token']}"} if r.status_code == 200 else r.status_code

    alice = login("alice", "alice password 1")
    bad = client.post("/auth/password", headers=alice, json={"current_password": "nope", "new_password": "x" * 12})
    assert bad.status_code == 401
    ok = client.post("/auth/password", headers=alice,
                     json={"current_password": "alice password 1", "new_password": "alice password 2"})
    assert ok.status_code == 200
    assert client.get("/me", headers=alice).status_code == 401              # sessions ended
    assert login("alice", "alice password 1") == 401
    alice = login("alice", "alice password 2")

    boss = login("boss", "admin password 1")
    assert client.post("/admin/users/alice/role", headers=alice, json={"role": "admin"}).status_code == 403
    assert client.post("/admin/users/alice/role", headers=boss, json={"role": "lead"}).status_code == 200
    assert client.post("/admin/users/boss/role", headers=boss, json={"role": "analyst"}).status_code == 400
    assert client.post("/admin/users/alice/password", headers=boss, json={"password": "reset by admin 1"}).status_code == 200
    assert login("alice", "reset by admin 1") != 401
    assert client.post("/admin/users/alice/disable", headers=boss).status_code == 200
    assert login("alice", "reset by admin 1") == 401
    assert client.post("/admin/users/alice/enable", headers=boss).status_code == 200
    assert {u["username"]: u["role"] for u in store.users()} == {"alice": "lead", "boss": "admin"}
    assert client.post("/admin/users/nobody/password", headers=boss, json={"password": "x" * 12}).status_code == 404
