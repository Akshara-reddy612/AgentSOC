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
