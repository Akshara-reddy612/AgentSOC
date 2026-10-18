"""
review_api/accounts.py

Accounts for the review API (M4.1, 2026-10-18; DEMO_BACKEND_DESIGN.md).

  - Users: username (the analyst id the case store records), role (analyst,
    lead, admin), password hash.  Passwords are hashed with scrypt from the
    Python standard library (random 16-byte salt, n = 2**14, r = 8, p = 1)
    and compared in constant time; they are never stored or logged.
  - Sessions: a random token is returned once at login; only its SHA-256 is
    stored, with an expiry.  A disabled user's sessions stop working.
  - Roles: analysts review and approve; leads also control the live replay;
    admins also manage users.  Four-eyes approval still means two different
    usernames (perception/case_store.py).

Create the first admin:
    python -m review_api.accounts --db <auth.sqlite> create-user <name> --role admin
(the password is read from the terminal, or from AGENTSOC_NEW_PASSWORD).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from perception.case_store import is_valid_analyst_id

ROLES = ("analyst", "lead", "admin")
MIN_PASSWORD = 12
SESSION_TTL = timedelta(hours=12)
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    role     TEXT NOT NULL,
    salt     BLOB NOT NULL,
    pw_hash  BLOB NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    username   TEXT NOT NULL,
    expires    TEXT NOT NULL
);
"""


class AccountError(ValueError):
    pass


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, maxmem=64 * 1024 * 1024, **_SCRYPT)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AccountStore:
    """Users and sessions in one SQLite file (see module docstring).  Thread-safe."""

    def __init__(self, path: str | Path, clock=_now) -> None:
        self._con = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._con.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self.clock = clock

    def close(self) -> None:
        self._con.close()

    # -- users -----------------------------------------------------------------

    def create_user(self, username: str, password: str, role: str = "analyst") -> None:
        if not is_valid_analyst_id(username):
            raise AccountError("usernames are 1-64 characters: letters, digits, _ . @ -")
        if role not in ROLES:
            raise AccountError(f"role must be one of {ROLES}")
        if not isinstance(password, str) or len(password) < MIN_PASSWORD:
            raise AccountError(f"passwords have at least {MIN_PASSWORD} characters")
        salt = secrets.token_bytes(16)
        with self._lock:
            try:
                self._con.execute("INSERT INTO users VALUES (?, ?, ?, ?, 0, ?)",
                                  (username, role, salt, _hash(password, salt), self.clock().isoformat()))
            except sqlite3.IntegrityError:
                raise AccountError(f"user {username!r} exists") from None

    def set_password(self, username: str, password: str) -> None:
        if len(password) < MIN_PASSWORD:
            raise AccountError(f"passwords have at least {MIN_PASSWORD} characters")
        salt = secrets.token_bytes(16)
        with self._lock:
            cur = self._con.execute("UPDATE users SET salt = ?, pw_hash = ? WHERE username = ?",
                                    (salt, _hash(password, salt), username))
            self._con.execute("DELETE FROM sessions WHERE username = ?", (username,))
        if not cur.rowcount:
            raise AccountError(f"no user {username!r}")

    def set_disabled(self, username: str, disabled: bool) -> None:
        with self._lock:
            cur = self._con.execute("UPDATE users SET disabled = ? WHERE username = ?", (int(disabled), username))
            if disabled:
                self._con.execute("DELETE FROM sessions WHERE username = ?", (username,))
        if not cur.rowcount:
            raise AccountError(f"no user {username!r}")

    def users(self) -> list[dict]:
        with self._lock:
            rows = self._con.execute("SELECT username, role, disabled, created FROM users ORDER BY username").fetchall()
        return [{"username": u, "role": r, "disabled": bool(d), "created": c} for u, r, d, c in rows]

    # -- sessions --------------------------------------------------------------

    def login(self, username: str, password: str) -> tuple[str, str, datetime] | None:
        """(token, role, expiry) for valid credentials of an enabled user, else None."""
        with self._lock:
            row = self._con.execute("SELECT role, salt, pw_hash, disabled FROM users WHERE username = ?",
                                    (username,)).fetchone()
        if row is None:
            _hash(password, b"0" * 16)               # same work for unknown users (no timing oracle)
            return None
        role, salt, pw_hash, disabled = row
        if not hmac.compare_digest(_hash(password, salt), pw_hash) or disabled:
            return None
        token = secrets.token_urlsafe(32)
        expires = self.clock() + SESSION_TTL
        with self._lock:
            self._con.execute("INSERT INTO sessions VALUES (?, ?, ?)",
                              (hashlib.sha256(token.encode()).digest(), username, expires.isoformat()))
        return token, role, expires

    def resolve(self, token: str) -> tuple[str, str] | None:
        """(username, role) of a valid session token, else None."""
        th = hashlib.sha256(token.encode("utf-8")).digest()
        with self._lock:
            row = self._con.execute(
                "SELECT s.username, u.role, s.expires, u.disabled FROM sessions s JOIN users u USING (username)"
                " WHERE s.token_hash = ?", (th,)).fetchone()
        if row is None or row[3] or datetime.fromisoformat(row[2]) <= self.clock():
            return None
        return row[0], row[1]

    def logout(self, token: str) -> None:
        with self._lock:
            self._con.execute("DELETE FROM sessions WHERE token_hash = ?",
                              (hashlib.sha256(token.encode("utf-8")).digest(),))


def main() -> None:
    ap = argparse.ArgumentParser(description="AgentSOC accounts")
    ap.add_argument("--db", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-user")
    c.add_argument("username")
    c.add_argument("--role", default="analyst", choices=ROLES)
    sub.add_parser("list")
    args = ap.parse_args()
    store = AccountStore(args.db)
    if args.cmd == "list":
        for u in store.users():
            print(u)
        return
    password = os.environ.get("AGENTSOC_NEW_PASSWORD") or getpass.getpass(f"password for {args.username}: ")
    try:
        store.create_user(args.username, password, args.role)
    except AccountError as e:
        sys.exit(str(e))
    print(f"created {args.username} ({args.role})")


if __name__ == "__main__":
    main()
