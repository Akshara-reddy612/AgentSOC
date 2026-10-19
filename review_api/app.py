"""
review_api/app.py

HTTP API of the analyst review loop (step 5, 2026-10-11; decision B1:
FastAPI).  A thin layer over perception/review_service.py: the review logic
lives there, this module maps it to HTTP and adds authentication.

Security rules:
  - Who acts is decided by the bearer token, never by the request body: one
    token per analyst (AGENTSOC_ANALYST_TOKENS="alice:<token>,bob:<token>",
    at least 24 characters each), compared as SHA-256 digests in constant
    time.  Tokens are never logged or returned.  With an AccountStore
    (review_api/accounts.py) users sign in instead: /auth/login,
    /auth/password (own password), /admin/users/* (admins).  First run:
    while no account exists, /auth/setup creates the first admin (once; the
    server binds to localhost, so create it right after starting).
  - Request bodies are validated (fixed verdict vocabulary, length limits) and
    unknown fields are rejected, so a client cannot smuggle an "analyst"
    field.
  - Responses carry case data, including untrusted text (command lines, raw
    events) exactly as recorded: a client must render it as text, never as
    HTML.  Responses are marked no-store and nosniff.
  - Analysts never write the Knowledge Store: verdicts, approvals and
    rollbacks become commands in the case store, which the SOC loop applies
    (single writer, invariant I6).
Errors: 401 no / wrong token; 404 unknown case or action; 409 the case is
claimed by another analyst; 400 an action not allowed in the current state;
422 an invalid request body; 429 too many failed logins or password checks
(LoginThrottle); 409 on /auth/setup once an account exists.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from typing import Callable, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from perception.case_store import CaseStore, ConflictError, NotFoundError, ReviewError, is_valid_analyst_id
from perception.review_service import ReviewService

MIN_TOKEN_LENGTH = 24
Verdict = Literal["malicious", "benign", "benign_once", "needs_info"]


def load_tokens(spec: str) -> dict[str, str]:
    """
    "alice:<token>,bob:<token>" -> {token: analyst}.  Raises ValueError (without
    echoing any token) for a malformed list, a short or repeated token, or an
    invalid analyst id.
    """
    tokens: dict[str, str] = {}
    for part in (p.strip() for p in (spec or "").split(",")):
        if not part:
            continue
        analyst, sep, token = part.partition(":")
        if not sep or not is_valid_analyst_id(analyst):
            raise ValueError("AGENTSOC_ANALYST_TOKENS must be comma-separated analyst:token pairs "
                             "(analyst ids: letters, digits, _ . @ -)")
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"the token of analyst {analyst!r} is shorter than {MIN_TOKEN_LENGTH} characters")
        if token in tokens or analyst in tokens.values():
            raise ValueError("each analyst needs exactly one, distinct token")
        tokens[token] = analyst
    if not tokens:
        raise ValueError("no analyst tokens configured (AGENTSOC_ANALYST_TOKENS)")
    return tokens


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerdictIn(_Body):
    verdict: Verdict
    note: str | None = Field(default=None, max_length=10_000)


class BulkVerdictIn(VerdictIn):
    case_ids: list[str] = Field(min_length=1, max_length=500)


class NoteIn(_Body):
    text: str = Field(min_length=1, max_length=10_000)


class ReasonIn(_Body):
    reason: str = Field(min_length=1, max_length=1_000)


class LoginIn(_Body):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1_000)


class PasswordChangeIn(_Body):
    current_password: str = Field(min_length=1, max_length=1_000)
    new_password: str = Field(min_length=1, max_length=1_000)


class PasswordIn(_Body):
    password: str = Field(min_length=1, max_length=1_000)


class RoleIn(_Body):
    role: Literal["analyst", "lead", "admin"]


class NewUserIn(_Body):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1_000)
    role: Literal["analyst", "lead", "admin"] = "analyst"


def create_app(store: CaseStore, tokens: dict[str, str] | None = None, *, accounts=None,
               clock: Callable[[], datetime] | None = None, throttle=None) -> FastAPI:
    """
    The review API over `store`.  Authentication: `accounts` (review_api.accounts.AccountStore:
    users, roles, sessions) and/or fixed per-analyst `tokens` from load_tokens (role analyst;
    for tests and scripts).  `clock` for replays and tests.
    """
    if not tokens and accounts is None:
        raise ValueError("configure accounts or analyst tokens")
    service = ReviewService(store, clock=clock)
    if throttle is None and accounts is not None:
        from review_api.accounts import LoginThrottle
        throttle = LoginThrottle()
    digests = {hashlib.sha256(t.encode("utf-8")).digest(): a for t, a in (tokens or {}).items()}
    app = FastAPI(title="AgentSOC review API", version="1",
                  description="Analyst review loop: queue, cases, verdicts, actions, audit.")

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(ReviewError)
    async def _review_error(request: Request, exc: ReviewError):
        status = 404 if isinstance(exc, NotFoundError) else 409 if isinstance(exc, ConflictError) else 400
        return JSONResponse({"detail": str(exc)}, status_code=status)

    def principal(authorization: str | None = Header(default=None)) -> tuple[str, str]:
        """(username, role) of the bearer token: a session, or a fixed analyst token."""
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "a bearer token is required", headers={"WWW-Authenticate": "Bearer"})
        raw = authorization[len("Bearer "):]
        if accounts is not None and (found := accounts.resolve(raw)) is not None:
            return found
        given = hashlib.sha256(raw.encode("utf-8")).digest()
        who = None
        for digest, name in digests.items():        # every digest is compared: no early exit
            if hmac.compare_digest(given, digest):
                who = name
        if who is None:
            raise HTTPException(401, "unknown or expired token", headers={"WWW-Authenticate": "Bearer"})
        return who, "analyst"

    def analyst(p: tuple[str, str] = Depends(principal)) -> str:
        return p[0]

    def role(*allowed: str):
        def check(p: tuple[str, str] = Depends(principal)) -> tuple[str, str]:
            if p[1] not in allowed:
                raise HTTPException(403, f"needs role {' or '.join(allowed)}")
            return p
        return check

    app.state.principal, app.state.role = principal, role      # for routers added by soc_server

    @app.post("/auth/login")
    def login(body: LoginIn, request: Request) -> dict:
        if accounts is None:
            raise HTTPException(404, "accounts are not configured")
        address = request.client.host if request.client else "unknown"
        wait = throttle.retry_after(body.username, address)
        if wait is not None:
            raise HTTPException(429, "too many failed logins; try again later",
                                headers={"Retry-After": str(int(wait) + 1)})
        found = accounts.login(body.username, body.password)
        if found is None:
            throttle.failed(body.username, address)
            raise HTTPException(401, "wrong username or password")
        throttle.succeeded(body.username, address)
        token, user_role, expires = found
        return {"token": token, "username": body.username, "role": user_role, "expires": expires.isoformat()}

    @app.get("/auth/setup")
    def setup_needed() -> dict:
        """First run: no account exists yet, so the first one (an admin) can be created here."""
        return {"needed": accounts is not None and not accounts.has_users()}

    @app.post("/auth/setup")
    def setup(body: LoginIn) -> dict:
        from review_api.accounts import AccountError
        if accounts is None:
            raise HTTPException(404, "accounts are not configured")
        try:
            accounts.create_user(body.username, body.password, "admin", only_if_empty=True)
        except AccountError as e:
            raise HTTPException(409 if "exist" in str(e) else 400, str(e)) from None
        token, user_role, expires = accounts.login(body.username, body.password)
        return {"token": token, "username": body.username, "role": user_role, "expires": expires.isoformat()}

    @app.post("/auth/password")
    def change_password(body: PasswordChangeIn, request: Request, p: tuple[str, str] = Depends(principal)) -> dict:
        """Change one's own password; every session of the user ends (sign in again)."""
        from review_api.accounts import AccountError
        if accounts is None:
            raise HTTPException(404, "accounts are not configured")
        address = request.client.host if request.client else "unknown"
        wait = throttle.retry_after(p[0], address)
        if wait is not None:
            raise HTTPException(429, "too many failed attempts; try again later",
                                headers={"Retry-After": str(int(wait) + 1)})
        if not accounts.verify(p[0], body.current_password):
            throttle.failed(p[0], address)
            raise HTTPException(401, "current password is wrong")
        try:
            accounts.set_password(p[0], body.new_password)
        except AccountError as e:
            raise HTTPException(400, str(e)) from None
        return {"changed": p[0]}

    @app.post("/auth/logout")
    def logout(authorization: str | None = Header(default=None), p: tuple[str, str] = Depends(principal)) -> dict:
        if accounts is not None and authorization:
            accounts.logout(authorization[len("Bearer "):])
        return {"logged_out": p[0]}

    @app.get("/admin/users")
    def list_users(p: tuple[str, str] = Depends(role("admin"))) -> list[dict]:
        return accounts.users() if accounts is not None else []

    @app.post("/admin/users")
    def new_user(body: NewUserIn, p: tuple[str, str] = Depends(role("admin"))) -> dict:
        from review_api.accounts import AccountError
        if accounts is None:
            raise HTTPException(404, "accounts are not configured")
        try:
            accounts.create_user(body.username, body.password, body.role)
        except AccountError as e:
            raise HTTPException(400, str(e)) from None
        return {"created": body.username, "role": body.role}

    @app.post("/admin/users/{username}/disable")
    def disable_user(username: str, p: tuple[str, str] = Depends(role("admin"))) -> dict:
        from review_api.accounts import AccountError
        if username == p[0]:
            raise HTTPException(400, "admins cannot disable themselves")
        try:
            accounts.set_disabled(username, True)
        except (AccountError, AttributeError) as e:
            raise HTTPException(404, str(e)) from None
        return {"disabled": username}

    @app.post("/admin/users/{username}/enable")
    def enable_user(username: str, p: tuple[str, str] = Depends(role("admin"))) -> dict:
        from review_api.accounts import AccountError
        try:
            accounts.set_disabled(username, False)
        except (AccountError, AttributeError) as e:
            raise HTTPException(404, str(e)) from None
        return {"enabled": username}

    @app.post("/admin/users/{username}/role")
    def set_user_role(username: str, body: RoleIn, p: tuple[str, str] = Depends(role("admin"))) -> dict:
        from review_api.accounts import AccountError
        if username == p[0]:
            raise HTTPException(400, "admins cannot change their own role")
        try:
            accounts.set_role(username, body.role)
        except (AccountError, AttributeError) as e:
            raise HTTPException(404, str(e)) from None
        return {"username": username, "role": body.role}

    @app.post("/admin/users/{username}/password")
    def reset_password(username: str, body: PasswordIn, p: tuple[str, str] = Depends(role("admin"))) -> dict:
        """An admin sets a new password (the user's sessions end)."""
        from review_api.accounts import AccountError
        try:
            accounts.set_password(username, body.password)
        except AccountError as e:
            raise HTTPException(404 if "no user" in str(e) else 400, str(e)) from None
        except AttributeError as e:
            raise HTTPException(404, str(e)) from None
        return {"reset": username}

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/me")
    def me(p: tuple[str, str] = Depends(principal)) -> dict:
        return {"analyst": p[0], "role": p[1]}

    @app.get("/queue")
    def queue(limit: int = Query(50, ge=1, le=500), host: str | None = None, include_claimed: bool = True,
              who: str = Depends(analyst)) -> list[dict]:
        return service.queue(limit=limit, host=host, include_claimed=include_claimed)

    @app.get("/cases/{case_id}")
    def case(case_id: str, who: str = Depends(analyst)) -> dict:
        return service.case_view(case_id)

    @app.post("/cases/{case_id}/claim")
    def claim(case_id: str, who: str = Depends(analyst)) -> dict:
        service.claim(case_id, who)
        return {"case_id": case_id, "claimed_by": who}

    @app.post("/cases/{case_id}/release")
    def release(case_id: str, who: str = Depends(analyst)) -> dict:
        service.release(case_id, who)
        return {"case_id": case_id, "released_by": who}

    @app.post("/cases/{case_id}/verdict")
    def verdict(case_id: str, body: VerdictIn, who: str = Depends(analyst)) -> dict:
        return {"case_id": case_id, "verdict": body.verdict,
                "command_id": service.verdict(case_id, body.verdict, who, body.note)}

    @app.post("/cases/{case_id}/withdraw")
    def withdraw(case_id: str, body: ReasonIn, p: tuple[str, str] = Depends(role("lead", "admin"))) -> dict:
        return {"case_id": case_id, "status": "open", "command_id": service.withdraw(case_id, p[0], body.reason)}

    @app.post("/verdicts")
    def verdicts(body: BulkVerdictIn, who: str = Depends(analyst)) -> dict:
        ids = service.verdicts(body.case_ids, body.verdict, who, body.note)
        return {"verdict": body.verdict, "command_ids": dict(zip(body.case_ids, ids))}

    @app.post("/cases/{case_id}/notes")
    def note(case_id: str, body: NoteIn, who: str = Depends(analyst)) -> dict:
        service.note(case_id, who, body.text)
        return {"case_id": case_id, "added_by": who}

    @app.post("/actions/{action_id}/approve")
    def approve(action_id: str, who: str = Depends(analyst)) -> dict:
        cmd = service.approve(action_id, who)
        act = store.action(action_id)
        return {"action_id": action_id, "status": act["status"], "approvals": act["approvals"],
                "approvals_needed": act["approvals_needed"], "command_id": cmd}

    @app.post("/actions/{action_id}/reject")
    def reject(action_id: str, body: ReasonIn, who: str = Depends(analyst)) -> dict:
        service.reject(action_id, who, body.reason)
        return {"action_id": action_id, "status": "rejected"}

    @app.post("/actions/{action_id}/rollback")
    def rollback(action_id: str, body: ReasonIn, who: str = Depends(analyst)) -> dict:
        return {"action_id": action_id, "status": "rollback_requested",
                "command_id": service.rollback(action_id, who, body.reason)}

    @app.get("/audit")
    def audit(since_seq: int = Query(0, ge=0), case_id: str | None = None,
              who: str = Depends(analyst)) -> list[dict]:
        return store.audit(since_seq=since_seq, case_id=case_id)

    return app
