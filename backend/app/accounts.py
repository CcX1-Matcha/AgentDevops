"""SQLite accounts, salted passwords and revocable bearer sessions."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .security import ROLE_PERMISSIONS, bearer_token, bootstrap_request_allowed, require_permission


Role = Literal["viewer", "junior", "senior", "admin"]
_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,63}\Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_password(password: str) -> str:
    if not 9 <= len(password) <= 1024:
        raise ValueError("Password must contain between 9 and 1024 characters.")
    return password


def _validate_username(username: str) -> str:
    username = username.strip()
    if not _USERNAME.fullmatch(username):
        raise ValueError("Username must contain 3-64 letters, digits, dots, underscores or hyphens.")
    return username


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=64)
    return f"scrypt${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, salt, digest = stored.split("$")
        if algorithm != "scrypt":
            return False
        actual = _password_hash(password, bytes.fromhex(salt)).split("$")[2]
        return hmac.compare_digest(actual, digest)
    except (ValueError, TypeError):
        return False


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024, repr=False)


class BootstrapInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str = Field(repr=False)

    _username = field_validator("username")(_validate_username)
    _password = field_validator("password")(_validate_password)


class AccountCreate(BootstrapInput):
    role: Role = "junior"
    enabled: bool = True


class AccountPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    enabled: bool | None = None
    password: str | None = Field(default=None, repr=False)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return _validate_password(value) if value is not None else value


class AccountService:
    def __init__(self, path: str | Path, audit=None, session_ttl_seconds: int = 28_800):
        if session_ttl_seconds <= 0:
            raise ValueError("Session TTL must be positive.")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.audit = audit
        self.session_ttl_seconds = session_ttl_seconds
        self._lock = threading.RLock()
        self._failures: dict[str, deque] = defaultdict(deque)
        self._dummy_hash = _password_hash(secrets.token_urlsafe(24))
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                expires_at REAL NOT NULL, created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS session_account ON sessions(account_id);
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _record(self, action: str, target: str, actor: str, details: dict | None = None) -> None:
        if self.audit:
            self.audit(action, "account", target, actor, details or {})

    @staticmethod
    def _public(row) -> dict:
        return {"id": row["id"], "username": row["username"], "role": row["role"],
                "enabled": bool(row["enabled"]), "permissions": sorted(ROLE_PERMISSIONS[row["role"]]),
                "created_at": row["created_at"], "updated_at": row["updated_at"]}

    def bootstrap_available(self) -> bool:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0

    def list_accounts(self) -> dict:
        with self._lock:
            users = [self._public(row) for row in self._db.execute("SELECT * FROM accounts ORDER BY created_at, username")]
            return {"items": users, "total": len(users)}

    def _insert_account(self, username: str, password: str, role: str, enabled: bool) -> dict:
        _validate_password(password)
        username = _validate_username(username)
        if role not in {"viewer", "junior", "senior", "admin"}:
            raise ValueError("Unknown account role.")
        identifier = str(uuid4())
        timestamp = _now()
        try:
            self._db.execute("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (identifier, username, _password_hash(password), role, int(enabled), timestamp, timestamp))
        except sqlite3.IntegrityError as exc:
            raise ValueError("This username already exists.") from exc
        return self._public(self._db.execute("SELECT * FROM accounts WHERE id = ?", (identifier,)).fetchone())

    def create_account(self, username: str, password: str, role: str = "junior", enabled: bool = True, actor: str = "admin") -> dict:
        with self._lock, self._db:
            user = self._insert_account(username, password, role, enabled)
        self._record("account_created", user["id"], actor, {"username": user["username"], "role": role, "enabled": enabled})
        return user

    def _session(self, user: dict) -> dict:
        token = secrets.token_urlsafe(48)
        self._db.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        self._db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                         (hashlib.sha256(token.encode("utf-8")).hexdigest(), user["id"], time.time() + self.session_ttl_seconds, _now()))
        return {"token": token, "user": user}

    def bootstrap(self, username: str, password: str, issue_session: bool = True) -> dict:
        with self._lock, self._db:
            # Acquire the SQLite write lock before checking for a first account.
            self._db.execute("BEGIN IMMEDIATE")
            if not self.bootstrap_available():
                raise ValueError("The first administrator has already been initialized.")
            user = self._insert_account(username, password, "admin", True)
            result = self._session(user) if issue_session else {"user": user}
        self._record("auth_bootstrap", user["id"], user["username"], {"role": "admin"})
        return result

    def login(self, username: str, password: str, peer: str = "unknown") -> dict:
        now = time.monotonic()
        username = username.strip()
        with self._lock:
            attempts = self._failures[peer]
            while attempts and now - attempts[0] >= 300:
                attempts.popleft()
            if len(attempts) >= 8:
                raise HTTPException(429, detail="Too many failed login attempts. Try again in five minutes.")
            row = self._db.execute("SELECT * FROM accounts WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
            valid = _verify_password(password, row["password_hash"] if row else self._dummy_hash)
            if not row or not row["enabled"] or not valid:
                attempts.append(now)
                self._record("auth_login_failed", "login", "anonymous", {"username": username[:64]})
                raise HTTPException(401, detail="Invalid username or password.")
            with self._db:
                user = self._public(row)
                result = self._session(user)
            attempts.clear()
        self._record("auth_login", user["id"], user["username"])
        return result

    def authenticate(self, token: str) -> dict | None:
        if not token or len(token) > 4096:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            row = self._db.execute("SELECT accounts.* FROM sessions JOIN accounts ON accounts.id = sessions.account_id "
                                   "WHERE token_hash = ? AND expires_at > ? AND accounts.enabled = 1", (digest, time.time())).fetchone()
            return self._public(row) if row else None

    def logout(self, token: str) -> None:
        user = self.authenticate(token)
        with self._lock, self._db:
            self._db.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode("utf-8")).hexdigest(),))
        if user:
            self._record("auth_logout", user["id"], user["username"])

    def update_account(self, account_id: str, role: str | None = None, enabled: bool | None = None,
                       password: str | None = None, actor: str = "admin") -> dict:
        if role is not None and role not in {"viewer", "junior", "senior", "admin"}:
            raise ValueError("Unknown account role.")
        if password is not None:
            _validate_password(password)
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                raise KeyError(account_id)
            next_role = role if role is not None else row["role"]
            next_enabled = enabled if enabled is not None else bool(row["enabled"])
            if row["role"] == "admin" and row["enabled"] and (next_role != "admin" or not next_enabled):
                count = self._db.execute("SELECT COUNT(*) FROM accounts WHERE role = 'admin' AND enabled = 1").fetchone()[0]
                if count <= 1:
                    raise ValueError("The last enabled administrator cannot be disabled or demoted.")
            changed = next_role != row["role"] or next_enabled != bool(row["enabled"]) or password is not None
            if changed:
                self._db.execute("UPDATE accounts SET role = ?, enabled = ?, password_hash = ?, updated_at = ? WHERE id = ?",
                                 (next_role, int(next_enabled), _password_hash(password) if password is not None else row["password_hash"], _now(), account_id))
                self._db.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
            user = self._public(self._db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone())
        self._record("account_updated", account_id, actor, {"role": next_role, "enabled": next_enabled,
                                                          "password_changed": password is not None, "sessions_revoked": changed})
        return user


def create_account_router(service: AccountService) -> APIRouter:
    router = APIRouter(prefix="/api", tags=["accounts"])

    @router.get("/auth/me")
    def me(request: Request):
        return {"username": getattr(request.state, "operator", "guest"), "role": getattr(request.state, "role", "guest"),
                "permissions": sorted(getattr(request.state, "permissions", ())),
                "authenticated": getattr(request.state, "authenticated", False),
                "bootstrap_available": service.bootstrap_available() and bootstrap_request_allowed(request)}

    @router.post("/auth/bootstrap", status_code=201)
    def bootstrap(payload: BootstrapInput, request: Request):
        if not bootstrap_request_allowed(request):
            raise HTTPException(403, detail="The first administrator must be initialized from this machine.")
        try:
            return service.bootstrap(payload.username, payload.password)
        except ValueError as exc:
            raise HTTPException(409, detail=str(exc)) from exc

    @router.post("/auth/login")
    def login(payload: LoginInput, request: Request):
        return service.login(payload.username, payload.password, request.client.host if request.client else "unknown")

    @router.post("/auth/logout")
    def logout(request: Request):
        service.logout(bearer_token(request))
        return {"logged_out": True}

    @router.get("/accounts")
    def accounts(request: Request):
        require_permission(request, "account:manage")
        return service.list_accounts()

    @router.post("/accounts", status_code=201)
    def create_account(payload: AccountCreate, request: Request):
        require_permission(request, "account:manage")
        try:
            return service.create_account(payload.username, payload.password, payload.role, payload.enabled, request.state.operator)
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc)) from exc

    @router.patch("/accounts/{account_id}")
    def update_account(account_id: str, payload: AccountPatch, request: Request):
        require_permission(request, "account:manage")
        try:
            return service.update_account(account_id, **payload.model_dump(exclude_none=True), actor=request.state.operator)
        except KeyError as exc:
            raise HTTPException(404, detail="Account not found.") from exc
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc)) from exc

    return router


def main(argv: list[str] | None = None) -> int:
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="Initialize the first local operations administrator.")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap_parser = commands.add_parser("bootstrap")
    bootstrap_parser.add_argument("--username", required=True)
    bootstrap_parser.add_argument("--data-path", default=os.getenv("OPS_DATA_PATH", str(Path(__file__).resolve().parents[2] / "data")))
    args = parser.parse_args(argv)
    service = AccountService(Path(args.data_path).expanduser().resolve() / "accounts.sqlite3")
    try:
        if not service.bootstrap_available():
            print("An administrator is already initialized. Log in to manage accounts.")
            return 1
        username = _validate_username(args.username)
        password = getpass.getpass("Administrator password (at least 9 characters): ")
        _validate_password(password)
        confirmation = getpass.getpass("Confirm password: ")
        if not hmac.compare_digest(password.encode("utf-8"), confirmation.encode("utf-8")):
            print("Passwords do not match. No account was created.")
            return 1
        service.bootstrap(username, password, issue_session=False)
        print(f"Administrator '{username}' initialized. Sign in through the operations console.")
        return 0
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        print(str(exc) if isinstance(exc, ValueError) else "Initialization cancelled.")
        return 1
    finally:
        service.close()


if __name__ == "__main__":
    raise SystemExit(main())
