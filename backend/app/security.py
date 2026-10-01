"""Personal sessions and least-privilege access for the operations API."""
from __future__ import annotations

import hmac
import ipaddress
import os
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


ROLE_PERMISSIONS = {
    "viewer": frozenset({"incident:read"}),
    "junior": frozenset({"incident:read", "incident:write", "source:scan"}),
    "senior": frozenset({"incident:read", "incident:write", "source:scan", "remediation:execute"}),
    "admin": frozenset({"incident:read", "incident:write", "source:scan", "remediation:execute",
                        "source:manage", "knowledge:import", "account:manage"}),
    "operator": frozenset({"incident:read", "incident:write", "source:scan"}),
    "alert_ingest": frozenset(),
    "guest": frozenset(),
}


def require_permission(request: Request, name: str) -> None:
    if name not in getattr(request.state, "permissions", ()):
        raise HTTPException(403, detail="Your account does not have permission for this operation.")


def is_loopback_request(request: Request) -> bool:
    peer = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(peer).is_loopback
    except ValueError:
        return peer == "testclient"


def same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    try:
        supplied = urlparse(origin)
        expected = urlparse(str(request.url))
        if supplied.username or supplied.password or supplied.path or supplied.query or supplied.fragment:
            return False
        return (supplied.scheme.lower(), supplied.hostname, supplied.port or (443 if supplied.scheme == "https" else 80)) == (
            expected.scheme.lower(), expected.hostname, expected.port or (443 if expected.scheme == "https" else 80))
    except ValueError:
        return False


def bootstrap_request_allowed(request: Request) -> bool:
    if not is_loopback_request(request) or not same_origin(request):
        return False
    host = request.url.hostname or ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or (host == "testserver" and request.client and request.client.host == "testclient")


def bearer_token(request: Request) -> str:
    value = request.headers.get("authorization", "")
    return value[7:] if value.lower().startswith("bearer ") else ""


class AccessMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, account_service=None):
        super().__init__(app)
        self.account_service = account_service

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/") or path == "/api/health":
            return await call_next(request)
        write = request.method not in {"GET", "HEAD", "OPTIONS"}
        if write and not same_origin(request):
            return JSONResponse({"detail": "Cross-site write requests are not allowed."}, status_code=403)
        request.state.role = "guest"
        request.state.operator = "guest"
        request.state.permissions = frozenset()
        request.state.account_id = None
        request.state.authenticated = False
        token = bearer_token(request)
        if path in {"/api/auth/login", "/api/auth/bootstrap"}:
            return await call_next(request)
        account = self.account_service.authenticate(token) if self.account_service and token else None
        operator_token = os.getenv("OPS_API_TOKEN", "")
        read_token = os.getenv("OPS_READ_TOKEN", "")
        webhook_token = os.getenv("ALERT_WEBHOOK_TOKEN", "")
        is_webhook = path == "/api/alerts/webhook"
        role = None
        if account:
            role = account["role"]
            request.state.account_id = account["id"]
            request.state.operator = account["username"]
        elif token and operator_token and hmac.compare_digest(token.encode("utf-8"), operator_token.encode("utf-8")):
            role = "operator"
            request.state.operator = "shared-operator"
        elif token and read_token and hmac.compare_digest(token.encode("utf-8"), read_token.encode("utf-8")):
            role = "viewer"
            request.state.operator = "shared-viewer"
        elif token and is_webhook and webhook_token and hmac.compare_digest(token.encode("utf-8"), webhook_token.encode("utf-8")):
            role = "alert_ingest"
            request.state.operator = "alert-platform"
        elif (not token and not (operator_token or read_token or (is_webhook and webhook_token))
              and is_loopback_request(request)
              and (not self.account_service or self.account_service.bootstrap_available())):
            role = "operator"
            request.state.operator = "local-operator"
        if role:
            request.state.role = role
            request.state.permissions = ROLE_PERMISSIONS[role]
            request.state.authenticated = True
        if path == "/api/auth/me":
            return await call_next(request)
        if role is None:
            return JSONResponse({"detail": "A valid access token or account session is required."}, status_code=401)
        if role == "alert_ingest":
            if is_webhook and request.method == "POST":
                return await call_next(request)
            return JSONResponse({"detail": "Alert tokens may only submit alerts."}, status_code=403)
        if write:
            permission = "incident:write"
            if path.startswith("/api/accounts"):
                permission = "account:manage"
            elif path.startswith("/api/sources"):
                permission = "source:scan" if path.endswith("/scan-now") else "source:manage"
            elif path == "/api/knowledge/import":
                permission = "knowledge:import"
            elif path.startswith("/api/remediation") or "/remediation" in path:
                permission = "remediation:execute"
            elif path == "/api/auth/logout":
                permission = None
            if permission and permission not in request.state.permissions:
                return JSONResponse({"detail": "Your role does not have permission for this operation."}, status_code=403)
        elif "incident:read" not in request.state.permissions:
            return JSONResponse({"detail": "Your role does not have read permission."}, status_code=403)
        return await call_next(request)
