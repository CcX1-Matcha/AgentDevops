"""Local operator access and optional role tokens for the operations API."""
from __future__ import annotations

import hmac
import ipaddress
import os
from urllib.parse import urlparse

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class AccessMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api/") or request.url.path == "/api/health":
            return await call_next(request)
        token = request.headers.get("authorization", "")
        token = token[7:] if token.lower().startswith("bearer ") else ""
        operator_token = os.getenv("OPS_API_TOKEN", "")
        read_token = os.getenv("OPS_READ_TOKEN", "")
        webhook_token = os.getenv("ALERT_WEBHOOK_TOKEN", "")
        is_webhook = request.url.path == "/api/alerts/webhook"
        role = None
        if token and operator_token and hmac.compare_digest(token.encode("utf-8"), operator_token.encode("utf-8")):
            role = "operator"
        elif token and read_token and hmac.compare_digest(token.encode("utf-8"), read_token.encode("utf-8")):
            role = "viewer"
        elif token and is_webhook and webhook_token and hmac.compare_digest(token.encode("utf-8"), webhook_token.encode("utf-8")):
            role = "alert_ingest"
        elif not (operator_token or read_token or (is_webhook and webhook_token)):
            peer = request.client.host if request.client else ""
            try:
                local = ipaddress.ip_address(peer).is_loopback
            except ValueError:
                # TestClient has an in-process peer name rather than a socket.
                local = peer == "testclient"
            if local:
                role = "operator"
        if role is None:
            return JSONResponse({"detail": "需要有效的访问令牌；未配置令牌时仅允许本机访问。"}, status_code=401)
        write = request.method not in {"GET", "HEAD", "OPTIONS"}
        if write and role == "viewer":
            return JSONResponse({"detail": "只读角色不能修改数据源或处理故障事件。"}, status_code=403)
        origin = request.headers.get("origin")
        if write and not token and origin and urlparse(origin).netloc != request.url.netloc:
            return JSONResponse({"detail": "拒绝来自其他站点的写入请求。"}, status_code=403)
        request.state.role = role
        request.state.operator = "alert-platform" if role == "alert_ingest" else "local-operator" if not token else role
        return await call_next(request)
