"""Read-only, configured HTTP connectors for incident context collection."""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx


_KINDS = {"prometheus": "metrics", "metrics": "metrics", "loki": "logs", "logs": "logs", "changes": "changes", "topology": "topology"}
_LABELS = {"metrics": "监控指标", "logs": "关联日志", "changes": "发布变更", "topology": "依赖拓扑"}
_MAX_PAYLOAD = 256_000
_MAX_CONTEXT_TEXT = 24_000


def _stamp(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (float, int)):
        try:
            parsed = datetime.fromtimestamp(value, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return fallback
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return fallback
    else:
        return fallback
    parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    # Alert payloads may use year 0001 as the unresolved end-time sentinel.
    return parsed if parsed.year >= 1970 else fallback


def _label(value: Any) -> str:
    # PromQL and LogQL label values use JSON-compatible quoted string escapes.
    return json.dumps(str(value or "")[:500], ensure_ascii=False)[1:-1]


class ContextCollector:
    """Collect context from endpoints configured by the operator, never the model.

    A configuration is a JSON list or ``{"connectors": [...]}``. Each connector
    has ``name``, ``kind``, and a fixed ``url``. Prometheus/Loki additionally
    accept ``query`` templates with ``{service}`` and ``{instance}`` placeholders.
    Generic changes/topology connectors receive bounded time and identity query
    parameters. Injecting an AsyncClient supports offline connector testing.
    """

    def __init__(self, config_path: str | Path | None = None, *, configs: list[dict] | dict | None = None, client: httpx.AsyncClient | None = None):
        self.client = client
        self.config_error: str | None = None
        self.connectors: list[dict] = []
        self.timeout = 8.0
        self.window_minutes = 60.0
        path = config_path or os.getenv("CONTEXT_CONFIG_PATH")
        try:
            raw = configs
            if raw is None and path:
                raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict):
                self.timeout = min(30.0, max(0.1, float(raw.get("timeout_seconds", self.timeout))))
                self.window_minutes = min(360.0, max(1.0, float(raw.get("window_minutes", self.window_minutes))))
                raw = raw.get("connectors", raw.get("sources", []))
            if raw is not None and not isinstance(raw, list):
                raise ValueError("Context configuration must contain a connector list")
            self.connectors = [dict(item) for item in (raw or []) if isinstance(item, dict)][:20]
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.config_error = "上下文配置无法读取或格式无效，请检查 CONTEXT_CONFIG_PATH。"

    def _bounds(self, event: dict) -> tuple[datetime, datetime]:
        now = datetime.now(timezone.utc)
        end = _stamp(event.get("end_time") or event.get("ends_at") or event.get("endsAt"), now)
        end = min(end, now)
        start = _stamp(event.get("start_time") or event.get("starts_at") or event.get("startsAt"), end - timedelta(minutes=self.window_minutes))
        # Include the pre-incident window, capped to protect upstream systems.
        start = min(start, end - timedelta(minutes=self.window_minutes))
        start = max(start, end - timedelta(hours=6))
        return start, end

    async def collect(self, event: dict) -> dict:
        start, end = self._bounds(event)
        labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
        identity = {key: str(event.get(key) or labels.get(key) or "")[:500] for key in ("service", "instance")}
        if self.client is None:
            async with httpx.AsyncClient(follow_redirects=False, timeout=self.timeout) as client:
                sources = await asyncio.gather(*(self._collect_one(item, identity, start, end, client) for item in self.connectors))
        else:
            sources = await asyncio.gather(*(self._collect_one(item, identity, start, end, self.client) for item in self.connectors))
        configured = {source["kind"] for source in sources}
        observed_at = datetime.now(timezone.utc).isoformat()
        for kind, label in _LABELS.items():
            if kind not in configured:
                sources.append({"name": label, "kind": kind, "status": "not_configured", "data": None, "summary": f"{label}数据源未配置，无法验证其状态。", "error": None, "observed_at": observed_at, "source_url": None})
        if self.config_error:
            sources.append({"name": "上下文配置", "kind": "configuration", "status": "failed", "data": None, "summary": self.config_error, "error": self.config_error, "observed_at": observed_at, "source_url": None})
        collected_logs = [source.pop("_logs", "") for source in sources]
        logs = "\n".join(text for text in collected_logs if text)[:_MAX_CONTEXT_TEXT]
        context_parts = []
        for source in sources:
            context_parts.append(f"[{source['name']} / {source['kind']} / {source['status']}] {source['summary']}")
            if source["status"] == "ok":
                context_parts.append(json.dumps(source["data"], ensure_ascii=False)[:6_000])
        return {"context_sources": sources, "logs": logs, "context_text": "\n".join(context_parts)[:_MAX_CONTEXT_TEXT], "start_time": start.isoformat(), "end_time": end.isoformat()}

    async def _collect_one(self, config: dict, identity: dict, start: datetime, end: datetime, client: httpx.AsyncClient) -> dict:
        connector = str(config.get("kind", config.get("type", ""))).lower()
        kind = _KINDS.get(connector, connector or "unknown")
        name = str(config.get("name", _LABELS.get(kind, connector)))[:120]
        url = str(config.get("url", config.get("base_url", "")))
        result = {"name": name, "kind": kind, "status": "failed", "data": None, "summary": "", "error": None, "observed_at": datetime.now(timezone.utc).isoformat(), "source_url": url}
        try:
            parsed = urlsplit(url)
            if connector not in _KINDS or parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or "{" in url or "}" in url:
                raise ValueError("Connector requires a fixed HTTP(S) endpoint and a supported kind")
            params: dict[str, Any]
            if connector in {"prometheus", "metrics", "loki", "logs"}:
                query = config.get("query")
                if not isinstance(query, str) or not query.strip():
                    raise ValueError("A configured query template is required")
                for key, value in identity.items():
                    query = query.replace("{" + key + "}", _label(value))
                if len(query) > 12_000:
                    raise ValueError("Configured query exceeds the size limit")
                params = {"query": query}
                if kind == "metrics":
                    url = self._endpoint(url, "/api/v1/query")
                    params["time"] = end.timestamp()
                else:
                    url = self._endpoint(url, "/loki/api/v1/query_range")
                    params.update(start=int(start.timestamp() * 1_000_000_000), end=int(end.timestamp() * 1_000_000_000), limit=min(500, max(1, int(config.get("limit", 200)))), direction="backward")
            else:
                params = {**identity, "start": start.isoformat(), "end": end.isoformat()}
            timeout = min(30.0, max(0.1, float(config.get("timeout_seconds", self.timeout))))
            headers = {str(key): str(value) for key, value in config.get("headers", {}).items()} if isinstance(config.get("headers"), dict) else {}
            chunks: list[bytes] = []
            size = 0
            async with client.stream("GET", url, params=params, headers=headers, timeout=timeout, follow_redirects=False) as response:
                if response.status_code < 200 or response.status_code >= 300:
                    raise ValueError(f"HTTP {response.status_code}")
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > _MAX_PAYLOAD:
                        raise ValueError("Context response exceeds the size limit")
                    chunks.append(chunk)
            try:
                data = json.loads(b"".join(chunks))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError("Invalid JSON response") from exc
            if kind in {"metrics", "logs"}:
                if not isinstance(data, dict) or data.get("status") != "success" or not isinstance(data.get("data"), dict) or not isinstance(data["data"].get("result"), list):
                    raise ValueError("Monitoring API did not return a successful result")
            if not isinstance(data, (dict, list)):
                raise ValueError("Context response must be a JSON object or list")
            if isinstance(data, dict) and (data.get("error") or data.get("status") in {"failed", "error"}):
                raise ValueError("Context API reported a failure")
            if kind == "logs":
                lines: list[str] = []
                for stream in data["data"]["result"]:
                    if isinstance(stream, dict):
                        for value in stream.get("values", []):
                            if isinstance(value, list) and len(value) == 2:
                                lines.append(str(value[1])[:4_000])
                result["_logs"] = "\n".join(lines[:500])[:_MAX_CONTEXT_TEXT]
            result.update(status="ok", data=data, summary=f"已从 {_LABELS.get(kind, kind)}数据源 {name} 采集；时间窗口 {start.isoformat()} 至 {end.isoformat()}，空结果不能证明服务正常。", source_url=url)
        except httpx.TimeoutException:
            result["error"] = "上下文查询超时。"
        except httpx.RequestError:
            result["error"] = "无法连接配置的数据源。"
        except ValueError as exc:
            result["error"] = str(exc)[:200]
        except (TypeError, KeyError, OverflowError, RecursionError):
            result["error"] = "配置或响应字段格式无效。"
        if result["status"] == "failed":
            result["summary"] = f"{name}采集失败，无法判断该数据源状态：{result['error']}"
        result["observed_at"] = datetime.now(timezone.utc).isoformat()
        return result

    @staticmethod
    def _endpoint(url: str, suffix: str) -> str:
        if urlsplit(url).query:
            raise ValueError("Monitoring endpoint URLs must not contain query parameters")
        return url if url.rstrip("/").endswith(suffix) else url.rstrip("/") + suffix
