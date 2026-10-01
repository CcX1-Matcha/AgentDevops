"""Durable, read-only log monitoring, incident aggregation and diagnosis jobs."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import os
import sqlite3
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

from .agent import ReActAgent
from .ops_models import AlertInput, FollowupInput, IncidentPatch, MergeInput, SourceCreate, SourcePatch, SplitInput
from .parser import normalize_source, parse_logs


MAX_READ_BYTES = 262_144
MAX_CONTEXT_CHARS = 65_536
MAX_PARTIAL_BYTES = 65_536
_SEVERITY = {"info": 0, "warning": 1, "error": 2, "critical": 3}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


class OperationsService:
    def __init__(self, db_path: str | Path, agent: ReActAgent, context_provider=None, aggregation_seconds: int = 300):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.agent = agent
        self.context_provider = context_provider
        self.aggregation_seconds = aggregation_seconds
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY, aggregate_key TEXT NOT NULL, first_seen TEXT NOT NULL,
                status TEXT NOT NULL, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS incident_group ON incidents(aggregate_key, first_seen);
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, external_key TEXT UNIQUE, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS alert_incident ON alerts(incident_id);
            CREATE TABLE IF NOT EXISTS timeline (
                id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS diagnoses (
                id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, body TEXT NOT NULL);
        """)
        self._tasks: list[asyncio.Task] = []
        self._thread_jobs: set[asyncio.Task] = set()
        self._running = False
        self._scan_locks: dict[str, asyncio.Lock] = {}
        self._last_scan: dict[str, float] = {}
        # A killed process can leave a claimed job in diagnosing state.
        with self._lock, self._db:
            for row in self._db.execute("SELECT body FROM incidents WHERE status = 'diagnosing'").fetchall():
                event = json.loads(row["body"])
                event.update(status="new", needs_diagnosis=True)
                self._save_incident(event)

    def _get(self, table: str, item_id: str) -> dict:
        row = self._db.execute(f"SELECT body FROM {table} WHERE id = ?", (item_id,)).fetchone()
        if row is None:
            raise KeyError(item_id)
        return json.loads(row["body"])

    def _save_source(self, source: dict) -> None:
        self._db.execute("INSERT OR REPLACE INTO sources VALUES (?, ?)", (source["id"], _json(source)))

    def _save_incident(self, event: dict) -> None:
        self._db.execute("INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?)",
                         (event["id"], event["aggregate_key"], event["first_seen"], event["status"], _json(event)))

    def _audit(self, action: str, target: str, result: str = "ok", details: Any = None, actor: str = "agent", is_demo: bool = False) -> None:
        item = dict(id=str(uuid4()), action=action, actor=actor, target=target, result=result,
                    details=details, created_at=_now(), is_demo=is_demo)
        self._db.execute("INSERT INTO audit VALUES (?, ?)", (item["id"], _json(item)))

    def _timeline(self, event_id: str, action: str, message: str, data: Any = None, actor: str = "agent") -> None:
        item = dict(id=str(uuid4()), action=action, message=message, data=data, actor=actor, created_at=_now())
        self._db.execute("INSERT INTO timeline VALUES (?, ?, ?)", (item["id"], event_id, _json(item)))

    async def start(self) -> None:
        if self._running:
            return
        with self._lock, self._db:
            for row in self._db.execute("SELECT body FROM incidents WHERE status = 'diagnosing'").fetchall():
                event = json.loads(row["body"])
                event.update(status="new", needs_diagnosis=True)
                self._save_incident(event)
        self._running = True
        self._tasks = [asyncio.create_task(self._monitor_loop()), asyncio.create_task(self._diagnosis_loop())]

    async def stop(self, grace_seconds: float = 35) -> bool:
        self._running = False
        deadline = time.monotonic() + max(0, grace_seconds)
        drained = True
        monitor = self._tasks[0] if self._tasks else None
        worker = self._tasks[1] if len(self._tasks) > 1 else None
        if monitor:
            monitor.cancel()
            await asyncio.gather(monitor, return_exceptions=True)
        if worker:
            try:
                await asyncio.wait_for(asyncio.shield(worker), timeout=max(0, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                drained = False
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
            except Exception:
                drained = False
        if self._thread_jobs:
            _, pending = await asyncio.wait(list(self._thread_jobs), timeout=max(0, deadline - time.monotonic()))
            drained = drained and not pending
        self._tasks = []
        return drained

    async def _run_in_thread(self, call, *args, **kwargs):
        # Shield the thread future so cancellation cannot hide live work from shutdown.
        job = asyncio.create_task(asyncio.to_thread(call, *args, **kwargs))
        self._thread_jobs.add(job)

        def completed(task):
            self._thread_jobs.discard(task)
            if not task.cancelled():
                task.exception()

        job.add_done_callback(completed)
        return await asyncio.shield(job)

    def monitor_health(self) -> dict:
        errors = []
        names = ("log_monitor", "diagnosis_worker")
        if self._running:
            for index, name in enumerate(names):
                if index >= len(self._tasks):
                    errors.append({"task": name, "error": "Background task is missing"})
                    continue
                task = self._tasks[index]
                if task.cancelled():
                    errors.append({"task": name, "error": "Background task was cancelled unexpectedly"})
                elif task.done():
                    exception = task.exception()
                    message = f"{type(exception).__name__}: {exception}" if exception else "Background task exited unexpectedly"
                    errors.append({"task": name, "error": message})
        running = self._running and not errors
        return {"running": running, "status": "degraded" if errors else "running" if running else "stopped", "errors": errors}

    def create_source(self, payload: SourceCreate | dict, operator: str = "operator") -> dict:
        request = payload if isinstance(payload, SourceCreate) else SourceCreate.model_validate(payload)
        source = request.model_dump()
        source["source"] = normalize_source(source["source"])
        source["path"] = str(Path(source["path"]).expanduser().resolve())
        source.update(id=str(uuid4()), created_at=_now(), cursor_offset=None, file_identity=None,
                      checkpoint="", head_checkpoint="", partial="", discard_until_newline=False, last_polled_at=None,
                      last_anomaly_at=None, last_error=None, collection_warning=None, health="pending", log_context="")
        try:
            with Path(source["path"]).open("rb") as stream:
                stat = os.fstat(stream.fileno())
                offset = 0 if source["read_existing"] else stat.st_size
                source.update(cursor_offset=offset, file_identity=f"{stat.st_dev}:{stat.st_ino}", health="ok")
                if offset:
                    stream.seek(max(0, offset - 64))
                    tail = stream.read(min(64, offset))
                    source["checkpoint"] = hashlib.sha256(tail).hexdigest()
                    source["discard_until_newline"] = not source["read_existing"] and not tail.endswith(b"\n")
                    stream.seek(0)
                    source["head_checkpoint"] = hashlib.sha256(stream.read(min(64, offset))).hexdigest()
        except OSError as exc:
            source.update(health="error", last_error=f"{type(exc).__name__}: {exc}")
        if not source["enabled"]:
            source["health"] = "paused"
        with self._lock, self._db:
            if any(item["path"] == source["path"] for item in self.list_sources()["items"]):
                raise ValueError("This log file is already registered")
            self._save_source(source)
            self._audit("source_created", source["id"], details={"path": source["path"], "read_existing": source["read_existing"]},
                        actor=operator, is_demo=source["is_demo"])
        return self._public_source(source)

    def ensure_source(self, payload: SourceCreate | dict, update_existing: bool = False) -> dict:
        request = payload if isinstance(payload, SourceCreate) else SourceCreate.model_validate(payload)
        value = request.model_dump()
        path = str(Path(value["path"]).expanduser().resolve())
        for item in self.list_sources()["items"]:
            if item["path"] == path:
                if update_existing:
                    with self._lock, self._db:
                        source = self._get("sources", item["id"])
                        source.update(value, path=path, source=normalize_source(value["source"]))
                        source["health"] = "paused" if not source["enabled"] else ("error" if source["last_error"] else "ok")
                        self._save_source(source)
                        self._audit("source_configuration_applied", source["id"], details=value, actor="configuration", is_demo=source["is_demo"])
                        return self._public_source(source)
                return item
        return self.create_source(request)

    @staticmethod
    def _public_source(source: dict) -> dict:
        return {key: value for key, value in source.items() if key not in {"partial", "checkpoint", "head_checkpoint", "log_context", "file_identity", "discard_until_newline"}}

    def list_sources(self) -> dict:
        with self._lock:
            items = [self._public_source(json.loads(row["body"])) for row in self._db.execute("SELECT body FROM sources ORDER BY rowid")]
        return {"items": items, "total": len(items)}

    def update_source(self, source_id: str, patch: SourcePatch, operator: str = "operator") -> dict:
        with self._lock, self._db:
            source = self._get("sources", source_id)
            source.update(patch.model_dump(exclude_none=True))
            source["health"] = "paused" if not source["enabled"] else ("error" if source["last_error"] else "ok")
            self._save_source(source)
            self._audit("source_updated", source_id, details=patch.model_dump(exclude_none=True), actor=operator, is_demo=source["is_demo"])
            return self._public_source(source)

    def delete_source(self, source_id: str, operator: str = "operator") -> dict:
        with self._lock, self._db:
            source = self._get("sources", source_id)
            self._db.execute("DELETE FROM sources WHERE id = ?", (source_id,))
            self._audit("source_deleted", source_id, actor=operator, is_demo=source["is_demo"])
        return {"deleted": True, "id": source_id}

    async def scan_source(self, source_id: str) -> dict:
        lock = self._scan_locks.setdefault(source_id, asyncio.Lock())
        async with lock:
            return await self._run_in_thread(self._scan_source_sync, source_id)

    def _scan_source_sync(self, source_id: str) -> dict:
        with self._lock, self._db:
            source = self._get("sources", source_id)
            if not source["enabled"]:
                return {"source": self._public_source(source), "lines_read": 0, "anomalies_detected": 0, "incident_ids": []}
            source["last_polled_at"] = _now()
            try:
                with Path(source["path"]).open("rb") as stream:
                    stat = os.fstat(stream.fileno())
                    identity = f"{stat.st_dev}:{stat.st_ino}"
                    offset = source["cursor_offset"]
                    if offset is None:
                        offset = 0 if source["read_existing"] else stat.st_size
                    rewritten = False
                    if offset and stat.st_size >= offset and source["checkpoint"]:
                        stream.seek(max(0, offset - 64))
                        rewritten = hashlib.sha256(stream.read(min(64, offset))).hexdigest() != source["checkpoint"]
                        if source.get("head_checkpoint"):
                            stream.seek(0)
                            rewritten = rewritten or hashlib.sha256(stream.read(min(64, offset))).hexdigest() != source["head_checkpoint"]
                    if source["file_identity"] not in (None, identity) or stat.st_size < offset or rewritten:
                        offset = 0
                        source.update(partial="", discard_until_newline=False)
                        self._audit("log_rotated_or_truncated", source_id, details={"path": source["path"]}, is_demo=source["is_demo"])
                    stream.seek(offset)
                    data = stream.read(MAX_READ_BYTES)
                    offset += len(data)
                    stream.seek(max(0, offset - 64))
                    checkpoint = hashlib.sha256(stream.read(min(64, offset))).hexdigest() if offset else ""
                    stream.seek(0)
                    head_checkpoint = hashlib.sha256(stream.read(min(64, offset))).hexdigest() if offset else ""
                if source["discard_until_newline"]:
                    boundary = data.find(b"\n")
                    if boundary < 0:
                        data = b""
                    else:
                        data = data[boundary + 1:]
                        source["discard_until_newline"] = False
                pending = base64.b64decode(source["partial"]) + data
                boundary = pending.rfind(b"\n")
                complete, partial = (pending[:boundary + 1], pending[boundary + 1:]) if boundary >= 0 else (b"", pending)
                if len(partial) > MAX_PARTIAL_BYTES:
                    partial = b""
                    source.update(discard_until_newline=True, collection_warning="Oversized unterminated log line was skipped (64 KiB limit)")
                    self._audit("log_line_limit", source_id, result="partial", details=source["collection_warning"], is_demo=source["is_demo"])
                text = complete.decode("utf-8", errors="replace")
                source.update(cursor_offset=offset, file_identity=identity, checkpoint=checkpoint,
                              head_checkpoint=head_checkpoint, partial=base64.b64encode(partial).decode("ascii"), health="ok", last_error=None)
                source["log_context"] = (source["log_context"] + text)[-MAX_CONTEXT_CHARS:]
            except OSError as exc:
                error = f"{type(exc).__name__}: {exc}"
                if source["last_error"] != error:
                    self._audit("log_collection_failed", source_id, result="failed", details=error, is_demo=source["is_demo"])
                source.update(health="error", last_error=error)
                self._save_source(source)
                return {"source": self._public_source(source), "lines_read": 0, "anomalies_detected": 0, "incident_ids": [], "error": error}
            parsed = parse_logs(text, source["source"])
            anomalies = [item for item in parsed if item.severity in {"critical", "error", "warning"}]
            incident_ids = []
            for item in anomalies:
                alert = AlertInput(service=source["service"], environment=source["environment"], instance=source["instance"],
                                   source=source["source"], severity=item.severity, message=item.message if len(item.message) <= 32_768 else item.message[:16_300] + "\n[log line truncated]\n" + item.message[-16_300:], is_demo=source["is_demo"])
                event = self._ingest(alert, source_id, item.failure_type, item.source)
                if event:
                    incident_ids.append(event["id"])
            if anomalies:
                source["last_anomaly_at"] = _now()
            self._save_source(source)
            return {"source": self._public_source(source), "lines_read": len(parsed), "anomalies_detected": len(anomalies),
                    "incident_ids": list(dict.fromkeys(incident_ids))}

    def ingest_alert(self, payload: AlertInput | dict) -> dict | None:
        alert = payload if isinstance(payload, AlertInput) else AlertInput.model_validate(payload)
        with self._lock, self._db:
            return self._ingest(alert)

    def ingest_alerts(self, alerts: list[AlertInput], operator: str = "agent") -> list[dict]:
        with self._lock, self._db:
            return [event for alert in alerts if (event := self._ingest(alert, operator=operator)) is not None]

    def _ingest(self, alert: AlertInput, source_id: str | None = None, kind: str | None = None, detected_source: str | None = None, operator: str = "agent") -> dict | None:
        parsed = parse_logs(alert.message, alert.source)
        actionable = [item for item in parsed if item.failure_type != "normal"]
        kind = kind or (Counter(item.failure_type for item in actionable).most_common(1)[0][0] if actionable else "unknown_error")
        detected_source = detected_source or (parsed[0].source if parsed else normalize_source(alert.source))
        aggregate_key = hashlib.sha256(_json([alert.service, alert.environment, alert.instance, kind, alert.is_demo]).encode()).hexdigest()
        external_key = f"{alert.fingerprint}:{alert.starts_at or ''}:{alert.status}" if alert.fingerprint else None
        if external_key:
            duplicate = self._db.execute("SELECT incident_id FROM alerts WHERE external_key = ?", (external_key,)).fetchone()
            if duplicate:
                return self._public_incident(self._get("incidents", duplicate["incident_id"]))
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=self.aggregation_seconds)).isoformat()
        row = self._db.execute("SELECT body FROM incidents WHERE aggregate_key = ? AND first_seen >= ? AND status != 'resolved' ORDER BY first_seen DESC LIMIT 1", (aggregate_key, cutoff)).fetchone()
        if alert.status == "resolved" and alert.fingerprint:
            firing = self._db.execute("SELECT incident_id FROM alerts WHERE external_key = ?", (f"{alert.fingerprint}:{alert.starts_at or ''}:firing",)).fetchone()
            if firing:
                row = self._db.execute("SELECT body FROM incidents WHERE id = ?", (firing["incident_id"],)).fetchone()
        if alert.status == "resolved" and row is None:
            self._audit("alert_resolved_without_event", alert.instance, details=alert.model_dump(), is_demo=alert.is_demo)
            return None
        now = _now()
        event = json.loads(row["body"]) if row else dict(
            id=str(uuid4()), aggregate_key=aggregate_key, source_id=source_id, service=alert.service,
            environment=alert.environment, instance=alert.instance, source=detected_source,
            severity=alert.severity, failure_type=kind, title=f"{alert.service} · {kind}", status="new",
            occurrences=0, first_seen=now, last_seen=now, is_demo=alert.is_demo, diagnosis=None,
            diagnosis_error=None, fallback_reason=None, context_collection={}, context_notes=[],
            logs="", revision=0, needs_diagnosis=True, resolution=None, resolved_at=None,
            confirmed_at=None, impact_scope={"service": alert.service, "instance": alert.instance, "environment": alert.environment,
                                           "affected_users": None, "affected_endpoints": None},
        )
        raw = alert.model_dump()
        raw.update(id=str(uuid4()), received_at=now, failure_type=kind, source_id=source_id)
        self._db.execute("INSERT INTO alerts VALUES (?, ?, ?, ?)", (raw["id"], event["id"], external_key, _json(raw)))
        event["occurrences"] += 1
        event["last_seen"] = now
        if alert.status == "firing":
            event["logs"] = (event["logs"] + "\n" + alert.message)[-MAX_CONTEXT_CHARS:]
            event["revision"] += 1
            event["needs_diagnosis"] = True
            if _SEVERITY[alert.severity] > _SEVERITY[event["severity"]]:
                event["severity"] = alert.severity
            if event["status"] not in {"diagnosing", "acknowledged"}:
                event["status"] = "new"
        self._save_incident(event)
        self._timeline(event["id"], "alert_received" if row else "incident_created", alert.message[:500], {"alert_id": raw["id"], "status": alert.status}, actor=operator)
        self._audit("alert_ingested", event["id"], details={"alert_id": raw["id"], "aggregated": bool(row), "status": alert.status}, actor=operator, is_demo=alert.is_demo)
        return self._public_incident(event)

    async def _monitor_loop(self) -> None:
        while self._running:
            for source in self.list_sources()["items"]:
                if source["enabled"] and time.monotonic() - self._last_scan.get(source["id"], 0) >= source["poll_interval_seconds"]:
                    try:
                        await self.scan_source(source["id"])
                    except KeyError:
                        pass
                    except Exception as exc:
                        with self._lock, self._db:
                            self._audit("monitor_failed", source["id"], result="failed", details=str(exc), is_demo=source["is_demo"])
                    self._last_scan[source["id"]] = time.monotonic()
            await asyncio.sleep(0.25)

    def _claim_job(self) -> dict | None:
        with self._lock, self._db:
            for row in self._db.execute("SELECT body FROM incidents WHERE status != 'resolved' ORDER BY first_seen").fetchall():
                event = json.loads(row["body"])
                if event["needs_diagnosis"] and event["status"] != "diagnosing":
                    event.update(status="diagnosing", needs_diagnosis=False)
                    self._save_incident(event)
                    self._timeline(event["id"], "diagnosis_started", "自动采集上下文并执行诊断")
                    return event
        return None

    async def _diagnosis_loop(self) -> None:
        while self._running:
            event = self._claim_job()
            if event is None:
                await asyncio.sleep(0.2)
                continue
            await self._diagnose_event(event)

    async def _diagnose_event(self, event: dict) -> None:
        collection: dict = {"context_sources": [{"name": "external_context", "status": "not_configured", "summary": "尚未配置监控、变更或拓扑数据源"}]}
        fallback_reason = None
        try:
            if self.context_provider:
                try:
                    if inspect.iscoroutinefunction(self.context_provider):
                        collection = await asyncio.wait_for(self.context_provider({**self.get_incident(event["id"]), "start_time": event["first_seen"], "end_time": event["last_seen"]}), timeout=30)
                    else:
                        collection = await asyncio.wait_for(self._run_in_thread(self.context_provider, {**self.get_incident(event["id"]), "start_time": event["first_seen"], "end_time": event["last_seen"]}), timeout=30)
                    if inspect.isawaitable(collection):
                        collection = await asyncio.wait_for(collection, timeout=30)
                    if not isinstance(collection, dict):
                        raise ValueError("Context provider must return an object")
                except Exception as exc:
                    collection = {"context_sources": [{"name": "context_provider", "status": "failed", "error": str(exc), "observed_at": _now()}]}
            logs = event["logs"]
            if event["source_id"]:
                with self._lock:
                    try:
                        source = self._get("sources", event["source_id"])
                        # Include nearby normal logs, without interpreting a missing source as healthy.
                        nearby = "\n".join(item.message for item in parse_logs(source["log_context"], source["source"]) if item.severity == "info")
                        logs = (nearby + "\n" + logs)[-MAX_CONTEXT_CHARS:]
                        collection.setdefault("context_sources", []).append({"name": source["name"], "kind": "local_log", "status": "failed" if source["last_error"] else "ok",
                            "error": source["last_error"], "summary": f"只读日志采集：{source['path']}", "observed_at": source["last_polled_at"]})
                    except KeyError:
                        collection.setdefault("context_sources", []).append({"name": "local_log", "status": "failed", "error": "Source was removed"})
            logs = (logs + "\n" + str(collection.get("logs", "")))[-MAX_CONTEXT_CHARS:]
            context = "\n".join([f"服务={event['service']} 环境={event['environment']} 实例={event['instance']} 告警类型={event['failure_type']}",
                                 str(collection.get("context_text", "")), *[item["message"] for item in event["context_notes"]]])[:10_000]
            diagnose_kwargs = {"observations": collection} if "observations" in inspect.signature(self.agent.diagnose).parameters else {}
            try:
                result = await self._run_in_thread(self.agent.diagnose, logs, event["source"] if event["source"] in {"server", "nginx", "docker", "kubernetes"} else "auto", context, **diagnose_kwargs)
            except Exception as exc:
                if getattr(self.agent, "mode", "local") != "llm":
                    raise
                fallback_reason = f"LLM unavailable: {type(exc).__name__}: {exc}"
                fallback = ReActAgent(store=self.agent.store)
                fallback.mode = "local"
                result = await self._run_in_thread(fallback.diagnose, logs, event["source"] if event["source"] in {"server", "nginx", "docker", "kubernetes"} else "auto", context, **diagnose_kwargs)
            diagnosis = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
            diagnosis["confirmed"] = False
            diagnosis.setdefault("boundary", "根因是日志与知识库支持的候选判断，仍需人工核对指标、依赖和近期变更。")
            if fallback_reason:
                diagnosis["degraded"] = True
                diagnosis["boundary"] += f" LLM 调用失败，已使用本地诊断降级：{fallback_reason}"
            diagnosis["impact_scope"] = event["impact_scope"]
            missing = list(dict.fromkeys(diagnosis.get("missing_information", [])))
            for item in collection.get("context_sources", []):
                name = item.get("name", "context")
                if item.get("status") != "ok" and not any(name in description for description in missing):
                    missing.append(name)
            diagnosis["missing_information"] = missing
            for step in diagnosis.get("steps", []):
                step.setdefault("execution", "manual")
                step.setdefault("risk", "requires_review")
            with self._lock, self._db:
                current = self._get("incidents", event["id"])
                current.update(diagnosis=diagnosis, context_collection=collection, fallback_reason=fallback_reason, diagnosis_error=None,
                               title=diagnosis.get("summary", current["title"]), last_diagnosed_at=_now(), needs_diagnosis=current["revision"] != event["revision"])
                if current["status"] != "resolved":
                    current["status"] = "new" if current["needs_diagnosis"] else ("acknowledged" if current.get("confirmed_at") else "awaiting_confirmation")
                self._save_incident(current)
                history = {"id": str(uuid4()), "diagnosis": diagnosis, "context_collection": collection, "fallback_reason": fallback_reason, "created_at": _now()}
                self._db.execute("INSERT INTO diagnoses VALUES (?, ?, ?)", (history["id"], event["id"], _json(history)))
                for item in collection.get("context_sources", []):
                    self._audit("context_collected", event["id"], result=item.get("status", "unknown"), details=item, is_demo=current["is_demo"])
                self._timeline(event["id"], "diagnosis_completed", diagnosis.get("summary", "诊断完成"), {"mode": diagnosis.get("mode"), "fallback_reason": fallback_reason})
                self._audit("diagnosis_completed", event["id"], result="degraded" if fallback_reason else "ok", details={"mode": diagnosis.get("mode"), "fallback_reason": fallback_reason}, is_demo=current["is_demo"])
        except Exception as exc:
            with self._lock, self._db:
                current = self._get("incidents", event["id"])
                current.update(status="failed" if current["status"] != "resolved" else "resolved", diagnosis_error=f"{type(exc).__name__}: {exc}", context_collection=collection)
                self._save_incident(current)
                self._timeline(event["id"], "diagnosis_failed", current["diagnosis_error"])
                self._audit("diagnosis_failed", event["id"], result="failed", details=current["diagnosis_error"], is_demo=current["is_demo"])

    def list_incidents(self, status: str | None = None, severity: str | None = None, is_demo: bool | None = None, limit: int = 100) -> dict:
        with self._lock:
            items = [json.loads(row["body"]) for row in self._db.execute("SELECT body FROM incidents ORDER BY first_seen DESC")]
        items = [item for item in items if (not status or item["status"] == status) and (not severity or item["severity"] == severity) and (is_demo is None or item["is_demo"] == is_demo)]
        total = len(items)
        return {"items": [self._public_incident(item) for item in items[:limit]], "total": total}

    @staticmethod
    def _public_incident(event: dict) -> dict:
        return {key: value for key, value in event.items() if key not in {"logs", "aggregate_key", "needs_diagnosis", "revision"}}

    def get_incident(self, event_id: str) -> dict:
        with self._lock:
            event = self._public_incident(self._get("incidents", event_id))
            for key, table in (("original_alerts", "alerts"), ("timeline", "timeline"), ("diagnosis_history", "diagnoses")):
                event[key] = [json.loads(row["body"]) for row in self._db.execute(f"SELECT body FROM {table} WHERE incident_id = ? ORDER BY rowid", (event_id,))]
        return event

    def update_incident(self, event_id: str, request: IncidentPatch) -> dict:
        with self._lock, self._db:
            event = self._get("incidents", event_id)
            event["status"] = request.status
            if request.status == "acknowledged":
                event["confirmed_at"] = _now()
            elif request.status == "resolved":
                event.update(resolved_at=_now(), resolution=request.resolution, needs_diagnosis=False)
            elif request.status == "awaiting_confirmation":
                event.update(confirmed_at=None, resolved_at=None)
            self._save_incident(event)
            self._timeline(event_id, "status_changed", request.resolution or request.status, {"status": request.status}, actor=request.operator)
            self._audit("incident_status_changed", event_id, details=request.model_dump(), actor=request.operator, is_demo=event["is_demo"])
        return self.get_incident(event_id)

    def followup(self, event_id: str, request: FollowupInput) -> dict:
        with self._lock, self._db:
            event = self._get("incidents", event_id)
            event["context_notes"].append({"message": request.message, "actor": request.operator, "created_at": _now()})
            event["context_notes"] = event["context_notes"][-30:]
            if request.logs:
                event["logs"] = (event["logs"] + "\n" + request.logs)[-MAX_CONTEXT_CHARS:]
            event.update(revision=event["revision"] + 1, needs_diagnosis=True, resolved_at=None)
            if event["status"] != "diagnosing":
                event["status"] = "new"
            self._save_incident(event)
            self._timeline(event_id, "context_added", request.message, actor=request.operator)
            self._audit("incident_followup", event_id, details={"message": request.message, "has_logs": bool(request.logs)}, actor=request.operator, is_demo=event["is_demo"])
        return self.get_incident(event_id)

    async def verify_incident(self, event_id: str, operator: str = "operator") -> dict:
        event = self.get_incident(event_id)
        result = {"healthy": None, "log_check_passed": None, "observed_errors": None, "checked_at": _now(), "note": "没有持续采集数据源，无法自动验证恢复。"}
        if event["source_id"]:
            try:
                scanned = await self.scan_source(event["source_id"])
                if scanned.get("error"):
                    result["note"] = f"采集失败：{scanned['error']}"
                elif not scanned["source"]["enabled"]:
                    result["note"] = "数据源已暂停，无法验证恢复。"
                elif not scanned["lines_read"]:
                    result["note"] = "尚无新增完整日志行，不能据此判断服务恢复。"
                else:
                    passed = scanned["anomalies_detected"] == 0
                    result.update(healthy=None if passed else False, log_check_passed=passed, observed_errors=scanned["anomalies_detected"],
                                  note="新增日志未发现异常，业务恢复状态尚未验证。" if passed else "新增日志仍存在异常，服务整体健康需关联指标确认。")
            except KeyError:
                result["note"] = "采集数据源已删除，无法验证恢复。"
        with self._lock, self._db:
            self._timeline(event_id, "recovery_verified", result["note"], result, actor=operator)
            self._audit("recovery_verified", event_id, result="unknown" if result["healthy"] is None else "ok", details=result, actor=operator, is_demo=event["is_demo"])
        return result

    def audit(self, action: str | None = None, target_kind: str | None = None, target_id: str | None = None,
              operator: str = "agent", details: Any = None, limit: int = 100) -> dict:
        with self._lock:
            if action:
                with self._db:
                    self._audit(action, target_id or target_kind or "operations", details={"target_kind": target_kind, "data": details}, actor=operator,
                                is_demo=action.startswith("demo_"))
                return {"recorded": True}
            total = self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            items = [json.loads(row["body"]) for row in self._db.execute("SELECT body FROM audit ORDER BY rowid DESC LIMIT ?", (limit,))]
        return {"items": items, "total": total}

    def overview(self, is_demo: bool | None = None) -> dict:
        events = self.list_incidents(is_demo=is_demo, limit=100_000)["items"]
        sources = self.list_sources()["items"]
        if is_demo is not None:
            sources = [source for source in sources if source["is_demo"] == is_demo]
        diagnoses = [event["diagnosis"] for event in events if event["diagnosis"]]
        duration = [item["metrics"]["duration_ms"] for item in diagnoses if item.get("metrics")]
        resolved = [event for event in events if event.get("resolved_at") and not event["is_demo"]]
        mttr = [(datetime.fromisoformat(event["resolved_at"]) - datetime.fromisoformat(event["first_seen"])).total_seconds() for event in resolved]
        metrics = dict(total_incidents=len(events), active_incidents=sum(event["status"] != "resolved" for event in events),
                       diagnosed_incidents=len(diagnoses), original_alerts=sum(event["occurrences"] for event in events),
                       enabled_sources=sum(source["enabled"] for source in sources), unhealthy_sources=sum(source["health"] == "error" for source in sources),
                       demo_incidents=sum(event["is_demo"] for event in events), mean_diagnosis_ms=round(sum(duration) / len(duration), 2) if duration else None,
                       top1_accuracy=None, top3_accuracy=None, adoption_rate=None, mttr_seconds=round(sum(mttr) / len(mttr), 2) if mttr else None)
        return dict(monitor={**self.monitor_health(), "poll_interval_seconds": 0.25, "aggregation_seconds": self.aggregation_seconds},
                    metrics=metrics, recent_incidents=events[:8], source_health=sources,
                    failure_distribution=[{"failure_type": key, "count": value} for key, value in Counter(event["failure_type"] for event in events).most_common()])

    async def wait_for_idle(self, timeout: float = 10) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                pending = any(json.loads(row["body"]).get("needs_diagnosis") or json.loads(row["body"])["status"] == "diagnosing" for row in self._db.execute("SELECT body FROM incidents WHERE status != 'resolved'"))
            if not pending:
                return
            await asyncio.sleep(0.05)
        raise TimeoutError("Diagnosis queue did not become idle")

    def export_incident(self, event_id: str) -> str:
        event = self.get_incident(event_id)
        diagnosis = event["diagnosis"] or {}
        lines = [f"# 故障复盘初稿：{event['service']}", "", f"- 事件：{event_id}", f"- 数据：{'演示数据' if event['is_demo'] else '接入数据'}",
                 f"- 状态：{event['status']}", f"- 环境 / 实例：{event['environment']} / {event['instance']}",
                 f"- 告警数量：{event['occurrences']}", f"- 用户影响：未知（尚未接入影响统计）", "", "## 智能体候选根因（待人工核实）", "", diagnosis.get("root_cause", "诊断尚未完成"),
                 "", "## 人工处置记录", "", event.get("resolution") or "尚未提交", "", "## 故障时间线", ""]
        lines.extend(f"- {item['created_at']} {item['action']}: {item['message']}" for item in event["timeline"])
        lines.extend(["", "## 处置建议", ""])
        lines.extend(f"- {step['title']}: {step['description']}" for step in diagnosis.get("steps", []))
        lines.extend(["", "## 知识引用", ""])
        lines.extend(f"- {item['id']}: {item['title']} — {item['excerpt']}" for item in diagnosis.get("knowledge", []))
        return "\n".join(lines)

    def merge_incidents(self, event_id: str, request: MergeInput) -> dict:
        with self._lock, self._db:
            target = self._get("incidents", event_id)
            donors = [self._get("incidents", item_id) for item_id in dict.fromkeys(request.incident_ids) if item_id != event_id]
            if target["status"] == "diagnosing" or any(item["status"] == "diagnosing" for item in donors):
                raise ValueError("Wait for running diagnoses to finish before merging")
            if any(item["is_demo"] != target["is_demo"] for item in donors):
                raise ValueError("Demo and real incidents cannot be merged")
            for donor in donors:
                for table in ("alerts", "timeline", "diagnoses"):
                    self._db.execute(f"UPDATE {table} SET incident_id = ? WHERE incident_id = ?", (event_id, donor["id"]))
                target["logs"] = (target["logs"] + "\n" + donor["logs"])[-MAX_CONTEXT_CHARS:]
                target["occurrences"] += donor["occurrences"]
                target["first_seen"] = min(target["first_seen"], donor["first_seen"])
                target["last_seen"] = max(target["last_seen"], donor["last_seen"])
                self._db.execute("DELETE FROM incidents WHERE id = ?", (donor["id"],))
            target.update(status="new", revision=target["revision"] + 1, needs_diagnosis=True, resolved_at=None)
            self._save_incident(target)
            self._timeline(event_id, "incidents_merged", "人工合并故障事件", {"incident_ids": request.incident_ids}, actor=request.operator)
            self._audit("incidents_merged", event_id, details=request.model_dump(), actor=request.operator, is_demo=target["is_demo"])
        return self.get_incident(event_id)

    def split_incident(self, event_id: str, request: SplitInput) -> dict:
        with self._lock, self._db:
            event = self._get("incidents", event_id)
            if event["status"] == "diagnosing":
                raise ValueError("Wait for the running diagnosis to finish before splitting")
            rows = self._db.execute("SELECT id, body FROM alerts WHERE incident_id = ?", (event_id,)).fetchall()
            chosen = [row for row in rows if row["id"] in request.alert_ids]
            if len(chosen) != len(set(request.alert_ids)) or len(chosen) == len(rows):
                raise ValueError("Select valid alerts while keeping at least one alert in the original incident")
            split = dict(event)
            split.update(id=str(uuid4()), aggregate_key=f"manual:{uuid4()}", occurrences=len(chosen), diagnosis=None,
                         logs="\n".join(json.loads(row["body"])["message"] for row in chosen)[-MAX_CONTEXT_CHARS:],
                         status="new", revision=1, needs_diagnosis=True, confirmed_at=None, resolved_at=None)
            for row in chosen:
                self._db.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (split["id"], row["id"]))
            event.update(occurrences=len(rows) - len(chosen), logs="\n".join(json.loads(row["body"])["message"] for row in rows if row not in chosen)[-MAX_CONTEXT_CHARS:],
                         status="new", revision=event["revision"] + 1, needs_diagnosis=True, resolved_at=None)
            self._save_incident(event)
            self._save_incident(split)
            self._timeline(event_id, "incident_split", "人工拆分原始告警", {"new_incident_id": split["id"], "alert_ids": request.alert_ids}, actor=request.operator)
            self._timeline(split["id"], "incident_created", "从现有故障事件拆分", {"original_incident_id": event_id}, actor=request.operator)
            self._audit("incident_split", event_id, details={"new_incident_id": split["id"], "alert_ids": request.alert_ids}, actor=request.operator, is_demo=event["is_demo"])
        return {"original": self.get_incident(event_id), "split": self.get_incident(split["id"])}


def create_ops_router(service: OperationsService) -> APIRouter:
    router = APIRouter(prefix="/api", tags=["operations"])

    def invoke(call, *args, **kwargs):
        try:
            return call(*args, **kwargs)
        except KeyError as exc:
            raise HTTPException(404, detail="Resource not found") from exc
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc)) from exc

    @router.get("/overview")
    def overview(is_demo: bool | None = None):
        return service.overview(is_demo)

    @router.get("/sources")
    def sources():
        return service.list_sources()

    @router.post("/sources", status_code=201)
    def add_source(payload: SourceCreate, request: Request):
        return invoke(service.create_source, payload, getattr(request.state, "operator", "operator"))

    @router.patch("/sources/{source_id}")
    def update_source(source_id: str, payload: SourcePatch, request: Request):
        return invoke(service.update_source, source_id, payload, getattr(request.state, "operator", "operator"))

    @router.delete("/sources/{source_id}")
    def delete_source(source_id: str, request: Request):
        return invoke(service.delete_source, source_id, getattr(request.state, "operator", "operator"))

    @router.post("/sources/{source_id}/scan-now")
    async def scan_source(source_id: str, request: Request):
        try:
            result = await service.scan_source(source_id)
            service.audit("source_scan_requested", "source", source_id, getattr(request.state, "operator", "operator"),
                          {"lines_read": result["lines_read"], "anomalies_detected": result["anomalies_detected"]})
            return result
        except KeyError as exc:
            raise HTTPException(404, detail="Source not found") from exc

    @router.get("/incidents")
    def incidents(status: str | None = None, severity: str | None = None, is_demo: bool | None = None, limit: int = Query(100, ge=1, le=1000)):
        return service.list_incidents(status, severity, is_demo, limit)

    @router.get("/incidents/{event_id}")
    def incident(event_id: str):
        return invoke(service.get_incident, event_id)

    @router.patch("/incidents/{event_id}")
    def update_incident(event_id: str, payload: IncidentPatch, request: Request):
        payload.operator = getattr(request.state, "operator", "operator")
        return invoke(service.update_incident, event_id, payload)

    @router.post("/incidents/{event_id}/followup")
    def followup(event_id: str, payload: FollowupInput, request: Request):
        payload.operator = getattr(request.state, "operator", "operator")
        return invoke(service.followup, event_id, payload)

    @router.post("/incidents/{event_id}/merge")
    def merge(event_id: str, payload: MergeInput, request: Request):
        payload.operator = getattr(request.state, "operator", "operator")
        return invoke(service.merge_incidents, event_id, payload)

    @router.post("/incidents/{event_id}/split")
    def split(event_id: str, payload: SplitInput, request: Request):
        payload.operator = getattr(request.state, "operator", "operator")
        return invoke(service.split_incident, event_id, payload)

    @router.post("/incidents/{event_id}/verify")
    async def verify(event_id: str, request: Request):
        try:
            return await service.verify_incident(event_id, getattr(request.state, "operator", "operator"))
        except KeyError as exc:
            raise HTTPException(404, detail="Incident not found") from exc

    @router.get("/incidents/{event_id}/export")
    def export(event_id: str):
        document = invoke(service.export_incident, event_id)
        return Response(document, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="incident-{event_id}.md"'})

    @router.get("/audit")
    def audit(limit: int = Query(100, ge=1, le=1000)):
        return service.audit(limit=limit)

    @router.post("/alerts/webhook", status_code=202)
    def webhook(payload: dict, request: Request):
        if len(_json(payload)) > 1_000_000:
            raise HTTPException(413, detail="Alert payload exceeds 1 MB")
        alerts = []
        try:
            if "alerts" in payload:
                if not isinstance(payload["alerts"], list) or len(payload["alerts"]) > 100:
                    raise ValueError("alerts must contain at most 100 alerts")
                for raw in payload["alerts"]:
                    labels = raw.get("labels", {})
                    annotations = raw.get("annotations", {})
                    level = labels.get("severity", "error").lower()
                    level = {"page": "critical", "warn": "warning", "fatal": "critical"}.get(level, level)
                    alert = AlertInput(service=labels.get("service", labels.get("job", "unknown")), environment=labels.get("environment", labels.get("env", "unknown")),
                                       instance=labels.get("instance", labels.get("pod", "unknown")), source=labels.get("source", "auto"), severity=level if level in _SEVERITY else "error",
                                       message="\n".join(filter(None, [labels.get("alertname"), annotations.get("summary"), annotations.get("description")])),
                                       status=raw.get("status", payload.get("status", "firing")), labels=labels, annotations=annotations,
                                       starts_at=raw.get("startsAt"), ends_at=raw.get("endsAt"), generator_url=raw.get("generatorURL"), fingerprint=raw.get("fingerprint"), is_demo=payload.get("is_demo", False))
                    alerts.append(alert)
            else:
                alerts.append(AlertInput.model_validate(payload))
        except (ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(422, detail=str(exc)) from exc
        events = service.ingest_alerts(alerts, getattr(request.state, "operator", "alert-platform"))
        return {"accepted": True, "incident_ids": list(dict.fromkeys(event["id"] for event in events)), "received_alerts": len(payload.get("alerts", [payload]))}

    return router
