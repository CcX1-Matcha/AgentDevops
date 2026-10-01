"""Approved playbooks use fixed executors; diagnosis text is never executable."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .parser import parse_logs
from .security import require_permission


_LEVELS = {"info": 0, "warning": 1, "error": 2, "critical": 3}
_ACTIONS = Literal["restart_stateless_workload", "switch_standby", "cleanup_managed_temp"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class Playbook(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,79}$")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1000)
    action: _ACTIONS
    source: Literal["server", "nginx", "docker", "kubernetes"]
    service: str = Field(min_length=1, max_length=120)
    environment: str = Field(min_length=1, max_length=120)
    instance: str = Field(min_length=1, max_length=200)
    failure_types: list[str] = Field(min_length=1, max_length=20)
    risk: Literal["low"] = "low"
    approved_by: str = Field(min_length=1, max_length=120)
    rollback: str = Field(min_length=1, max_length=2000)
    endpoint_url: str
    verify_url: str
    token_env: str | None = Field(None, pattern=r"^[A-Z][A-Z0-9_]{0,99}$")
    parameters: dict = Field(default_factory=dict)
    timeout_seconds: float = Field(10, ge=1, le=30)

    @field_validator("service", "environment", "instance", "approved_by", "rollback")
    @classmethod
    def exact_target(cls, value: str) -> str:
        if not value.strip() or value.strip().lower() in {"unknown", "*", "null"}:
            raise ValueError("Playbooks need explicit targets and an accountable reviewer")
        return value.strip()

    @field_validator("failure_types")
    @classmethod
    def specific_failure(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[a-z][a-z0-9_]{1,79}", value) or value in {"normal", "unknown_error", "unknown_critical"} for value in values):
            raise ValueError("Unclassified errors cannot select a playbook")
        return list(dict.fromkeys(values))

    @field_validator("endpoint_url", "verify_url")
    @classmethod
    def fixed_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Executor URLs must not contain credentials, queries or fragments")
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("Executors require HTTPS except for local loopback development")
        return value


class PlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    playbook_id: str = Field(min_length=1, max_length=80)


class ApprovalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]


class RemediationService:
    def __init__(self, operations, config_path: str | Path | None = None, demo_runner=None, transport=None):
        self.operations = operations
        self.demo_runner = demo_runner
        self.transport = transport
        self.playbooks: dict[str, Playbook] = {}
        self.config_error: str | None = None
        if config_path:
            try:
                records = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
                if not isinstance(records, list) or len(records) > 100:
                    raise ValueError("Expected an array of at most 100 playbooks")
                validated = [Playbook.model_validate(record) for record in records]
                if len({book.id for book in validated}) != len(validated) or any(book.id == "demo-cache-recovery" for book in validated):
                    raise ValueError("Duplicate or reserved playbook ID")
                self.playbooks = {book.id: book for book in validated}
            except (OSError, ValueError):
                # Do not expose validation inputs, which can contain connector secrets.
                self.config_error = "白名单剧本配置无效，真实执行已关闭，请检查服务端配置。"
        with operations._lock, operations._db:
            operations._db.executescript("""
                CREATE TABLE IF NOT EXISTS remediation_plans (
                    id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, body TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS remediation_incident ON remediation_plans(incident_id);
            """)
            for row in operations._db.execute("SELECT id, body FROM remediation_plans").fetchall():
                plan = json.loads(row["body"])
                if plan["status"] == "running":
                    plan.update(status="unknown", result={"status": "unknown", "message": "执行期间进程退出，需人工核对执行器结果；不会自动重试。"})
                    self._save(plan)
                    self._record(plan, "remediation_interrupted", plan["result"]["message"], actor="agent")

    def _save(self, plan: dict) -> None:
        self.operations._db.execute("INSERT OR REPLACE INTO remediation_plans VALUES (?, ?, ?)",
                                    (plan["id"], plan["incident_id"], _dump(plan)))

    def _get(self, plan_id: str) -> dict:
        row = self.operations._db.execute("SELECT body FROM remediation_plans WHERE id = ?", (plan_id,)).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return json.loads(row["body"])

    def _record(self, plan: dict, action: str, message: str, actor: str):
        self.operations._timeline(plan["incident_id"], action, message,
                                  {"plan_id": plan["id"], "status": plan["status"], "mode": plan["mode"]}, actor=actor)
        self.operations._audit(action, plan["incident_id"], details={"plan_id": plan["id"], "playbook_id": plan["playbook_id"],
                               "status": plan["status"], "target": plan["target"], "mode": plan["mode"]}, actor=actor,
                               is_demo=plan["mode"] == "demo")

    @staticmethod
    def _signature(event: dict) -> str:
        return hashlib.sha256(_dump([event["revision"], event["diagnosis"]["id"], event["severity"],
            event["failure_type"], event["service"], event["environment"], event["instance"], event["is_demo"]]).encode()).hexdigest()

    def _eligibility(self, event: dict) -> tuple[bool, str]:
        diagnosis = event.get("diagnosis")
        if event["status"] not in {"awaiting_confirmation", "acknowledged"} or event.get("needs_diagnosis") or not diagnosis or not diagnosis.get("id"):
            return False, "需要完成当前事件的诊断，且事件尚未解决。"
        if diagnosis.get("failure_type") != event["failure_type"]:
            return False, "告警类型与当前诊断不一致，请人工复核。"
        levels = [event["severity"], diagnosis.get("severity", "critical")]
        levels.extend(item.severity for item in parse_logs(event.get("logs", ""), event["source"]))
        if max(_LEVELS.get(level, 3) for level in levels) > 1:
            return False, "错误或严重等级事件必须由工程师手动处置。"
        if any(event.get(key, "unknown").lower() in {"unknown", "", "null", "*"} for key in ("service", "environment", "instance")):
            return False, "缺少明确的服务、环境或实例，不能执行。"
        return True, "仅可执行已审核、匹配固定目标的白名单剧本；需要高级工程师确认。"

    def _books(self, event: dict) -> list[dict]:
        if event["is_demo"]:
            if self.demo_runner and event["service"] == "demo-warning" and event["environment"] == "demo" and event["instance"] == "local-demo" and event["source"] == "server" and event["failure_type"] == "managed_cache_pressure":
                return [dict(id="demo-cache-recovery", name="模拟临时缓存恢复", description="在演示日志中写入恢复记录，验证审批与执行审计流程。",
                    action="cleanup_managed_temp", mode="demo", risk="low", requires_approval=True,
                    rollback="模拟剧本不改动真实服务，无需回滚。", approved_by="built-in-demo")]
            return []
        return [dict(id=book.id, name=book.name, description=book.description, action=book.action, mode="http", risk=book.risk,
                     rollback=book.rollback, approved_by=book.approved_by, requires_approval=True)
                for book in self.playbooks.values() if all(getattr(book, key) == event[key] for key in ("source", "service", "environment", "instance"))
                and event["failure_type"] in book.failure_types]

    def describe(self, event_id: str) -> dict:
        with self.operations._lock:
            event = self.operations._get("incidents", event_id)
            eligible, reason = self._eligibility(event)
            books = self._books(event)
            if eligible and not books:
                eligible, reason = False, self.config_error or "没有匹配该事件和固定目标的已审核白名单剧本。"
            plans = [json.loads(row["body"]) for row in self.operations._db.execute(
                "SELECT body FROM remediation_plans WHERE incident_id = ? ORDER BY rowid DESC", (event_id,))]
            if eligible and any(plan["status"] not in {"pending", "stale"} for plan in plans):
                eligible, reason = False, "该事件已有执行记录，请核对执行与恢复结果，不能重复执行。"
            return {"eligible": eligible, "reason": reason, "playbooks": books if eligible else [], "plans": plans}

    def create_plan(self, event_id: str, playbook_id: str, actor: str) -> dict:
        with self.operations._lock, self.operations._db:
            event = self.operations._get("incidents", event_id)
            eligible, reason = self._eligibility(event)
            if not eligible:
                raise ValueError(reason)
            selected = next((book for book in self._books(event) if book["id"] == playbook_id), None)
            if selected is None:
                raise ValueError("白名单剧本不匹配当前事件。")
            signature = self._signature(event)
            previous = [json.loads(row["body"]) for row in self.operations._db.execute(
                "SELECT body FROM remediation_plans WHERE incident_id = ?", (event_id,))]
            if any(plan["status"] not in {"pending", "stale"} for plan in previous):
                raise ValueError("该事件已有执行记录，请人工核对结果，不能重复执行。")
            for plan in previous:
                if plan["status"] == "pending" and plan["event_signature"] == signature and plan["playbook_id"] == playbook_id and datetime.fromisoformat(plan["expires_at"]) > _now():
                    return plan
            book_hash = hashlib.sha256(_dump(self.playbooks[playbook_id].model_dump()).encode()).hexdigest() if selected["mode"] == "http" else "built-in-demo-v1"
            plan = dict(id=str(uuid4()), incident_id=event_id, playbook_id=playbook_id, name=selected["name"],
                        description=selected["description"], action=selected["action"], mode=selected["mode"], risk="low",
                        rollback=selected["rollback"], approved_by=selected["approved_by"], created_by=actor, executed_by=None,
                        created_at=_now().isoformat(), expires_at=(_now() + timedelta(minutes=10)).isoformat(),
                        status="pending", target={key: event[key] for key in ("service", "environment", "instance")},
                        severity=event["severity"], failure_type=event["failure_type"], diagnosis_id=event["diagnosis"]["id"],
                        event_signature=signature, executor_config_hash=book_hash, result=None, verification=None)
            self._save(plan)
            self._record(plan, "remediation_plan_created", "生成白名单处置计划，等待高级工程师确认。", actor)
            return plan

    async def execute(self, plan_id: str, actor: str) -> dict:
        with self.operations._lock, self.operations._db:
            plan = self._get(plan_id)
            if plan["status"] != "pending":
                raise ValueError("此计划已提交或失效，不能再次执行。")
            try:
                event = self.operations._get("incidents", plan["incident_id"])
            except KeyError:
                event = None
            eligible = event and self._eligibility(event)[0]
            book = self.playbooks.get(plan["playbook_id"])
            current_hash = hashlib.sha256(_dump(book.model_dump()).encode()).hexdigest() if book else "built-in-demo-v1"
            if not eligible or datetime.fromisoformat(plan["expires_at"]) <= _now() or self._signature(event) != plan["event_signature"] or current_hash != plan["executor_config_hash"] or not any(item["id"] == plan["playbook_id"] for item in self._books(event)):
                plan.update(status="stale", result={"status": "rejected", "message": "事件、诊断、剧本或有效期已变化，请重新生成计划。"})
                self._save(plan)
                self._record(plan, "remediation_rejected", plan["result"]["message"], actor)
                rejected = True
            else:
                rejected = False
                for row in self.operations._db.execute("SELECT body FROM remediation_plans").fetchall():
                    existing = json.loads(row["body"])
                    if existing["id"] == plan_id or existing["target"] != plan["target"] or existing["mode"] != plan["mode"]:
                        continue
                    if (existing["incident_id"] == plan["incident_id"] and existing["status"] not in {"pending", "stale"}) or existing["status"] in {"running", "unknown"} or (existing.get("started_at") and datetime.fromisoformat(existing["started_at"]) > _now() - timedelta(minutes=10)):
                        raise ValueError("该目标存在正在执行、结果未知或最近执行的计划，请人工核对。")
                if plan["mode"] == "http" and book.token_env and not os.getenv(book.token_env):
                    raise ValueError("执行器认证尚未配置，未发送任何操作。")
                plan.update(status="running", executed_by=actor, started_at=_now().isoformat())
                self._save(plan)
                self._record(plan, "remediation_started", "高级工程师已确认，开始白名单执行。", actor)
        if rejected:
            raise ValueError(plan["result"]["message"])
        try:
            if plan["mode"] == "demo":
                await self.operations._run_in_thread(self.demo_runner, event)
                status = "simulated"
                result = {"status": "simulated", "message": "已写入模拟恢复日志，未操作真实服务。"}
                verification = {"healthy": None, "checked_at": _now().isoformat(), "note": "演示流程完成；不能作为真实业务恢复证据。"}
            else:
                status, result, verification = await self.operations._run_in_thread(self._http_execute, book, plan)
        except Exception:
            status, result, verification = "unknown", {"status": "unknown", "message": "执行结果未知，需人工核对；不会自动重试。"}, None
        with self.operations._lock, self.operations._db:
            plan.update(status=status, result=result, verification=verification, finished_at=_now().isoformat())
            self._save(plan)
            self._record(plan, "remediation_completed", result["message"], actor)
            try:
                current = self.operations._get("incidents", plan["incident_id"])
                current["last_remediation"] = {key: plan[key] for key in ("id", "status", "executed_by", "verification", "finished_at")}
                self.operations._save_incident(current)
            except KeyError:
                pass
        return plan

    def _http_execute(self, book: Playbook, plan: dict) -> tuple[str, dict, dict | None]:
        headers = {"Idempotency-Key": plan["id"]}
        if book.token_env:
            headers["Authorization"] = f"Bearer {os.environ[book.token_env]}"
        payload = {"action": book.action, "target": plan["target"], "parameters": book.parameters,
                   "incident_id": plan["incident_id"], "plan_id": plan["id"]}
        with httpx.Client(timeout=book.timeout_seconds, follow_redirects=False, trust_env=False, transport=self.transport) as client:
            try:
                data = self._read_response(client, "POST", book.endpoint_url, json=payload, headers=headers)
                if not isinstance(data, dict) or data.get("status") not in {"succeeded", "failed"}:
                    raise ValueError("Executor must return a terminal status")
            except (httpx.HTTPError, ValueError):
                return "unknown", {"status": "unknown", "message": "执行器超时或结果不明确，请核对远端操作；不会自动重试。"}, None
            if data["status"] == "failed":
                return "failed", {"status": "failed", "message": "执行器报告操作失败，请人工检查。"}, None
            result = {"status": "succeeded", "message": "白名单操作已完成，恢复核查仍需人工确认。"}
            try:
                observed = self._read_response(client, "GET", book.verify_url, params={"plan_id": plan["id"], **plan["target"]}, headers=headers)
                if not isinstance(observed, dict) or type(observed.get("healthy")) is not bool or observed.get("plan_id") != plan["id"]:
                    raise ValueError("Verification must identify this plan and return a boolean health state")
                if not isinstance(observed.get("checked_at"), str):
                    raise ValueError("Verification needs a timestamp")
                checked_at = datetime.fromisoformat(observed["checked_at"].replace("Z", "+00:00"))
                if checked_at.tzinfo is None or checked_at < datetime.fromisoformat(plan["started_at"]) or not -10 <= (_now() - checked_at).total_seconds() <= 60:
                    raise ValueError("Verification observation is stale")
                verification = {"healthy": observed["healthy"], "checked_at": checked_at.isoformat(), "plan_id": plan["id"],
                                "note": "固定核查接口报告健康，需工程师确认业务恢复。" if observed["healthy"] else "核查接口仍报告异常，请人工升级处置。"}
                return ("succeeded" if observed["healthy"] else "verification_failed"), result, verification
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                return "succeeded", result, {"healthy": None, "checked_at": _now().isoformat(), "note": "操作已完成，恢复核查数据缺失或无效，业务健康未知。"}

    @staticmethod
    def _read_response(client: httpx.Client, method: str, url: str, **kwargs):
        with client.stream(method, url, **kwargs) as response:
            if not 200 <= response.status_code < 300:
                raise ValueError("Executor response was not accepted")
            content = bytearray()
            for chunk in response.iter_bytes(chunk_size=8192):
                if len(content) + len(chunk) > 65_536:
                    raise ValueError("Executor response exceeded the size limit")
                content.extend(chunk)
            return json.loads(content)


def create_remediation_router(service: RemediationService) -> APIRouter:
    router = APIRouter(prefix="/api", tags=["remediation"])

    def invoke(call, *args):
        try:
            return call(*args)
        except KeyError as exc:
            raise HTTPException(404, detail="事件或处置计划不存在。") from exc
        except ValueError as exc:
            raise HTTPException(409, detail=str(exc)) from exc

    @router.get("/incidents/{event_id}/remediation")
    def describe(event_id: str):
        return invoke(service.describe, event_id)

    @router.post("/incidents/{event_id}/remediation/plans", status_code=201)
    def create(event_id: str, payload: PlanInput, request: Request):
        require_permission(request, "remediation:execute")
        return invoke(service.create_plan, event_id, payload.playbook_id, request.state.operator)

    @router.post("/remediation/plans/{plan_id}/execute")
    async def execute(plan_id: str, payload: ApprovalInput, request: Request):
        require_permission(request, "remediation:execute")
        try:
            return await service.execute(plan_id, request.state.operator)
        except KeyError as exc:
            raise HTTPException(404, detail="处置计划不存在。") from exc
        except ValueError as exc:
            raise HTTPException(409, detail=str(exc)) from exc

    return router
