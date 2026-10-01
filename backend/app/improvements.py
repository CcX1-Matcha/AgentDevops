"""Evidence-limited incident correlation and durable human learning signals."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, StrictBool

from .knowledge_api import KnowledgeRepository, RunbookDocument
from .operations import OperationsService


_UNKNOWN = {"", "unknown", "unknown_error", "n/a", "none", "null", "-", "未知", "未配置"}
_SEVERITY = {"info": 0, "warning": 1, "error": 2, "critical": 3}
_FEEDBACK_LABEL = "人工建议有用率，不代表根因准确率或执行成功率。"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _known(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    return text if text not in _UNKNOWN else None


def _stamp(value: Any) -> datetime | None:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _stats(items: list[dict]) -> dict:
    useful = sum(bool(item["useful"]) for item in items)
    count = len(items)
    return {"feedback_count": count, "useful_count": useful,
            "acceptance_rate": round(useful / count, 4) if count else None,
            "metric_label": _FEEDBACK_LABEL}


class FeedbackInput(BaseModel):
    useful: StrictBool
    comment: str = Field("", max_length=2000)


class ImprovementService:
    def __init__(self, operations: OperationsService, repository: KnowledgeRepository):
        self.operations = operations
        self.repository = repository
        with operations._lock, operations._db:
            operations._db.executescript("""
                CREATE TABLE IF NOT EXISTS incident_feedback (
                    diagnosis_id TEXT NOT NULL, actor TEXT NOT NULL, incident_id TEXT NOT NULL,
                    body TEXT NOT NULL, PRIMARY KEY (diagnosis_id, actor));
                CREATE INDEX IF NOT EXISTS feedback_incident ON incident_feedback(incident_id);
                CREATE TABLE IF NOT EXISTS historical_cases (
                    incident_id TEXT PRIMARY KEY, snapshot_hash TEXT NOT NULL, body TEXT NOT NULL);
            """)

    def campaigns(self, is_demo: bool | None = None, window_seconds: int = 600) -> dict:
        events = self.operations.list_incidents(is_demo=is_demo, limit=100_000)["items"]
        # Index strong labels first; temporal adjacency alone never joins events.
        keyed: dict[tuple, list[tuple[datetime, datetime, dict]]] = defaultdict(list)
        eligible: dict[str, dict] = {}
        for event in events:
            env = _known(event.get("environment"))
            first, last = _stamp(event.get("first_seen")), _stamp(event.get("last_seen"))
            if env is None or first is None or last is None:
                continue
            scope = (bool(event.get("is_demo")), env)
            instance = _known(event.get("instance"))
            service, failure = _known(event.get("service")), _known(event.get("failure_type"))
            keys = []
            if instance:
                keys.append((*scope, "shared_instance", instance))
            if service and failure:
                keys.append((*scope, "same_service_failure", service, failure))
            if keys:
                eligible[event["id"]] = event
                for key in keys:
                    keyed[key].append((first, max(first, last), event))

        parent = {event_id: event_id for event_id in eligible}
        evidence: list[dict] = []

        def find(value: str) -> str:
            while parent[value] != value:
                parent[value] = parent[parent[value]]
                value = parent[value]
            return value

        def join(left: str, right: str) -> None:
            left, right = find(left), find(right)
            if left != right:
                parent[max(left, right)] = min(left, right)

        for key, bucket in keyed.items():
            bucket.sort(key=lambda item: (item[0], item[2]["id"]))
            anchor = None
            for first, last, event in bucket:
                if anchor is not None and (first - anchor[1]).total_seconds() <= window_seconds:
                    previous = anchor[2]
                    join(previous["id"], event["id"])
                    evidence.append({"incident_ids": [previous["id"], event["id"]], "relation": key[2],
                                     "detail": f"环境 {event['environment']}；" +
                                               (f"共同实例 {event['instance']}" if key[2] == "shared_instance" else
                                                f"同服务 {event['service']}、同故障类型 {event['failure_type']}"),
                                     "time_gap_seconds": max(0, round((first - anchor[1]).total_seconds(), 2))})
                    if last > anchor[1]:
                        anchor = (first, last, event)
                else:
                    anchor = (first, last, event)

        grouped: dict[str, list[dict]] = defaultdict(list)
        for event_id, event in eligible.items():
            grouped[find(event_id)].append(event)
        group_evidence: dict[str, list[dict]] = defaultdict(list)
        for item in evidence:
            group_evidence[find(item["incident_ids"][0])].append(item)
        items = []
        for group_id, members in grouped.items():
            if len(members) < 2:
                continue
            ids = sorted(item["id"] for item in members)
            services = sorted({str(item["service"]) for item in members if _known(item.get("service"))})
            instances = sorted({str(item["instance"]) for item in members if _known(item.get("instance"))})
            failure_types = sorted({str(item["failure_type"]) for item in members if _known(item.get("failure_type"))})
            items.append({"id": "campaign-" + hashlib.sha256(_json(ids).encode()).hexdigest()[:16],
                          "incident_ids": ids, "services": services, "instances": instances,
                          "failure_types": failure_types, "environment": members[0]["environment"],
                          "is_demo": bool(members[0].get("is_demo")),
                          "first_seen": min(item["first_seen"] for item in members),
                          "last_seen": max(item["last_seen"] for item in members),
                          "severity": max((item["severity"] for item in members), key=lambda x: _SEVERITY.get(x, 0)),
                          "summary": f"{len(members)} 个事件存在时间与标签关联，统一根因待确认。",
                          "evidence": group_evidence[group_id],
                          "root_cause": None})
        items.sort(key=lambda item: item["last_seen"], reverse=True)
        return {"items": items, "total": len(items), "window_seconds": window_seconds,
                "boundary": "关联分组是候选排查线索，不能据此认定共同根因；未知环境不参与关联。"}

    @staticmethod
    def _latest_diagnosis(incident: dict) -> tuple[str | None, dict | None]:
        history = incident.get("diagnosis_history", [])
        if history:
            latest = history[-1]
            return latest.get("id"), latest.get("diagnosis")
        diagnosis = incident.get("diagnosis")
        return (diagnosis.get("id"), diagnosis) if diagnosis else (None, None)

    def learning(self, incident_id: str, actor: str) -> dict:
        with self.operations._lock:
            incident = self.operations.get_incident(incident_id)
            diagnosis_id, _ = self._latest_diagnosis(incident)
            feedback = [json.loads(row["body"]) for row in self.operations._db.execute(
                "SELECT body FROM incident_feedback WHERE incident_id = ? AND diagnosis_id = ? ORDER BY actor",
                (incident_id, diagnosis_id))]
            case = self.operations._db.execute("SELECT body FROM historical_cases WHERE incident_id = ?", (incident_id,)).fetchone()
        return {"diagnosis_id": diagnosis_id, "feedback": feedback,
                "current_feedback": next((item for item in feedback if item["actor"] == actor), None),
                "stats": _stats(feedback), "case": json.loads(case["body"]) if case else None}

    def feedback(self, incident_id: str, payload: FeedbackInput | dict, actor: str) -> dict:
        payload = payload if isinstance(payload, FeedbackInput) else FeedbackInput.model_validate(payload)
        with self.operations._lock, self.operations._db:
            incident = self.operations.get_incident(incident_id)
            diagnosis_id, diagnosis = self._latest_diagnosis(incident)
            if not diagnosis_id or not diagnosis:
                raise ValueError("尚无已完成诊断，不能提交建议反馈。")
            existing = self.operations._db.execute(
                "SELECT body FROM incident_feedback WHERE diagnosis_id = ? AND actor = ?", (diagnosis_id, actor)).fetchone()
            created_at = json.loads(existing["body"])["created_at"] if existing else _now()
            item = {"diagnosis_id": diagnosis_id, "incident_id": incident_id, "actor": actor,
                    "useful": payload.useful, "comment": payload.comment.strip(), "created_at": created_at,
                    "updated_at": _now(), "is_demo": bool(incident.get("is_demo")),
                    "knowledge_ids": sorted({str(item["id"]) for item in diagnosis.get("knowledge", []) if item.get("id")})}
            self.operations._db.execute("INSERT OR REPLACE INTO incident_feedback VALUES (?, ?, ?, ?)",
                                        (diagnosis_id, actor, incident_id, _json(item)))
            self.operations._audit("diagnosis_feedback", incident_id, actor=actor, is_demo=item["is_demo"],
                                   details={"diagnosis_id": diagnosis_id, "useful": payload.useful, "updated": bool(existing)})
        return self.learning(incident_id, actor)

    def metrics(self) -> dict:
        with self.operations._lock:
            feedback = [json.loads(row["body"]) for row in self.operations._db.execute("SELECT body FROM incident_feedback")]
        feedback = [item for item in feedback if not item["is_demo"]]
        by_knowledge: dict[str, list[dict]] = defaultdict(list)
        for item in feedback:
            for knowledge_id in item["knowledge_ids"]:
                by_knowledge[knowledge_id].append(item)
        runbooks = []
        for knowledge_id, items in sorted(by_knowledge.items()):
            stats = _stats(items)
            stats.pop("metric_label")
            runbooks.append({"id": knowledge_id, **stats,
                             "review_required": len(items) >= 3 and (len(items) - stats["useful_count"]) / len(items) > 0.5})
        return {**_stats(feedback), "runbooks": runbooks}

    def on_resolved(self, incident: dict, actor: str) -> dict | None:
        if incident.get("status") != "resolved" or incident.get("is_demo") or not str(incident.get("resolution") or "").strip():
            return None
        incident_id = incident["id"]
        with self.operations._lock, self.operations._db:
            current = self.operations.get_incident(incident_id)
            if current.get("status") != "resolved" or current.get("is_demo") or not str(current.get("resolution") or "").strip():
                return None
            diagnosis_id, diagnosis = self._latest_diagnosis(current)
            diagnosis = diagnosis or {}
            verification = next((item.get("data") or {} for item in reversed(current.get("timeline", []))
                                 if item.get("action") == "recovery_verified"), {})
            checked_at, last_seen = _stamp(verification.get("checked_at")), _stamp(current.get("last_seen"))
            resolved_at = _stamp(current.get("resolved_at"))
            if verification and (checked_at is None or (last_seen and checked_at < last_seen) or
                                 (resolved_at and checked_at > resolved_at)):
                verification = {"note": "已有核查记录不属于最新告警后的恢复核查，不能作为本次恢复证据。"}
            verification = {"healthy": verification.get("healthy") if isinstance(verification.get("healthy"), bool) else None,
                            "log_check_passed": verification.get("log_check_passed") if isinstance(verification.get("log_check_passed"), bool) else None,
                            "checked_at": verification.get("checked_at"),
                            "note": verification.get("note") or "尚未完成业务恢复核查，人工已标记解决。"}
            snapshot = {"diagnosis_id": diagnosis_id, "resolution": current["resolution"],
                        "resolved_at": current.get("resolved_at"), "verification": verification}
            snapshot_hash = hashlib.sha256(_json(snapshot).encode()).hexdigest()
            existing = self.operations._db.execute("SELECT * FROM historical_cases WHERE incident_id = ?", (incident_id,)).fetchone()
            if existing and existing["snapshot_hash"] == snapshot_hash:
                return json.loads(existing["body"])
            symptoms = [str(item.get("message", "")).strip()[:4900] for item in current.get("original_alerts", [])[:3]
                        if str(item.get("message", "")).strip()]
            case_id = f"case-{incident_id}"
            root_cause = str(diagnosis.get("root_cause") or "尚无根因诊断。")
            source = current.get("source")
            if source not in {"server", "nginx", "docker", "kubernetes"}:
                source = diagnosis.get("source")
            case = {"id": case_id, "incident_id": incident_id, "diagnosis_id": diagnosis_id,
                    "title": f"历史案例：{current.get('title', incident_id)}"[:300],
                    "source": source, "service": current.get("service"), "environment": current.get("environment"),
                    "instance": current.get("instance"), "failure_type": current.get("failure_type"),
                    "symptoms": symptoms, "root_cause": root_cause, "root_cause_confirmed": diagnosis.get("confirmed") is True,
                    "resolution": current["resolution"], "result": {"operator_status": "resolved", **verification},
                    "resolved_at": current.get("resolved_at"), "actor": actor, "trust_level": "personal",
                    "created_at": json.loads(existing["body"])["created_at"] if existing else _now(), "updated_at": _now(),
                    "knowledge_id": case_id if source in {"server", "nginx", "docker", "kubernetes"} else None}
            if case["knowledge_id"]:
                status = "已确认根因" if case["root_cause_confirmed"] else "诊断候选根因，未经核实"
                health = {True: "业务恢复核查通过", False: "业务恢复核查未通过", None: "业务恢复状态未知"}[verification["healthy"]]
                resolution = str(current["resolution"])
                steps = ["人工处置记录（待知识复核）：" + resolution[start:start + 4900]
                         for start in range(0, len(resolution), 4900)]
                steps.append(f"处置结果：人工标记解决；{health}。核查记录：{verification['note']}"[:5000])
                document = RunbookDocument(id=case_id, title=case["title"], source=source,
                                           root_cause=f"{status}：{root_cause}"[:20000], steps=steps,
                                           symptoms=symptoms, tags=["historical_case", f"service={case['service']}", f"environment={case['environment']}"],
                                           failure_types=[case["failure_type"]] if case["failure_type"] else [],
                                           source_urls=[f"/api/incidents/{incident_id}"], trust_level="personal")
                self.repository.import_documents([document])
                self.operations.agent.store = self.repository.store
                llm_agent = getattr(self.operations.agent, "_llm_agent", None)
                if llm_agent is not None:
                    llm_agent.store = self.repository.store
            self.operations._db.execute("INSERT OR REPLACE INTO historical_cases VALUES (?, ?, ?)",
                                        (incident_id, snapshot_hash, _json(case)))
            self.operations._audit("historical_case_saved", incident_id, actor=actor,
                                   details={"case_id": case_id, "knowledge_id": case["knowledge_id"], "trust_level": "personal",
                                            "healthy": verification["healthy"]})
            return case


def create_improvement_router(service: ImprovementService) -> APIRouter:
    router = APIRouter(prefix="/api", tags=["learning"])

    @router.get("/campaigns")
    def campaigns(is_demo: bool | None = None, window_seconds: int = Query(600, ge=30, le=3600)):
        return service.campaigns(is_demo, window_seconds)

    @router.get("/learning/metrics")
    def metrics():
        return service.metrics()

    @router.get("/incidents/{incident_id}/learning")
    def learning(incident_id: str, request: Request):
        try:
            return service.learning(incident_id, getattr(request.state, "operator", "operator"))
        except KeyError as exc:
            raise HTTPException(404, detail="Incident not found") from exc

    @router.post("/incidents/{incident_id}/feedback")
    def feedback(incident_id: str, payload: FeedbackInput, request: Request):
        from .security import require_permission
        require_permission(request, "incident:write")
        try:
            return service.feedback(incident_id, payload, getattr(request.state, "operator", "operator"))
        except KeyError as exc:
            raise HTTPException(404, detail="Incident not found") from exc
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc)) from exc

    return router
