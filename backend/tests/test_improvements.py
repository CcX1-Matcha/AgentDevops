"""Correlation never proves causation; learning preserves human and recovery evidence."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.agent import ReActAgent
from app.improvements import FeedbackInput, ImprovementService, create_improvement_router
from app.knowledge_api import KnowledgeRepository
from app.operations import OperationsService
from app.ops_models import IncidentPatch


ERROR = "connect() failed (111: Connection refused) while connecting to upstream"


def service_at(tmp_path):
    repository = KnowledgeRepository(tmp_path / "knowledge")
    operations = OperationsService(tmp_path / "operations.sqlite3", ReActAgent(store=repository.store))
    return operations, repository, ImprovementService(operations, repository)


def event_at(operations, **kwargs):
    return operations.ingest_alert({"service": "orders", "environment": "prod", "instance": "node-1",
                                    "source": "nginx", "message": ERROR, **kwargs})


def diagnose_pending(operations):
    async def scenario():
        while event := operations._claim_job():
            await operations._diagnose_event(event)
    asyncio.run(scenario())


def timestamp_event(operations, incident_id, minutes_ago):
    stamp = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    with operations._lock, operations._db:
        event = operations._get("incidents", incident_id)
        event.update(first_seen=stamp, last_seen=stamp)
        operations._save_incident(event)


def test_strong_labels_group_candidates_without_claiming_root_cause(tmp_path):
    operations, _, learning = service_at(tmp_path)
    first = event_at(operations, instance="node-1")
    second = event_at(operations, instance="node-2", severity="critical")
    # A shared instance can link differing failures without inventing a unified root cause.
    third = event_at(operations, service="payments", instance="node-1", message="No space left on device")
    group = learning.campaigns()["items"][0]
    assert set(group["incident_ids"]) == {first["id"], second["id"], third["id"]}
    assert group["root_cause"] is None
    assert "待确认" in group["summary"]
    assert group["severity"] == "critical"
    assert {item["relation"] for item in group["evidence"]} == {"shared_instance", "same_service_failure"}
    assert learning.campaigns()["items"][0]["id"] == group["id"]


def test_campaigns_never_connect_demo_environments_unknown_or_time_only(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event_at(operations)
    event_at(operations, environment="staging")
    event_at(operations, is_demo=True)
    event_at(operations, environment="unknown", service="foo")
    event_at(operations, environment="unknown", service="bar")
    event_at(operations, environment="test", service="unknown", instance="unknown")
    event_at(operations, environment="test", service="", instance="")
    event_at(operations, service="other", instance="node-2", message="unclassified alert")
    assert learning.campaigns()["total"] == 0


def test_unknown_failure_is_not_a_shared_service_link(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event_at(operations, instance="node-1", message="unclassified alert")
    event_at(operations, instance="node-2", message="another unclassified alert")
    assert learning.campaigns()["total"] == 0


def test_campaign_window_is_dynamic_and_filters_demo(tmp_path):
    operations, _, learning = service_at(tmp_path)
    first = event_at(operations)
    second = event_at(operations, instance="node-2")
    timestamp_event(operations, first["id"], 30)
    assert learning.campaigns(window_seconds=600)["total"] == 0
    timestamp_event(operations, first["id"], 4)
    assert learning.campaigns(window_seconds=600)["total"] == 1
    assert learning.campaigns(window_seconds=30)["total"] == 0
    event_at(operations, is_demo=True, instance="demo-1")
    event_at(operations, is_demo=True, instance="demo-2")
    assert learning.campaigns(is_demo=False)["total"] == 1
    assert learning.campaigns(is_demo=True)["total"] == 1
    assert second["id"] in learning.campaigns(is_demo=False)["items"][0]["incident_ids"]


def test_feedback_upserts_actor_diagnosis_and_is_audited(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event = event_at(operations)
    with pytest.raises(ValueError, match="已完成诊断"):
        learning.feedback(event["id"], {"useful": True}, "alice")
    diagnose_pending(operations)
    diagnosis_id = operations.get_incident(event["id"])["diagnosis_history"][-1]["id"]
    first = learning.feedback(event["id"], {"useful": True, "comment": "有帮助"}, "alice")
    assert first["current_feedback"]["diagnosis_id"] == diagnosis_id
    assert first["stats"]["acceptance_rate"] == 1
    second = learning.feedback(event["id"], {"useful": False}, "alice")
    assert second["stats"]["feedback_count"] == 1
    assert second["stats"]["acceptance_rate"] == 0
    learning.feedback(event["id"], {"useful": True}, "bob")
    assert learning.metrics()["feedback_count"] == 2
    assert learning.metrics()["acceptance_rate"] == 0.5
    assert "不代表根因准确率" in learning.metrics()["metric_label"]
    audit = [item for item in operations.audit()["items"] if item["action"] == "diagnosis_feedback"]
    assert len(audit) == 3
    assert audit[-1]["actor"] == "alice"
    assert audit[1]["details"]["updated"] is True


def test_new_diagnosis_requires_new_feedback_and_old_metrics_remain(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event = event_at(operations)
    diagnose_pending(operations)
    first = learning.feedback(event["id"], {"useful": False}, "alice")
    event_at(operations)
    diagnose_pending(operations)
    current = learning.learning(event["id"], "alice")
    assert current["diagnosis_id"] != first["diagnosis_id"]
    assert current["current_feedback"] is None
    assert current["stats"]["feedback_count"] == 0
    learning.feedback(event["id"], {"useful": True}, "alice")
    assert learning.metrics()["feedback_count"] == 2


def test_low_quality_knowledge_needs_multiple_real_reviews(tmp_path):
    operations, _, learning = service_at(tmp_path)
    first = event_at(operations)
    demo = event_at(operations, is_demo=True)
    diagnose_pending(operations)
    learning.feedback(first["id"], {"useful": False}, "alice")
    learning.feedback(first["id"], {"useful": False}, "bob")
    learning.feedback(demo["id"], {"useful": False}, "demo-user")
    before = learning.metrics()
    assert before["feedback_count"] == 2
    assert before["runbooks"]
    assert all(not item["review_required"] for item in before["runbooks"])
    learning.feedback(first["id"], {"useful": True}, "charlie")
    after = learning.metrics()
    assert after["feedback_count"] == 3
    assert all(item["review_required"] for item in after["runbooks"])
    learning.feedback(first["id"], {"useful": True}, "alice")
    assert all(not item["review_required"] for item in learning.metrics()["runbooks"])


def test_empty_metrics_unknown_and_boolean_feedback_validation(tmp_path):
    _, _, learning = service_at(tmp_path)
    assert learning.metrics()["acceptance_rate"] is None
    with pytest.raises(ValidationError):
        FeedbackInput(useful="false")
    with pytest.raises(ValidationError):
        FeedbackInput(useful=True, comment="x" * 2001)


def test_resolved_case_keeps_candidate_cause_and_unknown_health(tmp_path):
    operations, repository, learning = service_at(tmp_path)
    event = event_at(operations)
    diagnose_pending(operations)
    resolved = operations.update_incident(event["id"], IncidentPatch(status="resolved", resolution="修复 upstream 端口配置"))
    case = learning.on_resolved(resolved, "alice")
    assert case["result"]["operator_status"] == "resolved"
    assert case["result"]["healthy"] is None
    assert case["root_cause_confirmed"] is False
    assert case["trust_level"] == "personal"
    hits = repository.store.search("upstream 端口配置", source="nginx", limit=100)
    hit = next(item for item in hits if item.id == case["id"])
    assert "未经核实" in hit.summary
    assert any("业务恢复状态未知" in item for item in hit.steps)
    assert hit.trust_level == "personal"
    assert operations.agent.store is repository.store
    count = len(repository.store.documents)
    assert learning.on_resolved(resolved, "alice")["id"] == case["id"]
    assert len(repository.store.documents) == count
    assert len([item for item in operations.audit()["items"] if item["action"] == "historical_case_saved"]) == 1


def test_only_operator_resolution_creates_non_demo_cases(tmp_path):
    operations, repository, learning = service_at(tmp_path)
    active = event_at(operations)
    demo = event_at(operations, is_demo=True)
    assert learning.on_resolved(active, "alice") is None
    no_record = operations.update_incident(active["id"], IncidentPatch(status="resolved", resolution="  "))
    assert learning.on_resolved(no_record, "alice") is None
    demo_resolved = operations.update_incident(demo["id"], IncidentPatch(status="resolved", resolution="演示恢复"))
    assert learning.on_resolved(demo_resolved, "alice") is None
    assert not any(document.id.startswith("case-") for document in repository.store.documents)


def test_log_check_is_not_business_recovery_and_stale_checks_do_not_confirm(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event = event_at(operations)
    check = {"healthy": None, "log_check_passed": True, "checked_at": datetime.now(timezone.utc).isoformat(),
             "note": "日志无异常，业务恢复仍需核查。"}
    with operations._lock, operations._db:
        operations._timeline(event["id"], "recovery_verified", check["note"], check, actor="alice")
    resolved = operations.update_incident(event["id"], IncidentPatch(status="resolved", resolution="检查服务"))
    assert learning.on_resolved(resolved, "alice")["result"]["healthy"] is None
    with operations._lock, operations._db:
        operations._timeline(event["id"], "recovery_verified", "旧恢复核查", {
            "healthy": True, "checked_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()})
    result = learning.on_resolved(resolved, "alice")["result"]
    assert result["healthy"] is None
    assert "不能作为本次恢复证据" in result["note"]


def test_fresh_verified_health_is_preserved_as_evidence(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event = event_at(operations)
    with operations._lock, operations._db:
        operations._timeline(event["id"], "recovery_verified", "业务探测通过", {
            "healthy": True, "checked_at": datetime.now(timezone.utc).isoformat(), "note": "业务探测通过"})
    resolved = operations.update_incident(event["id"], IncidentPatch(status="resolved", resolution="修复配置"))
    assert learning.on_resolved(resolved, "alice")["result"]["healthy"] is True


def test_feedback_and_retrievable_cases_survive_close_reopen(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event = event_at(operations)
    diagnose_pending(operations)
    learning.feedback(event["id"], {"useful": True}, "alice")
    resolved = operations.update_incident(event["id"], IncidentPatch(status="resolved", resolution="fix upstream port configuration"))
    case = learning.on_resolved(resolved, "alice")
    operations._db.close()
    reopened, repository, learning2 = service_at(tmp_path)
    assert learning2.learning(event["id"], "alice")["current_feedback"]["useful"] is True
    assert learning2.learning(event["id"], "alice")["case"]["id"] == case["id"]
    assert any(item.id == case["id"] for item in repository.store.search("upstream port configuration", source="nginx", limit=100))
    assert learning2.on_resolved(reopened.get_incident(event["id"]), "alice")["id"] == case["id"]
    assert len([item for item in reopened.audit()["items"] if item["action"] == "historical_case_saved"]) == 1


def test_routes_bind_feedback_to_authenticated_actor(tmp_path):
    operations, _, learning = service_at(tmp_path)
    event = event_at(operations)
    diagnose_pending(operations)
    app = FastAPI()

    @app.middleware("http")
    async def identity(request: Request, call_next):
        request.state.operator = "alice"
        request.state.permissions = ["incident:write"] if request.headers.get("x-write") == "yes" else []
        return await call_next(request)

    app.include_router(create_improvement_router(learning))
    client = TestClient(app)
    assert client.get("/api/campaigns").status_code == 200
    assert client.get("/api/learning/metrics").json()["acceptance_rate"] is None
    assert client.get("/api/incidents/missing/learning").status_code == 404
    assert client.post(f"/api/incidents/{event['id']}/feedback", json={"useful": True}).status_code == 403
    response = client.post(f"/api/incidents/{event['id']}/feedback", headers={"x-write": "yes"},
                           json={"useful": True, "operator": "spoofed-admin"})
    assert response.status_code == 200
    assert response.json()["current_feedback"]["actor"] == "alice"
