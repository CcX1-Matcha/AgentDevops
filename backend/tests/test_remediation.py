import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.accounts import AccountService, create_account_router
from app.agent import ReActAgent
from app.demo import DemoSources
from app.operations import OperationsService
from app.ops_models import AlertInput, IncidentPatch
from app.remediation import Playbook, RemediationService, create_remediation_router
from app.security import AccessMiddleware


def event_at(tmp_path, **overrides):
    ops = OperationsService(tmp_path / "operations.sqlite3", ReActAgent())
    event = ops.ingest_alert(AlertInput.model_validate({"service": "orders-api", "environment": "staging",
        "instance": "worker-01", "source": "server", "severity": "warning",
        "message": "server WARNING managed temporary cache usage above baseline", **overrides}))
    asyncio.run(ops._diagnose_event(ops._claim_job()))
    return ops, ops.get_incident(event["id"])


def book_at(tmp_path, **overrides):
    data = dict(id="cache-cleanup", name="Managed cache cleanup", description="Rebuildable cache only",
        action="cleanup_managed_temp", source="server", service="orders-api", environment="staging",
        instance="worker-01", failure_types=["managed_cache_pressure"], approved_by="service-owner",
        rollback="Rebuild the managed cache", endpoint_url="https://executor.example/api/cleanup",
        verify_url="https://executor.example/api/health")
    data.update(overrides)
    path = tmp_path / "playbooks.json"
    path.write_text(json.dumps([data]), encoding="utf-8")
    return path


def successful_executor(calls, healthy=True, check_overrides=None):
    def respond(request):
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"status": "succeeded"})
        return httpx.Response(200, json={"healthy": healthy, "plan_id": request.url.params["plan_id"],
            "checked_at": datetime.now(timezone.utc).isoformat(), **(check_overrides or {})})
    return httpx.MockTransport(respond)


def test_http_execution_uses_fixed_target_and_verifies_without_resolving(tmp_path, monkeypatch):
    calls = []
    ops, event = event_at(tmp_path)
    monkeypatch.setenv("CACHE_EXECUTOR_TOKEN", "private-connector-secret")
    service = RemediationService(ops, book_at(tmp_path, token_env="CACHE_EXECUTOR_TOKEN"), transport=successful_executor(calls))
    plan = service.create_plan(event["id"], "cache-cleanup", "senior-a")
    result = asyncio.run(service.execute(plan["id"], "senior-a"))
    assert result["status"] == "succeeded" and result["verification"]["healthy"] is True
    assert ops.get_incident(event["id"])["status"] == "awaiting_confirmation"
    posted = json.loads(calls[0].content)
    assert posted["target"] == {"service": "orders-api", "environment": "staging", "instance": "worker-01"}
    assert "logs" not in posted and "command" not in posted
    assert calls[0].headers["Idempotency-Key"] == plan["id"]
    assert calls[0].headers["Authorization"] == "Bearer private-connector-secret"
    assert "private-connector-secret" not in json.dumps(ops.audit()) + json.dumps(service.describe(event["id"]))
    with pytest.raises(ValueError):
        asyncio.run(service.execute(plan["id"], "senior-a"))
    with pytest.raises(ValueError):
        service.create_plan(event["id"], "cache-cleanup", "senior-a")
    assert len(calls) == 2


@pytest.mark.parametrize("overrides", [
    {"severity": "critical"}, {"severity": "error"},
    {"message": "server ERROR disk write failed", "severity": "warning"},
    {"message": "server WARNING kernel OOMKilled", "severity": "warning"},
    {"instance": "unknown"}, {"environment": "production"},
])
def test_label_spoofing_or_high_severity_cannot_execute(tmp_path, overrides):
    ops, event = event_at(tmp_path, **overrides)
    service = RemediationService(ops, book_at(tmp_path))
    assert not service.describe(event["id"])["eligible"]
    with pytest.raises(ValueError):
        service.create_plan(event["id"], "cache-cleanup", "senior")


def test_escalated_incident_invalidates_approved_snapshot(tmp_path):
    calls = []
    ops, event = event_at(tmp_path)
    service = RemediationService(ops, book_at(tmp_path), transport=successful_executor(calls))
    plan = service.create_plan(event["id"], "cache-cleanup", "senior")
    ops.ingest_alert(AlertInput(service="orders-api", environment="staging", instance="worker-01",
        source="server", severity="critical", message="WARNING managed temporary cache usage above baseline"))
    with pytest.raises(ValueError):
        asyncio.run(service.execute(plan["id"], "senior"))
    assert service.describe(event["id"])["plans"][0]["status"] == "stale"
    assert not calls


def test_expired_or_changed_configuration_is_rejected(tmp_path):
    ops, event = event_at(tmp_path)
    path = book_at(tmp_path)
    service = RemediationService(ops, path)
    plan = service.create_plan(event["id"], "cache-cleanup", "senior")
    with ops._lock, ops._db:
        plan["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service._save(plan)
    with pytest.raises(ValueError):
        asyncio.run(service.execute(plan["id"], "senior"))
    new_plan = service.create_plan(event["id"], "cache-cleanup", "senior")
    service.playbooks["cache-cleanup"] = Playbook.model_validate({**service.playbooks["cache-cleanup"].model_dump(), "parameters": {"policy": "changed"}})
    with pytest.raises(ValueError):
        asyncio.run(service.execute(new_plan["id"], "senior"))


def test_timeout_is_unknown_and_not_replayed_after_restart(tmp_path):
    calls = []
    def timeout(request):
        calls.append(request)
        raise httpx.ReadTimeout("executor may have accepted the action")
    ops, event = event_at(tmp_path)
    path = book_at(tmp_path)
    service = RemediationService(ops, path, transport=httpx.MockTransport(timeout))
    plan = service.create_plan(event["id"], "cache-cleanup", "senior")
    result = asyncio.run(service.execute(plan["id"], "senior"))
    assert result["status"] == "unknown" and result["verification"] is None
    restarted = RemediationService(ops, path, transport=httpx.MockTransport(timeout))
    with pytest.raises(ValueError):
        asyncio.run(restarted.execute(plan["id"], "senior"))
    assert len(calls) == 1


@pytest.mark.parametrize("check_overrides,expected", [
    ({"healthy": False}, "verification_failed"),
    ({"healthy": "true"}, "succeeded"),
    ({"plan_id": "unrelated-plan"}, "succeeded"),
    ({"checked_at": "2020-01-01T00:00:00Z"}, "succeeded"),
    ({"checked_at": None}, "succeeded"),
    ({"checked_at": 123}, "succeeded"),
])
def test_invalid_health_is_unknown_and_unhealthy_is_failure(tmp_path, check_overrides, expected):
    ops, event = event_at(tmp_path)
    service = RemediationService(ops, book_at(tmp_path), transport=successful_executor([], check_overrides=check_overrides))
    plan = service.create_plan(event["id"], "cache-cleanup", "senior")
    result = asyncio.run(service.execute(plan["id"], "senior"))
    assert result["status"] == expected
    assert result["verification"]["healthy"] is (False if expected == "verification_failed" else None)


def test_process_interruption_is_persisted_as_unknown(tmp_path):
    ops, event = event_at(tmp_path)
    path = book_at(tmp_path)
    service = RemediationService(ops, path)
    plan = service.create_plan(event["id"], "cache-cleanup", "senior")
    with ops._lock, ops._db:
        plan["status"] = "running"
        service._save(plan)
    ops._db.close()
    reopened = OperationsService(tmp_path / "operations.sqlite3", ReActAgent())
    restarted = RemediationService(reopened, path)
    assert restarted.describe(event["id"])["plans"][0]["status"] == "unknown"


def test_concurrent_plans_for_same_target_only_send_one_operation(tmp_path):
    ops, first = event_at(tmp_path)
    async def scenario():
        started, release = threading.Event(), threading.Event()
        calls = []
        def executor(request):
            calls.append(request)
            if request.method == "POST":
                started.set()
                assert release.wait(3)
                return httpx.Response(200, json={"status": "succeeded"})
            return httpx.Response(200, json={"healthy": True, "plan_id": request.url.params["plan_id"],
                                           "checked_at": datetime.now(timezone.utc).isoformat()})
        with ops._lock, ops._db:
            old = ops._get("incidents", first["id"])
            old["first_seen"] = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
            ops._save_incident(old)
        second = ops.ingest_alert(AlertInput(service="orders-api", environment="staging", instance="worker-01",
            source="server", severity="warning", message="WARNING managed temporary cache usage above baseline"))
        await ops._diagnose_event(ops._claim_job())
        service = RemediationService(ops, book_at(tmp_path), transport=httpx.MockTransport(executor))
        plan_a = service.create_plan(first["id"], "cache-cleanup", "senior-a")
        plan_b = service.create_plan(second["id"], "cache-cleanup", "senior-b")
        running = asyncio.create_task(service.execute(plan_a["id"], "senior-a"))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            with pytest.raises(ValueError):
                await service.execute(plan_b["id"], "senior-b")
        finally:
            release.set()
            await running
        assert sum(call.method == "POST" for call in calls) == 1
    asyncio.run(scenario())


def test_actual_demo_collection_and_simulation_stays_separate(tmp_path):
    async def scenario():
        ops = OperationsService(tmp_path / "ops.sqlite3", ReActAgent())
        demo = DemoSources(ops, tmp_path)
        demo.initialize()
        alert = demo.append("warning")
        await ops.scan_source(alert["source_id"])
        await ops._diagnose_event(ops._claim_job())
        event = ops.list_incidents()["items"][0]
        assert event["severity"] == "warning" and event["failure_type"] == "managed_cache_pressure"
        service = RemediationService(ops, demo_runner=demo.remediate)
        plan = service.create_plan(event["id"], "demo-cache-recovery", "senior")
        result = await service.execute(plan["id"], "senior")
        assert result["status"] == "simulated" and result["verification"]["healthy"] is None
        assert (tmp_path / "demo" / "warning.log").read_text().count("simulated") == 1
        ops.update_incident(event["id"], IncidentPatch(status="resolved", resolution="simulation only"))
        assert not service.describe(event["id"])["eligible"]
    asyncio.run(scenario())


def test_role_and_explicit_confirmation_enforced_by_api(tmp_path, monkeypatch):
    for variable in ("OPS_API_TOKEN", "OPS_READ_TOKEN", "ALERT_WEBHOOK_TOKEN"):
        monkeypatch.delenv(variable, raising=False)
    ops, event = event_at(tmp_path)
    calls = []
    remediation = RemediationService(ops, book_at(tmp_path), transport=successful_executor(calls))
    accounts = AccountService(tmp_path / "accounts.sqlite3")
    administrator = accounts.bootstrap("admin-test", "Long-test-password")
    for username, role in [("junior-test", "junior"), ("senior-test", "senior"), ("viewer-test", "viewer")]:
        accounts.create_account(username, "Long-test-password", role)
    application = FastAPI()
    application.add_middleware(AccessMiddleware, account_service=accounts)
    application.include_router(create_account_router(accounts))
    application.include_router(create_remediation_router(remediation))
    client = TestClient(application)
    for username in ("junior-test", "viewer-test"):
        token = accounts.login(username, "Long-test-password")["token"]
        response = client.post(f"/api/incidents/{event['id']}/remediation/plans", json={"playbook_id": "cache-cleanup"}, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403
    token = accounts.login("senior-test", "Long-test-password")["token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(f"/api/incidents/{event['id']}/remediation/plans", json={"playbook_id": "cache-cleanup"}, headers=headers)
    assert response.status_code == 201
    plan_id = response.json()["id"]
    for payload in ({}, {"confirmed": False}, {"confirmed": True, "command": "arbitrary shell"}):
        assert client.post(f"/api/remediation/plans/{plan_id}/execute", json=payload, headers=headers).status_code == 422
    senior = next(user for user in accounts.list_accounts()["items"] if user["role"] == "senior")
    accounts.update_account(senior["id"], role="junior")
    assert client.post(f"/api/remediation/plans/{plan_id}/execute", json={"confirmed": True}, headers=headers).status_code in {401, 403}
    assert not calls
    response = client.post(f"/api/remediation/plans/{plan_id}/execute", json={"confirmed": True}, headers={"Authorization": f"Bearer {administrator['token']}"})
    assert response.status_code == 200 and response.json()["executed_by"] == "admin-test"


def test_missing_executor_secret_does_not_claim_plan(tmp_path, monkeypatch):
    monkeypatch.delenv("CACHE_EXECUTOR_TOKEN", raising=False)
    ops, event = event_at(tmp_path)
    service = RemediationService(ops, book_at(tmp_path, token_env="CACHE_EXECUTOR_TOKEN"))
    plan = service.create_plan(event["id"], "cache-cleanup", "senior")
    with pytest.raises(ValueError):
        asyncio.run(service.execute(plan["id"], "senior"))
    assert service.describe(event["id"])["plans"][0]["status"] == "pending"


def test_malformed_config_fails_closed(tmp_path):
    ops, event = event_at(tmp_path)
    service = RemediationService(ops, book_at(tmp_path, endpoint_url="http://untrusted.example/exec"))
    assert service.config_error and not service.describe(event["id"])["eligible"]
