"""Exercise the proactive path through real files, durable cursors and jobs."""
import asyncio
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.agent import ReActAgent
from app.knowledge import KnowledgeStore
from app.operations import MAX_READ_BYTES, OperationsService, create_ops_router
from app.ops_models import FollowupInput, IncidentPatch, MergeInput, SourcePatch, SplitInput


ERROR = "2026-10-01T10:00:00Z [error] connect() failed (111: Connection refused) while connecting to upstream\n"
NORMAL = "2026-10-01T10:00:01Z INFO health check completed\n"


def service_at(tmp_path, agent=None, provider=None):
    return OperationsService(tmp_path / "operations.sqlite3", agent or ReActAgent(), provider)


def source_at(service, tmp_path, initial="", **overrides):
    path = tmp_path / "nginx.log"
    path.write_text(initial, encoding="utf-8")
    source = service.create_source(dict(name="Nginx", path=str(path), source="nginx", service="orders",
                                       environment="test", instance="node-1", poll_interval_seconds=0.25, **overrides))
    return path, source


def append(path, text):
    with path.open("a", encoding="utf-8", newline="") as stream:
        stream.write(text)


def test_worker_detects_real_file_append_and_diagnoses(tmp_path):
    async def scenario():
        service = service_at(tmp_path)
        path, source = source_at(service, tmp_path, ERROR)
        await service.start()
        try:
            assert service.list_incidents()["total"] == 0
            append(path, NORMAL + ERROR)
            deadline = time.monotonic() + 5
            while service.list_incidents()["total"] == 0 and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            await service.wait_for_idle()
            event = service.list_incidents()["items"][0]
            detail = service.get_incident(event["id"])
            assert detail["status"] == "awaiting_confirmation"
            assert detail["source_id"] == source["id"]
            assert detail["diagnosis"]["failure_type"] == "upstream_unavailable"
            assert detail["diagnosis"]["metrics"]["error_count"] == 1
            assert detail["occurrences"] == 1
            assert detail["diagnosis"]["missing_information"]
            assert any(row["action"] == "diagnosis_completed" for row in service.audit()["items"])
        finally:
            await service.stop()
    asyncio.run(scenario())


def test_partial_line_is_buffered_and_cursor_survives_restart(tmp_path):
    service = service_at(tmp_path)
    path, source = source_at(service, tmp_path)
    append(path, ERROR[:40])
    first = asyncio.run(service.scan_source(source["id"]))
    assert first["lines_read"] == 0
    restarted = service_at(tmp_path)
    append(path, ERROR[40:])
    second = asyncio.run(restarted.scan_source(source["id"]))
    assert second["anomalies_detected"] == 1
    assert asyncio.run(restarted.scan_source(source["id"]))["anomalies_detected"] == 0
    assert restarted.list_incidents()["items"][0]["occurrences"] == 1


def test_initial_partial_line_is_not_mistaken_for_new_log(tmp_path):
    service = service_at(tmp_path)
    path, source = source_at(service, tmp_path, "existing unfinished line ")
    append(path, ERROR + NORMAL)
    result = asyncio.run(service.scan_source(source["id"]))
    assert result["anomalies_detected"] == 0
    append(path, ERROR)
    assert asyncio.run(service.scan_source(source["id"]))["anomalies_detected"] == 1


def test_read_existing_rotation_and_same_inode_rewrite(tmp_path):
    service = service_at(tmp_path)
    path, source = source_at(service, tmp_path, ERROR, read_existing=True)
    assert asyncio.run(service.scan_source(source["id"]))["anomalies_detected"] == 1
    path.rename(tmp_path / "nginx.log.1")
    path.write_text(ERROR, encoding="utf-8")
    assert asyncio.run(service.scan_source(source["id"]))["anomalies_detected"] == 1
    path.write_text(ERROR.replace("10:00:00", "11:00:00"), encoding="utf-8")
    assert asyncio.run(service.scan_source(source["id"]))["anomalies_detected"] == 1
    assert service.list_incidents()["items"][0]["occurrences"] == 3


def test_cursor_reads_bounded_chunks_without_losing_backlog(tmp_path):
    service = service_at(tmp_path)
    path, source = source_at(service, tmp_path)
    append(path, NORMAL * 7000 + ERROR)
    first = asyncio.run(service.scan_source(source["id"]))
    assert first["source"]["cursor_offset"] == MAX_READ_BYTES
    assert first["anomalies_detected"] == 0
    second = asyncio.run(service.scan_source(source["id"]))
    assert second["anomalies_detected"] == 1


def test_missing_source_is_explicit_and_paused_source_does_not_scan(tmp_path):
    service = service_at(tmp_path)
    path, source = source_at(service, tmp_path)
    path.unlink()
    failed = asyncio.run(service.scan_source(source["id"]))
    assert failed["source"]["health"] == "error"
    assert "FileNotFoundError" in failed["error"]
    service.update_source(source["id"], SourcePatch(enabled=False))
    path.write_text(ERROR, encoding="utf-8")
    assert asyncio.run(service.scan_source(source["id"]))["anomalies_detected"] == 0
    assert service.list_sources()["items"][0]["health"] == "paused"


def test_alert_grouping_isolated_by_environment_instance_type_and_demo(tmp_path):
    service = service_at(tmp_path)
    alert = dict(service="orders", environment="prod", instance="node1", source="nginx", message=ERROR)
    first = service.ingest_alert(alert)
    second = service.ingest_alert(alert)
    assert first["id"] == second["id"]
    assert second["occurrences"] == 2
    service.ingest_alert({**alert, "environment": "staging"})
    service.ingest_alert({**alert, "instance": "node2"})
    service.ingest_alert({**alert, "message": "ERROR upstream timed out"})
    service.ingest_alert({**alert, "is_demo": True})
    assert service.list_incidents()["total"] == 5
    assert len(service.get_incident(first["id"])["original_alerts"]) == 2


def test_aggregation_window_and_resolved_incident_generate_new_events(tmp_path):
    service = service_at(tmp_path)
    service.aggregation_seconds = -1
    alert = dict(service="orders", message=ERROR)
    first = service.ingest_alert(alert)
    second = service.ingest_alert(alert)
    assert first["id"] != second["id"]
    service.aggregation_seconds = 300
    service.update_incident(second["id"], IncidentPatch(status="resolved", resolution="Restarted manually"))
    service.update_incident(first["id"], IncidentPatch(status="resolved", resolution="Restarted manually"))
    third = service.ingest_alert(alert)
    assert third["id"] not in {first["id"], second["id"]}


def test_context_failure_is_retained_and_llm_failure_is_degraded(tmp_path):
    class UnavailableLLM:
        mode = "llm"
        store = KnowledgeStore()

        def diagnose(self, *args):
            raise TimeoutError("model timed out")

    async def provider(event):
        raise OSError("metrics unreachable")

    async def scenario():
        service = service_at(tmp_path, UnavailableLLM(), provider)
        event = service.ingest_alert(dict(service="orders", source="nginx", message=ERROR))
        await service.start()
        try:
            await service.wait_for_idle()
            detail = service.get_incident(event["id"])
            assert detail["diagnosis"]["mode"] == "local"
            assert "model timed out" in detail["fallback_reason"]
            assert detail["context_collection"]["context_sources"][0]["status"] == "failed"
            assert "metrics unreachable" in detail["context_collection"]["context_sources"][0]["error"]
        finally:
            await service.stop()
    asyncio.run(scenario())


def test_failed_job_followup_retry_and_export_are_durable(tmp_path):
    class BrokenLocal:
        mode = "local"

        def diagnose(self, *args):
            raise RuntimeError("KB unreadable")

    async def scenario():
        service = service_at(tmp_path, BrokenLocal())
        event = service.ingest_alert(dict(service="orders", source="nginx", message=ERROR, is_demo=True))
        await service.start()
        try:
            await service.wait_for_idle()
            assert service.get_incident(event["id"])["status"] == "failed"
            service.agent = ReActAgent()
            service.followup(event["id"], FollowupInput(message="No release today", logs="ERROR upstream timed out"))
            await service.wait_for_idle()
            service.update_incident(event["id"], IncidentPatch(status="acknowledged"))
            service.update_incident(event["id"], IncidentPatch(status="resolved", resolution="Corrected upstream port manually"))
            report = service.export_incident(event["id"])
            assert "演示数据" in report and "Corrected upstream port manually" in report
            assert "待人工核实" in report
        finally:
            await service.stop()
        restarted = service_at(tmp_path)
        detail = restarted.get_incident(event["id"])
        assert detail["status"] == "resolved"
        assert detail["context_notes"][0]["message"] == "No release today"
        assert restarted.overview()["metrics"]["mttr_seconds"] is None
        real_event = restarted.ingest_alert(dict(service="orders", source="nginx", message=ERROR))
        restarted.update_incident(real_event["id"], IncidentPatch(status="resolved", resolution="Confirmed by operator"))
        assert restarted.overview()["metrics"]["mttr_seconds"] is not None
        assert restarted.overview()["metrics"]["top1_accuracy"] is None
    asyncio.run(scenario())


def test_verify_never_claims_recovery_without_new_complete_data(tmp_path):
    async def scenario():
        service = service_at(tmp_path)
        path, source = source_at(service, tmp_path)
        append(path, ERROR)
        scanned = await service.scan_source(source["id"])
        event_id = scanned["incident_ids"][0]
        assert (await service.verify_incident(event_id))["healthy"] is None
        append(path, NORMAL)
        normal_result = await service.verify_incident(event_id)
        assert normal_result["healthy"] is None
        assert normal_result["log_check_passed"] is True
        append(path, ERROR)
        error_result = await service.verify_incident(event_id)
        assert error_result["healthy"] is False
        assert error_result["log_check_passed"] is False
    asyncio.run(scenario())


def test_alertmanager_webhook_retry_deduplicates_and_resolved_is_not_repair(tmp_path):
    service = service_at(tmp_path)
    app = FastAPI()
    app.include_router(create_ops_router(service))
    client = TestClient(app)
    payload = {"status": "firing", "alerts": [{"status": "firing", "fingerprint": "abc", "startsAt": "2026-10-01T12:00:00Z",
                "labels": {"alertname": "High5xx", "service": "orders", "instance": "host", "severity": "critical"},
                "annotations": {"summary": "ERROR connection refused"}}]}
    response = client.post("/api/alerts/webhook", json=payload)
    assert response.status_code == 202
    event_id = response.json()["incident_ids"][0]
    assert client.post("/api/alerts/webhook", json=payload).json()["incident_ids"] == [event_id]
    assert service.get_incident(event_id)["occurrences"] == 1
    payload["alerts"][0]["status"] = "resolved"
    client.post("/api/alerts/webhook", json=payload)
    assert service.get_incident(event_id)["status"] != "resolved"
    assert service.get_incident(event_id)["original_alerts"][-1]["status"] == "resolved"


def test_manual_split_and_merge_preserve_original_alert_count(tmp_path):
    service = service_at(tmp_path)
    alert = dict(service="orders", message=ERROR)
    event = service.ingest_alert(alert)
    service.ingest_alert(alert)
    service.ingest_alert(alert)
    detail = service.get_incident(event["id"])
    split = service.split_incident(event["id"], SplitInput(alert_ids=[detail["original_alerts"][0]["id"]]))
    assert split["original"]["occurrences"] == 2
    assert split["split"]["occurrences"] == 1
    combined = service.merge_incidents(event["id"], MergeInput(incident_ids=[split["split"]["id"]]))
    assert combined["occurrences"] == 3
    assert len(combined["original_alerts"]) == 3
    assert service.list_incidents()["total"] == 1


def test_recovered_in_progress_job_returns_to_queue(tmp_path):
    service = service_at(tmp_path)
    event = service.ingest_alert(dict(service="orders", message=ERROR))
    assert service._claim_job()["status"] == "diagnosing"
    restarted = service_at(tmp_path)
    recovered = restarted.get_incident(event["id"])
    assert recovered["status"] == "new"
    assert restarted._claim_job()["id"] == event["id"]


def test_resolved_external_alert_correlates_after_grouping_window(tmp_path):
    service = service_at(tmp_path)
    alert = dict(service="orders", message=ERROR, fingerprint="long-incident", starts_at="2026-10-01T10:00:00Z")
    event = service.ingest_alert(alert)
    service.aggregation_seconds = -1
    resolved = service.ingest_alert({**alert, "status": "resolved", "ends_at": "2026-10-01T10:20:00Z"})
    assert resolved["id"] == event["id"]
    assert resolved["status"] != "resolved"
    assert service.get_incident(event["id"])["original_alerts"][-1]["ends_at"] == "2026-10-01T10:20:00Z"


def test_api_audit_uses_authenticated_operator_not_body_override(tmp_path):
    service = service_at(tmp_path)
    app = FastAPI()

    @app.middleware("http")
    async def operator_identity(request, call_next):
        request.state.operator = "authenticated-sre"
        return await call_next(request)

    app.include_router(create_ops_router(service))
    client = TestClient(app)
    path = tmp_path / "identity.log"
    path.write_text("", encoding="utf-8")
    source = client.post("/api/sources", json={"name": "identity", "path": str(path)}).json()
    client.patch(f"/api/sources/{source['id']}", json={"enabled": False})
    client.delete(f"/api/sources/{source['id']}")
    event = service.ingest_alert(dict(service="orders", message=ERROR))
    client.patch(f"/api/incidents/{event['id']}", json={"status": "acknowledged", "operator": "spoofed-admin"})
    assert all(item["actor"] == "authenticated-sre" for item in service.audit()["items"] if item["action"] in {"source_created", "source_updated", "source_deleted", "incident_status_changed"})


def test_invalid_webhook_batch_does_not_persist_earlier_valid_alerts(tmp_path):
    service = service_at(tmp_path)
    app = FastAPI()
    app.include_router(create_ops_router(service))
    response = TestClient(app).post("/api/alerts/webhook", json={"alerts": [
        {"labels": {"service": "orders"}, "annotations": {"summary": "ERROR connection refused"}},
        {"labels": {"service": "orders", "source": "invalid-source"}, "annotations": {"summary": "ERROR timeout"}},
    ]})
    assert response.status_code == 422
    assert service.list_incidents()["total"] == 0
    assert service.audit()["total"] == 0


def test_explicit_configuration_update_preserves_tail_cursor(tmp_path):
    service = service_at(tmp_path)
    path, original = source_at(service, tmp_path, ERROR)
    payload = dict(name="configured name", path=str(path), source="docker", service="payments", environment="production",
                   instance="docker-1", enabled=False, poll_interval_seconds=8)
    unchanged = service.ensure_source(payload)
    assert unchanged["enabled"] is True
    assert unchanged["name"] == original["name"]
    updated = service.ensure_source(payload, update_existing=True)
    assert updated["id"] == original["id"]
    assert updated["cursor_offset"] == original["cursor_offset"]
    assert updated["enabled"] is False and updated["health"] == "paused"
    assert updated["service"] == "payments" and updated["source"] == "docker"
    append(path, ERROR)
    service.update_source(updated["id"], SourcePatch(enabled=True))
    assert asyncio.run(service.scan_source(updated["id"]))["anomalies_detected"] == 1


def test_completed_diagnosis_title_and_missing_context_are_readable(tmp_path):
    async def provider(event):
        return {"context_sources": [{"name": "监控指标", "kind": "metrics", "status": "not_configured"}], "logs": ""}

    async def scenario():
        service = service_at(tmp_path, provider=provider)
        event = service.ingest_alert(dict(service="orders", source="nginx", message=ERROR))
        await service.start()
        try:
            await service.wait_for_idle()
            detail = service.get_incident(event["id"])
            assert detail["title"] == detail["diagnosis"]["summary"]
            assert len([item for item in detail["diagnosis"]["missing_information"] if "监控指标" in item]) == 1
        finally:
            await service.stop()
    asyncio.run(scenario())


def test_shutdown_waits_for_started_diagnosis_before_reporting_drained(tmp_path):
    entered, release = threading.Event(), threading.Event()

    class BlockingAgent:
        mode = "local"

        def diagnose(self, *args):
            entered.set()
            release.wait(3)
            return ReActAgent().diagnose(*args)

    async def scenario():
        service = service_at(tmp_path, BlockingAgent())
        event = service.ingest_alert(dict(service="orders", message=ERROR))
        await service.start()
        while not entered.is_set():
            await asyncio.sleep(0.01)
        stopping = asyncio.create_task(service.stop(grace_seconds=2))
        await asyncio.sleep(0.05)
        assert not stopping.done()
        release.set()
        assert await stopping is True
        assert service.get_incident(event["id"])["status"] == "awaiting_confirmation"
        assert not service._thread_jobs
    try:
        asyncio.run(scenario())
    finally:
        release.set()


def test_shutdown_timeout_does_not_claim_live_thread_is_drained_and_can_restart(tmp_path):
    entered, release = threading.Event(), threading.Event()

    class BlockingAgent:
        mode = "local"

        def diagnose(self, *args):
            entered.set()
            release.wait(3)
            return ReActAgent().diagnose(*args)

    async def scenario():
        service = service_at(tmp_path, BlockingAgent())
        event = service.ingest_alert(dict(service="orders", message=ERROR))
        await service.start()
        while not entered.is_set():
            await asyncio.sleep(0.01)
        assert await service.stop(grace_seconds=0.01) is False
        assert service._thread_jobs
        assert service.get_incident(event["id"])["status"] == "diagnosing"
        release.set()
        while service._thread_jobs:
            await asyncio.sleep(0.01)
        await service.start()
        await service.wait_for_idle()
        assert await service.stop() is True
        assert service.get_incident(event["id"])["status"] == "awaiting_confirmation"
    try:
        asyncio.run(scenario())
    finally:
        release.set()


def test_monitor_health_reports_worker_exit_and_consumes_exception(tmp_path):
    async def scenario():
        service = service_at(tmp_path)

        def unavailable_storage():
            raise RuntimeError("storage unavailable")

        service._claim_job = unavailable_storage
        assert service.monitor_health()["status"] == "stopped"
        await service.start()
        await asyncio.sleep(0.01)
        health = service.monitor_health()
        assert health["running"] is False
        assert health["status"] == "degraded"
        assert health["errors"] == [{"task": "diagnosis_worker", "error": "RuntimeError: storage unavailable"}]
        assert service.overview()["monitor"]["running"] is False
        assert service.overview()["monitor"]["status"] == "degraded"
        await service.stop()
        assert service.monitor_health()["status"] == "stopped"
    asyncio.run(scenario())
