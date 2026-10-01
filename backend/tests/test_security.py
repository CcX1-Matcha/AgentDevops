from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.security import AccessMiddleware


def make_client():
    app = FastAPI()
    app.add_middleware(AccessMiddleware)

    @app.api_route("/api/test", methods=["GET", "POST"])
    def secured(request: Request):
        return {"role": request.state.role}

    @app.post("/api/alerts/webhook")
    def webhook(request: Request):
        return {"role": request.state.role}

    @app.post("/api/sources")
    def sources():
        return {"ok": True}

    @app.post("/api/sources/source-id/scan-now")
    def scan():
        return {"ok": True}

    @app.post("/api/remediation/plan-id/execute")
    def execute():
        return {"ok": True}

    return TestClient(app)


def test_role_tokens_enforce_read_write_permissions(monkeypatch):
    monkeypatch.setenv("OPS_API_TOKEN", "test-operator")
    monkeypatch.setenv("OPS_READ_TOKEN", "test-reader")
    monkeypatch.setenv("ALERT_WEBHOOK_TOKEN", "test-ingest")
    client = make_client()
    assert client.get("/api/test").status_code == 401
    assert client.get("/api/test", headers={"Authorization": "Bearer test-reader"}).json()["role"] == "viewer"
    assert client.post("/api/test", headers={"Authorization": "Bearer test-reader"}).status_code == 403
    assert client.post("/api/test", headers={"Authorization": "Bearer test-operator"}).status_code == 200
    assert client.post("/api/alerts/webhook", headers={"Authorization": "Bearer test-ingest"}).json()["role"] == "alert_ingest"
    assert client.get("/api/test", headers={"Authorization": "Bearer test-ingest"}).status_code == 401
    assert client.get("/api/test", headers={"Authorization": b"Bearer \xe9"}).status_code == 401


def test_tokenless_local_writes_reject_other_origin(monkeypatch):
    for key in ["OPS_API_TOKEN", "OPS_READ_TOKEN", "ALERT_WEBHOOK_TOKEN"]:
        monkeypatch.delenv(key, raising=False)
    client = make_client()
    assert client.post("/api/test").status_code == 200
    assert client.post("/api/test", headers={"Origin": "https://another.example"}).status_code == 403


def test_shared_token_cannot_manage_sources_or_execute_remediation(monkeypatch):
    monkeypatch.setenv("OPS_API_TOKEN", "test-operator")
    client = make_client()
    headers = {"Authorization": "Bearer test-operator"}
    assert client.post("/api/test", headers=headers).status_code == 200
    assert client.post("/api/sources/source-id/scan-now", headers=headers).status_code == 200
    assert client.post("/api/sources", headers=headers).status_code == 403
    assert client.post("/api/remediation/plan-id/execute", headers=headers).status_code == 403
    assert client.post("/api/test", headers={**headers, "Origin": "https://another.example"}).status_code == 403
    assert client.post("/api/test", headers={**headers, "Origin": "http://testserver"}).status_code == 200
    assert client.post("/api/test", headers={**headers, "Origin": "https://testserver"}).status_code == 403


def test_webhook_token_never_falls_back_to_local_operator(monkeypatch):
    monkeypatch.delenv("OPS_API_TOKEN", raising=False)
    monkeypatch.delenv("OPS_READ_TOKEN", raising=False)
    monkeypatch.setenv("ALERT_WEBHOOK_TOKEN", "test-ingest")
    client = make_client()
    headers = {"Authorization": "Bearer test-ingest"}
    assert client.post("/api/alerts/webhook", headers=headers).status_code == 200
    assert client.get("/api/test", headers=headers).status_code == 401
    assert client.post("/api/test", headers=headers).status_code == 401
    assert client.get("/api/test", headers={"Authorization": "Bearer arbitrary-token"}).status_code == 401


def test_local_fallback_remains_junior(monkeypatch):
    for key in ["OPS_API_TOKEN", "OPS_READ_TOKEN", "ALERT_WEBHOOK_TOKEN"]:
        monkeypatch.delenv(key, raising=False)
    client = make_client()
    assert client.post("/api/sources/source-id/scan-now").status_code == 200
    assert client.post("/api/sources").status_code == 403
    assert client.post("/api/remediation/plan-id/execute").status_code == 403
