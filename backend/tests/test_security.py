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
