import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.accounts import AccountService, create_account_router, main
from app.security import AccessMiddleware


PASSWORD = "test-password-123"


@pytest.fixture
def service(tmp_path):
    result = AccountService(tmp_path / "accounts.sqlite3")
    yield result
    result.close()


@pytest.fixture
def client(service, monkeypatch):
    monkeypatch.setenv("OPS_API_TOKEN", "shared-junior")
    monkeypatch.setenv("OPS_READ_TOKEN", "shared-viewer")
    monkeypatch.setenv("ALERT_WEBHOOK_TOKEN", "shared-webhook")
    return make_client(service)


def make_client(service, **kwargs):
    app = FastAPI()
    app.add_middleware(AccessMiddleware, account_service=service)
    app.include_router(create_account_router(service))

    @app.api_route("/api/incidents/example", methods=["GET", "PATCH"])
    def incident(request: Request):
        return {"actor": request.state.operator, "role": request.state.role, "account_id": request.state.account_id}

    @app.api_route("/api/sources", methods=["GET", "POST"])
    def sources():
        return {"ok": True}

    @app.post("/api/sources/example/scan-now")
    def scan():
        return {"ok": True}

    @app.post("/api/knowledge/import")
    def knowledge():
        return {"ok": True}

    @app.post("/api/remediation/example/execute")
    def execute():
        return {"ok": True}

    @app.post("/api/alerts/webhook")
    def webhook():
        return {"ok": True}

    return TestClient(app, **kwargs)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def bootstrap(client):
    response = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": PASSWORD})
    assert response.status_code == 201
    return response.json()


def test_bootstrap_is_local_once_and_does_not_grant_shared_token_admin(client, service):
    guest = client.get("/api/auth/me").json()
    assert guest == {"username": "guest", "role": "guest", "permissions": [], "authenticated": False, "bootstrap_available": True}
    shared = client.get("/api/auth/me", headers=auth("shared-junior")).json()
    assert shared["role"] == "operator"
    assert "account:manage" not in shared["permissions"]
    assert client.get("/api/accounts", headers=auth("shared-junior")).status_code == 403
    admin = bootstrap(client)
    assert admin["user"]["role"] == "admin"
    assert client.get("/api/accounts", headers=auth(admin["token"])).json()["total"] == 1
    assert client.post("/api/auth/bootstrap", json={"username": "other-admin", "password": PASSWORD}).status_code == 409
    assert client.get("/api/auth/me").json()["bootstrap_available"] is False
    assert service.bootstrap_available() is False


def test_bootstrap_rejects_remote_socket_cross_origin_and_untrusted_host(service, monkeypatch):
    monkeypatch.setenv("OPS_API_TOKEN", "shared-junior")
    payload = {"username": "administrator", "password": PASSWORD}
    remote = make_client(service, base_url="http://127.0.0.1", client=("198.51.100.10", 12345))
    assert remote.post("/api/auth/bootstrap", json=payload).status_code == 403
    assert remote.get("/api/auth/me").json()["bootstrap_available"] is False
    local = make_client(service, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 12345))
    assert local.post("/api/auth/bootstrap", json=payload, headers={"Origin": "http://evil.example"}).status_code == 403
    assert local.post("/api/auth/bootstrap", json=payload, headers={"Origin": "https://127.0.0.1:8000"}).status_code == 403
    assert make_client(service, base_url="http://evil.example").post("/api/auth/bootstrap", json=payload).status_code == 403
    assert service.bootstrap_available()
    assert local.post("/api/auth/bootstrap", json=payload, headers={"Origin": "http://127.0.0.1:8000"}).status_code == 201


@pytest.mark.parametrize("role,manual,scan,manage,execute", [
    ("viewer", 403, 403, 403, 403),
    ("junior", 200, 200, 403, 403),
    ("senior", 200, 200, 403, 200),
    ("admin", 200, 200, 200, 200),
])
def test_role_matrix_is_enforced_by_server(client, service, role, manual, scan, manage, execute):
    user = service.create_account(f"engineer-{role}", PASSWORD, role)
    session = client.post("/api/auth/login", json={"username": user["username"], "password": PASSWORD}).json()
    headers = auth(session["token"])
    me = client.get("/api/auth/me", headers=headers).json()
    assert me["role"] == role
    assert me["authenticated"] is True
    assert client.get("/api/incidents/example", headers=headers).status_code == 200
    result = client.patch("/api/incidents/example", headers=headers)
    assert result.status_code == manual
    if manual == 200:
        assert result.json()["actor"] == user["username"]
        assert result.json()["account_id"] == user["id"]
    assert client.post("/api/sources/example/scan-now", headers=headers).status_code == scan
    assert client.post("/api/sources", headers=headers).status_code == manage
    assert client.post("/api/knowledge/import", headers=headers).status_code == manage
    assert client.post("/api/remediation/example/execute", headers=headers).status_code == execute
    assert client.get("/api/accounts", headers=headers).status_code == manage


def test_sessions_passwords_persist_as_hashes_and_audit_does_not_include_secrets(tmp_path):
    events = []
    path = tmp_path / "accounts.sqlite3"
    service = AccountService(path, audit=lambda *args: events.append(args))
    first = service.bootstrap("administrator", PASSWORD)
    second = service.create_account("engineer", PASSWORD, "junior")
    service.close()
    with sqlite3.connect(path) as database:
        hashes = [row[0] for row in database.execute("SELECT password_hash FROM accounts")]
        token_hash = database.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert len(set(hashes)) == 2
    assert all(value.startswith("scrypt$") and PASSWORD not in value for value in hashes)
    assert token_hash == hashlib.sha256(first["token"].encode()).hexdigest()
    assert first["token"] not in json.dumps(events)
    assert PASSWORD not in json.dumps(events)
    restored = AccountService(path)
    try:
        assert restored.authenticate(first["token"])["role"] == "admin"
        assert restored.login("ENGINEER", PASSWORD)["user"]["id"] == second["id"]
    finally:
        restored.close()


def test_logout_password_change_disable_and_role_change_revoke_existing_sessions(client, service):
    admin = bootstrap(client)
    admin_headers = auth(admin["token"])
    created = client.post("/api/accounts", headers=admin_headers,
                          json={"username": "engineer", "password": PASSWORD, "role": "senior"})
    assert created.status_code == 201
    identifier = created.json()["id"]

    def login(password=PASSWORD):
        response = client.post("/api/auth/login", json={"username": "engineer", "password": password})
        assert response.status_code == 200
        return response.json()["token"]

    token = login()
    assert client.post("/api/auth/logout", headers=auth(token)).status_code == 200
    assert client.get("/api/incidents/example", headers=auth(token)).status_code == 401
    token = login()
    assert client.patch(f"/api/accounts/{identifier}", headers=admin_headers, json={"role": "junior"}).status_code == 200
    assert client.get("/api/auth/me", headers=auth(token)).json()["authenticated"] is False
    token = login()
    assert client.post("/api/remediation/example/execute", headers=auth(token)).status_code == 403
    assert client.patch(f"/api/accounts/{identifier}", headers=admin_headers, json={"password": "changed-password-123"}).status_code == 200
    assert service.authenticate(token) is None
    assert client.post("/api/auth/login", json={"username": "engineer", "password": PASSWORD}).status_code == 401
    token = login("changed-password-123")
    assert client.patch(f"/api/accounts/{identifier}", headers=admin_headers, json={"enabled": False}).status_code == 200
    assert client.patch("/api/incidents/example", headers=auth(token)).status_code == 401
    assert client.post("/api/auth/login", json={"username": "engineer", "password": "changed-password-123"}).status_code == 401


def test_last_administrator_cannot_be_disabled_or_demoted(client, service):
    first = bootstrap(client)
    headers = auth(first["token"])
    identifier = first["user"]["id"]
    for payload in [{"role": "senior"}, {"enabled": False}, {"role": "viewer", "enabled": False}]:
        assert client.patch(f"/api/accounts/{identifier}", headers=headers, json=payload).status_code == 400
        assert service.authenticate(first["token"])["role"] == "admin"
    assert client.post("/api/accounts", headers=headers, json={"username": "backup-admin", "password": PASSWORD, "role": "admin"}).status_code == 201
    assert client.patch(f"/api/accounts/{identifier}", headers=headers, json={"role": "junior"}).status_code == 200
    assert service.authenticate(first["token"]) is None


def test_password_minimum_duplicate_username_and_role_input_are_validated(client):
    assert client.post("/api/auth/bootstrap", json={"username": "administrator", "password": "short"}).status_code == 422
    admin = bootstrap(client)
    headers = auth(admin["token"])
    assert client.post("/api/accounts", headers=headers, json={"username": "Administrator", "password": PASSWORD}).status_code == 400
    assert client.post("/api/accounts", headers=headers, json={"username": "engineer", "password": PASSWORD, "role": "operator"}).status_code == 422
    assert client.patch(f"/api/accounts/{admin['user']['id']}", headers=headers, json={"password": "short"}).status_code == 422


def test_password_boundary_for_bootstrap_creation_and_change(client, service):
    short_password = "12345678"
    minimum_password = "123456789"
    changed_password = "abcdefghi"

    response = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": short_password})
    assert response.status_code == 422
    assert service.bootstrap_available()
    response = client.post("/api/auth/bootstrap", json={"username": "administrator", "password": minimum_password})
    assert response.status_code == 201
    headers = auth(response.json()["token"])
    assert client.post("/api/auth/login", json={"username": "administrator", "password": minimum_password}).status_code == 200

    response = client.post("/api/accounts", headers=headers,
                           json={"username": "engineer", "password": short_password, "role": "junior"})
    assert response.status_code == 422
    assert service.list_accounts()["total"] == 1
    response = client.post("/api/accounts", headers=headers,
                           json={"username": "engineer", "password": minimum_password, "role": "junior"})
    assert response.status_code == 201
    identifier = response.json()["id"]
    session = client.post("/api/auth/login", json={"username": "engineer", "password": minimum_password})
    assert session.status_code == 200
    token = session.json()["token"]

    response = client.patch(f"/api/accounts/{identifier}", headers=headers, json={"password": short_password})
    assert response.status_code == 422
    assert service.authenticate(token) is not None
    assert client.post("/api/auth/login", json={"username": "engineer", "password": minimum_password}).status_code == 200
    response = client.patch(f"/api/accounts/{identifier}", headers=headers, json={"password": changed_password})
    assert response.status_code == 200
    assert service.authenticate(token) is None
    assert client.post("/api/auth/login", json={"username": "engineer", "password": minimum_password}).status_code == 401
    session = client.post("/api/auth/login", json={"username": "engineer", "password": changed_password})
    assert session.status_code == 200
    assert client.get("/api/auth/me", headers=auth(session.json()["token"])).json()["username"] == "engineer"


def test_login_is_rate_limited_by_real_peer_without_trusting_forwarded_headers(client):
    bootstrap(client)
    for attempt in range(8):
        assert client.post("/api/auth/login", json={"username": f"not-found-{attempt}", "password": PASSWORD},
                           headers={"X-Forwarded-For": f"198.51.100.{attempt}"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "administrator", "password": PASSWORD}).status_code == 429


def test_local_fallback_ends_when_personal_accounts_are_initialized(service, monkeypatch):
    for key in ["OPS_API_TOKEN", "OPS_READ_TOKEN", "ALERT_WEBHOOK_TOKEN"]:
        monkeypatch.delenv(key, raising=False)
    client = make_client(service)
    assert client.get("/api/auth/me").json()["role"] == "operator"
    assert client.patch("/api/incidents/example").status_code == 200
    admin = bootstrap(client)
    assert client.get("/api/auth/me").json()["role"] == "guest"
    assert client.patch("/api/incidents/example").status_code == 401
    assert client.patch("/api/incidents/example", headers=auth("invalid-session")).status_code == 401
    viewer = service.create_account("viewer-account", PASSWORD, "viewer")
    session = service.login(viewer["username"], PASSWORD)
    assert client.patch("/api/incidents/example", headers=auth(session["token"])).status_code == 403
    assert client.patch("/api/incidents/example").status_code == 401
    assert client.get("/api/accounts", headers=auth(admin["token"])).status_code == 200


def test_login_and_bootstrap_reject_extra_role_fields(client):
    assert client.post("/api/auth/bootstrap", json={"username": "administrator", "password": PASSWORD, "role": "admin"}).status_code == 422
    bootstrap(client)
    assert client.post("/api/auth/login", json={"username": "administrator", "password": PASSWORD, "role": "admin"}).status_code == 422


def test_expired_session_does_not_authorize(client, service, monkeypatch):
    admin = bootstrap(client)
    monkeypatch.setattr("app.accounts.time.time", lambda: 10**12)
    assert service.authenticate(admin["token"]) is None
    assert client.get("/api/accounts", headers=auth(admin["token"])).status_code == 401


def test_concurrent_bootstrap_allows_only_one_administrator(tmp_path):
    first = AccountService(tmp_path / "accounts.sqlite3")
    second = AccountService(tmp_path / "accounts.sqlite3")

    def run(service, username):
        try:
            return service.bootstrap(username, PASSWORD)["user"]["username"]
        except ValueError:
            return None

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run, first, "administrator-one"), executor.submit(run, second, "administrator-two")]
            results = [future.result() for future in futures]
        assert sum(value is not None for value in results) == 1
        assert first.list_accounts()["total"] == 1
    finally:
        first.close()
        second.close()


def test_cli_bootstrap_uses_password_prompt_and_never_outputs_or_stores_raw_session(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPS_DATA_PATH", str(tmp_path))
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    assert main(["bootstrap", "--username", "administrator"]) == 0
    output = capsys.readouterr().out
    assert "initialized" in output
    assert PASSWORD not in output
    with sqlite3.connect(tmp_path / "accounts.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
        assert database.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert main(["bootstrap", "--username", "other-administrator"]) == 1


def test_cli_bootstrap_rejects_unconfirmed_password(tmp_path, monkeypatch, capsys):
    answers = iter([PASSWORD, "different-password"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    assert main(["bootstrap", "--username", "administrator", "--data-path", str(tmp_path)]) == 1
    service = AccountService(tmp_path / "accounts.sqlite3")
    try:
        assert service.bootstrap_available()
    finally:
        service.close()
    assert PASSWORD not in capsys.readouterr().out
