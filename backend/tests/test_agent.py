from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_nginx_connection_refused_diagnosis():
    response = client.post("/api/diagnose", json={"source": "nginx", "logs": "2026-09-29T12:00:00Z [error] connect() failed (111: Connection refused) while connecting to upstream"})
    assert response.status_code == 200
    body = response.json()
    assert body["failure_type"] == "upstream_unavailable"
    assert body["source"] == "nginx"
    assert body["knowledge"][0]["id"] == "nginx-upstream-refused"
    assert any(event["action"] == "retrieve_knowledge" for event in body["trace"])


def test_auto_detects_oom_and_has_steps():
    response = client.post("/api/diagnose", json={"logs": "Sep 29 12:01:01 host kernel: Out of memory: Killed process 42 (java)"})
    assert response.status_code == 200
    body = response.json()
    assert body["failure_type"] == "out_of_memory"
    assert body["steps"][0]["command"].startswith("dmesg")


def test_nginx_504_is_classified_as_request_timeout():
    response = client.post(
        "/api/diagnose",
        json={
            "source": "nginx",
            "logs": "2026-09-29T12:00:00Z [error] upstream timed out (110: Connection timed out) while reading response header from upstream",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["failure_type"] == "request_timeout"
    assert body["knowledge"][0]["id"] == "nginx-upstream-timeout"


def test_docker_image_pull_failure_uses_dependency_diagnosis():
    response = client.post(
        "/api/diagnose",
        json={
            "source": "docker",
            "logs": "2026-09-29T12:00:00Z docker: pull access denied for registry.example/orders-api, repository does not exist",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["failure_type"] == "missing_dependency"
    assert body["knowledge"][0]["id"] == "docker-image-pull-failed"


def test_ssh_auth_failures_are_reported_as_a_security_signal():
    response = client.post(
        "/api/diagnose",
        json={
            "logs": "Sep 29 13:22:01 sre-node-01 sshd[24111]: Failed password for invalid user deploy from 198.51.100.7 port 42318 ssh2",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["failure_type"] == "authentication_failure"
    assert body["knowledge"][0]["id"] == "server-ssh-auth-failure"


def test_kubernetes_crash_loop_is_detected_from_kubelet_events():
    response = client.post(
        "/api/diagnose",
        json={
            "source": "k8s",
            "logs": "2026-09-30T09:01:12Z kubelet: Warning BackOff restarting failed container api in pod orders-api\nReason: CrashLoopBackOff",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "kubernetes"
    assert body["failure_type"] == "k8s_crash_loop"
    assert body["knowledge"][0]["id"] == "kubernetes-crash-loop"


def test_kubernetes_image_pull_failure_is_detected_automatically():
    response = client.post(
        "/api/diagnose",
        json={
            "logs": "2026-09-30T09:05:03Z kubelet: Warning Failed pod/payments-api: Failed to pull image registry.example/api:v4: manifest unknown\nStatus: ImagePullBackOff",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "kubernetes"
    assert body["failure_type"] == "k8s_image_pull"
    assert body["knowledge"][0]["id"] == "kubernetes-image-pull"


def test_blank_logs_rejected():
    assert client.post("/api/diagnose", json={"logs": "   "}).status_code == 422
