from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parser import parse_logs


client = TestClient(app)
EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


@pytest.mark.parametrize(
    "filename,failure_type,knowledge_id",
    [
        ("crash_loop", "k8s_crash_loop", "kubernetes-crash-loop"),
        ("image_pull", "k8s_image_pull", "kubernetes-image-pull"),
        ("scheduling", "k8s_scheduling_failure", "kubernetes-scheduling-failed"),
        ("probe_failure", "k8s_probe_failure", "kubernetes-probe-failed"),
        ("oom_killed", "k8s_oom", "kubernetes-oom-killed"),
        ("service_unavailable", "k8s_service_unavailable", "kubernetes-service-unavailable"),
    ],
)
def test_kubernetes_examples_complete_the_diagnosis_pipeline(filename, failure_type, knowledge_id):
    logs = (EXAMPLES / f"kubernetes_{filename}.log").read_text(encoding="utf-8")
    response = client.post("/api/diagnose", json={"logs": logs})
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "kubernetes"
    assert body["failure_type"] == failure_type
    assert body["knowledge"][0]["id"] == knowledge_id
    assert all(item["category"] == "kubernetes" for item in body["knowledge"])
    assert body["steps"] and any("kubectl" in (step["command"] or "") for step in body["steps"])


@pytest.mark.parametrize(
    "logs",
    [
        'Normal Pulling 5s kubelet Pulling image "nginx:1.27"',
        'Normal Pulled 4s kubelet Successfully pulled image "nginx:1.27"',
        "kubelet INFO 5 nodes are available",
    ],
)
def test_normal_kubernetes_events_are_not_diagnosed_as_failures(logs):
    response = client.post("/api/diagnose", json={"source": "kubernetes", "logs": logs})
    assert response.status_code == 200
    body = response.json()
    assert body["failure_type"] == "normal"
    assert body["metrics"]["error_count"] == 0


@pytest.mark.parametrize("flag", [True, False])
def test_docker_inspect_oom_flag_does_not_change_to_kubernetes(flag):
    import json

    item = parse_logs(json.dumps({"State": {"OOMKilled": flag, "ExitCode": 0}}))[0]
    assert item.source == "docker"
    assert item.failure_type == ("out_of_memory" if flag else "normal")


@pytest.mark.parametrize("source", ["nginx", "app"])
def test_service_unavailable_alone_is_not_a_kubernetes_marker(source):
    item = parse_logs(f"2026-09-30T09:00:00Z {source} ERROR Service unavailable")[0]
    assert item.source != "kubernetes"


def test_console_kubernetes_sample_is_present():
    assert client.get("/examples/kubernetes_crash_loop.log").status_code == 200
    response = client.get("/")
    assert 'value="kubernetes"' in response.text
    assert 'data-example="kubernetes_crash_loop.log"' in response.text
