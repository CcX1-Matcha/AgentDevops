import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from backend.app.rag import KnowledgeBase, default_kb_path, tokenize
from backend.app.knowledge import KnowledgeStore


def test_default_kb_is_discoverable_and_has_all_sources():
    kb = KnowledgeBase()
    assert default_kb_path().exists()
    assert {doc["source"] for doc in kb.documents} == {"server", "nginx", "docker", "kubernetes"}


def test_nginx_connection_refused_ranks_before_unrelated_entries():
    result = KnowledgeBase().search("nginx upstream connect() failed 111 Connection refused 502")
    assert result
    assert result[0]["id"] == "nginx-upstream-refused"
    assert "ECONNREFUSED" in result[0]["tags"]
    assert "refused" in result[0]["matched_terms"]


def test_docker_oom_can_be_filtered_by_source():
    result = KnowledgeBase().search("Memory cgroup out of memory OOMKilled exit 137", source="docker")
    assert result
    assert result[0]["id"] == "docker-oom-killed"
    assert all(item["source"] == "docker" for item in result)


def test_no_overlap_returns_no_false_positive():
    assert KnowledgeBase().search("routine release completed with no errors") == []


def test_chinese_query_matches_disk_incident():
    result = KnowledgeBase().search("磁盘空间不足 ENOSPC")
    assert result
    assert result[0]["id"] in {"server-disk-full", "docker-storage-full"}


def test_json_is_valid_and_every_record_has_diagnostic_contract():
    payload = json.loads(default_kb_path().read_text(encoding="utf-8"))
    assert len(payload) >= 10
    required = {"id", "title", "source", "root_cause", "steps", "commands", "tags", "symptoms"}
    assert all(required <= set(item) for item in payload)


def test_tokenizer_keeps_canonical_ascii_terms_and_chinese_bigrams():
    tokens = tokenize("ENOSPC 磁盘空间不足")
    assert "enospc" in tokens
    assert "磁盘" in tokens
    assert "空间" in tokens


def test_agent_knowledge_store_uses_structured_incident_kb():
    result = KnowledgeStore().search("connect() failed connection refused upstream 502", limit=1)
    assert result
    assert result[0].id == "nginx-upstream-refused"


def test_kubernetes_incidents_are_structured_and_retrievable():
    kb = KnowledgeBase()
    expected = {
        "CrashLoopBackOff Back-off restarting failed container": "kubernetes-crash-loop",
        "ErrImagePull ImagePullBackOff manifest unknown": "kubernetes-image-pull",
        "Pending FailedScheduling Insufficient memory": "kubernetes-scheduling-failed",
        "Readiness probe failed Liveness probe failed HTTP 503": "kubernetes-probe-failed",
        "OOMKilled Exit Code 137 memory limit": "kubernetes-oom-killed",
        "Ingress 503 no endpoints available for service": "kubernetes-service-unavailable",
    }
    for query, identifier in expected.items():
        result = kb.search(query, source="kubernetes", limit=1)
        assert result, query
        assert result[0]["id"] == identifier


def test_kubernetes_records_keep_failure_type_contract():
    payload = json.loads(default_kb_path().read_text(encoding="utf-8"))
    records = [item for item in payload if item["source"] == "kubernetes"]
    assert {item["id"] for item in records} >= {
        "kubernetes-crash-loop",
        "kubernetes-image-pull",
        "kubernetes-scheduling-failed",
        "kubernetes-probe-failed",
        "kubernetes-oom-killed",
        "kubernetes-service-unavailable",
    }
    assert all(item.get("failure_types") for item in records)
