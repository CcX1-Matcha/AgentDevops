import asyncio
import json
import httpx
import pytest

from app.context import ContextCollector
from app.knowledge import KnowledgeStore
from app.rag import KnowledgeBase


def test_unconfigured_context_never_claims_healthy(monkeypatch):
    monkeypatch.delenv("CONTEXT_CONFIG_PATH", raising=False)
    result = asyncio.run(ContextCollector().collect({"service": "orders"}))
    assert {item["kind"] for item in result["context_sources"]} == {"metrics", "logs", "changes", "topology"}
    assert all(item["status"] == "not_configured" and item["data"] is None for item in result["context_sources"])
    assert result["logs"] == ""
    assert "无法验证" in result["context_text"]


def test_unresolved_alert_end_time_sentinel_has_bounded_window(monkeypatch):
    monkeypatch.delenv("CONTEXT_CONFIG_PATH", raising=False)
    result = asyncio.run(ContextCollector().collect({"starts_at": "2026-01-01T00:00:00Z", "ends_at": "0001-01-01T00:00:00Z"}))
    from datetime import datetime
    start = datetime.fromisoformat(result["start_time"])
    end = datetime.fromisoformat(result["end_time"])
    assert 0 < (end - start).total_seconds() <= 6 * 3600


def test_connector_parallel_collection_and_safe_identity():
    async def run():
        seen = []
        all_started = asyncio.Event()

        async def handler(request):
            seen.append(request)
            if len(seen) == 4:
                all_started.set()
            await asyncio.wait_for(all_started.wait(), timeout=1)
            if request.url.host == "metrics.internal":
                return httpx.Response(200, json={"status": "success", "data": {"resultType": "vector", "result": [{"metric": {"service": "orders"}, "value": [100, "95"]}]}})
            if request.url.host == "logs.internal":
                return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": [{"stream": {"service": "orders"}, "values": [["1000000000", "ERROR Too many connections"]]}]}})
            return httpx.Response(200, json={"items": [{"service": "orders", "version": "v2"}]})

        configs = [
            {"name": "Prometheus", "kind": "prometheus", "url": "http://metrics.internal", "query": 'cpu_usage{service="{service}",instance="{instance}"}'},
            {"name": "Loki", "kind": "loki", "url": "http://logs.internal", "query": '{service="{service}"} |= "ERROR"'},
            {"name": "Release API", "kind": "changes", "url": "http://releases.internal/changes"},
            {"name": "CMDB", "kind": "topology", "url": "http://cmdb.internal/topology"},
        ]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            event = {"service": 'orders"} or vector(1) #', "instance": 'node\\a\n"', "url": "http://untrusted.invalid", "starts_at": "2026-01-01T00:00:00Z", "ends_at": "2026-01-01T00:01:00Z"}
            result = await ContextCollector(configs=configs, client=client).collect(event)
        assert len(seen) == 4 and all(request.method == "GET" for request in seen)
        assert all(item["status"] == "ok" for item in result["context_sources"])
        metrics_request = next(request for request in seen if request.url.host == "metrics.internal")
        assert metrics_request.url.path == "/api/v1/query"
        assert metrics_request.url.params["query"] == 'cpu_usage{service="orders\\\"} or vector(1) #",instance="node\\\\a\\n\\\""}'
        logs_request = next(request for request in seen if request.url.host == "logs.internal")
        assert logs_request.url.path == "/loki/api/v1/query_range"
        assert int(logs_request.url.params["end"]) - int(logs_request.url.params["start"]) <= 6 * 3600 * 1_000_000_000
        assert result["logs"] == "ERROR Too many connections"
        assert "Release API" in result["context_text"]
        assert not any(request.url.host == "untrusted.invalid" for request in seen)
    asyncio.run(run())


@pytest.mark.parametrize("status,payload", [(503, {}), (200, {"status": "error", "error": "unavailable"}), (200, {"status": "success", "data": {"result": "wrong"}})])
def test_context_query_failure_does_not_become_normal(status, payload):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(status, json=payload))) as client:
            result = await ContextCollector(configs=[{"name": "Metrics", "kind": "prometheus", "url": "http://metrics.internal", "query": "up"}], client=client).collect({})
        source = result["context_sources"][0]
        assert source["status"] == "failed" and source["data"] is None and source["error"]
        assert "无法判断" in source["summary"]
    asyncio.run(run())


def test_oversized_response_is_failed():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=json.dumps({"large": "x" * 300_000})))) as client:
            result = await ContextCollector(configs=[{"name": "Changes", "kind": "changes", "url": "http://releases.internal"}], client=client).collect({})
        assert result["context_sources"][0]["status"] == "failed"
    asyncio.run(run())


def test_config_path_and_invalid_config_are_visible(tmp_path):
    config = tmp_path / "context.json"
    config.write_text('{"connectors": [], "window_minutes": 30}', encoding="utf-8")
    collector = ContextCollector(config)
    result = asyncio.run(collector.collect({}))
    assert collector.window_minutes == 30
    assert len(result["context_sources"]) == 4
    config.write_text("invalid json", encoding="utf-8")
    result = asyncio.run(ContextCollector(config).collect({}))
    assert any(item["kind"] == "configuration" and item["status"] == "failed" for item in result["context_sources"])


def test_connector_redirect_is_not_followed():
    async def run():
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(302, headers={"Location": "http://unconfigured.invalid"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
            result = await ContextCollector(configs=[{"kind": "changes", "url": "http://changes.internal"}], client=client).collect({})
        assert len(requests) == 1 and result["context_sources"][0]["status"] == "failed"
    asyncio.run(run())


def test_knowledge_provenance_steps_and_metadata_filters():
    store = KnowledgeStore()
    match = store.search("Too many connections", "database_connection_exhausted", source="server", limit=1)[0]
    assert match.id == "server-database-connections"
    assert match.steps and match.commands
    assert match.source_urls and all(url.startswith("https://") for url in match.source_urls)
    assert match.updated_at == "2026-10-01" and match.trust_level == "curated_runbook"
    kb = KnowledgeBase(documents=[
        {"id": "a", "source": "server", "root_cause": "disk full", "metadata": {"environment": "production"}},
        {"id": "b", "source": "server", "root_cause": "disk full", "metadata": {"environment": "staging"}},
    ])
    assert [item["id"] for item in kb.search("disk", metadata_filters={"environment": "production"})] == ["a"]
    assert kb.search("disk", metadata_filters={"environment": "missing"}) == []


@pytest.mark.parametrize("query,identifier", [
    ("CPU throttling detected", "server-cpu-saturation"),
    ("canceling statement due to statement timeout", "server-database-slow-query"),
    ("x509 certificate has expired or is not yet valid", "server-tls-certificate"),
    ("consumer lag exceeds threshold", "server-queue-backlog"),
])
def test_high_frequency_runbooks_are_retrievable(query, identifier):
    assert KnowledgeStore().search(query, source="server", limit=1)[0].id == identifier
