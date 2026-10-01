"""Contract tests for the bounded, tool-only LLM ReAct agent."""
from __future__ import annotations

import json

import httpx
import pytest

from app.llm import (
    LLMIterationLimitError,
    LLMProtocolError,
    LLMReActAgent,
    LLMSettings,
)


def tool_response(name: str, arguments: dict, call_id: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"role": "assistant", "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}]}}]
        },
    )


def diagnosis_finish(knowledge_id: str = "nginx-upstream-refused", line: int = 1) -> dict:
    return {
        "summary": "Nginx 502",
        "root_cause": "上游应用未监听目标端口",
        "failure_type": "upstream_unavailable",
        "confidence": 0.91,
        "severity": "error",
        "evidence_refs": [{"line_number": line}],
        "knowledge_refs": [knowledge_id],
        "steps": [{"title": "检查上游", "description": "确认进程和端口健康", "verification": "健康检查返回 2xx", "knowledge_refs": [knowledge_id]}],
    }


def agent_for(responses: list[httpx.Response], **overrides) -> LLMReActAgent:
    def handler(_request: httpx.Request) -> httpx.Response:
        if not responses:
            return httpx.Response(500, json={"error": "unexpected extra request"})
        return responses.pop(0)

    settings = LLMSettings(mode="llm", base_url="http://mock/v1", api_key="test", **overrides)
    return LLMReActAgent(settings, transport=httpx.MockTransport(handler))


def test_normal_react_loop_uses_parser_retrieval_and_validated_finish():
    responses = [
        tool_response("parse_logs", {"source": "nginx"}, "p"),
        tool_response("retrieve_knowledge", {"query": "502 upstream connection refused", "limit": 3}, "r"),
        tool_response("finish", diagnosis_finish(), "f"),
    ]
    agent = agent_for(responses)
    result = agent.diagnose("2026-09-29T12:00:00Z [error] connection refused while connecting to upstream", "nginx")
    assert result.mode == "llm"
    assert result.failure_type == "upstream_unavailable"
    assert result.evidence[0].line_number == 1
    assert result.knowledge[0].id == "nginx-upstream-refused"
    assert [event.action for event in result.trace] == ["parse_logs", "retrieve_knowledge", "finish"]


def test_kubernetes_alias_survives_the_llm_tool_loop():
    payload = diagnosis_finish("kubernetes-crash-loop")
    payload.update(
        summary="Pod CrashLoopBackOff",
        root_cause="容器反复退出，需要检查上一次容器日志确认具体原因。",
        failure_type="k8s_crash_loop",
    )
    responses = [
        tool_response("parse_logs", {"source": "k8s"}, "p"),
        tool_response("retrieve_knowledge", {"query": "CrashLoopBackOff", "source": "k8s"}, "r"),
        tool_response("finish", payload, "f"),
    ]
    with agent_for(responses) as agent:
        result = agent.diagnose("Warning BackOff kubelet: CrashLoopBackOff in pod orders-api", "k8s")
    assert result.source == "kubernetes"
    assert result.evidence[0].source == "kubernetes"
    assert result.failure_type == "k8s_crash_loop"
    assert result.knowledge[0].id == "kubernetes-crash-loop"


def test_no_tool_call_is_invalid_and_never_marked_completed():
    responses = [httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "I think it is an outage."}}]})]
    agent = agent_for(responses)
    with pytest.raises(LLMProtocolError, match="no tool call"):
        agent.diagnose("2026-09-29T12:00:00Z ERROR failure")


def test_loop_limit_is_explicit_when_model_never_finishes():
    responses = [tool_response("parse_logs", {"source": "server"}, "p1"), tool_response("retrieve_knowledge", {"query": "error"}, "r1")]
    agent = agent_for(responses, max_iterations=2)
    # A repeated retrieve call cannot finish and reaches the hard iteration cap.
    responses.append(tool_response("retrieve_knowledge", {"query": "error"}, "r2"))
    with pytest.raises((LLMIterationLimitError, LLMProtocolError)):
        agent.diagnose("Sep 29 12:00:00 host kernel: ERROR failure")


def test_unknown_tool_and_forged_references_are_rejected():
    unknown = agent_for([tool_response("run_shell", {"command": "rm -rf /"}, "x")])
    with pytest.raises(LLMProtocolError, match="unknown tool"):
        unknown.diagnose("2026-09-29T12:00:00Z ERROR failure")

    forged_responses = [
        tool_response("parse_logs", {"source": "nginx"}, "p"),
        tool_response("retrieve_knowledge", {"query": "502 upstream", "limit": 1}, "r"),
        tool_response("finish", diagnosis_finish(knowledge_id="forged-id", line=999), "f"),
    ]
    forged = agent_for(forged_responses)
    with pytest.raises(LLMProtocolError, match="unknown evidence line|knowledge not returned"):
        forged.diagnose("2026-09-29T12:00:00Z [error] connection refused upstream", "nginx")


def test_local_llm_endpoint_does_not_require_api_key(monkeypatch):
    monkeypatch.setenv("LLM_MODE", "llm")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    settings = LLMSettings.from_env()
    assert settings.api_key is None


def test_automatic_llm_incident_inspects_context_and_preserves_gaps():
    payload = diagnosis_finish()
    payload["steps"][0]["command"] = "kubectl run netcheck --image=curlimages/curl"
    responses = [tool_response("parse_logs", {"source": "nginx"}, "p"),
                 tool_response("collect_context", {"hypothesis": "上游资源或变更异常"}, "c"),
                 tool_response("retrieve_knowledge", {"query": "connection refused upstream"}, "r"),
                 tool_response("finish", payload, "f")]
    with agent_for(responses) as agent:
        result = agent.diagnose("nginx [error] connection refused upstream", "nginx", observations={
            "context_sources": [{"name": "Prometheus", "status": "failed", "error": "timeout"}]})
    assert "Prometheus（failed）" in result.missing_information
    assert result.steps[0].risk == "manual"
    assert result.steps[0].knowledge_refs == ["nginx-upstream-refused"]
    assert any(item.action == "collect_context" for item in result.trace)


def test_llm_cannot_skip_supplied_incident_context():
    responses = [tool_response("parse_logs", {"source": "nginx"}, "p"),
                 tool_response("retrieve_knowledge", {"query": "connection refused upstream"}, "r"),
                 tool_response("finish", diagnosis_finish(), "f")]
    with agent_for(responses) as agent, pytest.raises(LLMProtocolError, match="collect_context"):
        agent.diagnose("nginx [error] connection refused upstream", "nginx", observations={"context_sources": []})
