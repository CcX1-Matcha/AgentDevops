"""Diagnosis must retain evidence gaps, citations and manual execution boundaries."""
from app.agent import ReActAgent
from app.command_policy import command_risk


def test_duplicate_errors_do_not_inflate_confidence_and_context_gaps_are_visible():
    agent = ReActAgent()
    agent.mode = "local"
    line = "nginx [error] connect() failed (111: Connection refused) while connecting to upstream"
    single = agent.diagnose(line, "nginx")
    repeated = agent.diagnose("\n".join([line] * 20), "nginx", observations={"context_sources": [
        {"name": "Prometheus", "status": "failed"}, {"name": "Changes", "status": "not_configured"}]})
    assert single.confidence == repeated.confidence
    assert any("Prometheus" in item for item in repeated.missing_information)
    assert repeated.impact_scope["affected_users"] is None
    assert any(item.action == "collect_context" for item in repeated.trace)
    assert repeated.steps and all(step.execution == "advice_only" for step in repeated.steps)
    assert all(set(step.knowledge_refs) <= {item.id for item in repeated.knowledge} for step in repeated.steps)


def test_unknown_failure_is_not_reported_as_high_confidence():
    agent = ReActAgent()
    agent.mode = "local"
    result = agent.diagnose("server ERROR zzz unfamiliar operation failed", "server")
    assert result.failure_type == "unknown_error"
    assert result.confidence <= 0.4
    assert result.missing_information and result.boundary


def test_commands_that_mutate_or_embed_shell_actions_require_manual_review():
    assert command_risk("kubectl get pod <pod> -n <namespace>") == "read_only"
    assert command_risk("df -h && df -i") == "read_only"
    for command in ["docker pull <image>", "kubectl run netcheck --image=curlimages/curl", "df -h; rm -rf /data",
                    "df -h > /tmp/state", "ps $(touch /tmp/changed)", "systemctl restart nginx", None]:
        assert command_risk(command) == "manual"
