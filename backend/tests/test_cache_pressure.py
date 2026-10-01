"""Managed cache pressure stays precise and cannot demote higher-risk evidence."""
import pytest

from app.agent import ReActAgent
from app.command_policy import command_risk
from app.parser import parse_logs


CACHE = "managed temporary cache usage above baseline"
KNOWLEDGE_ID = "server-managed-cache-pressure"


@pytest.mark.parametrize("message", [
    f"server WARNING {CACHE}",
    CACHE,
    "WARNING MANAGED TEMPORARY CACHE USAGE ABOVE BASELINE",
    "WARNING 托管可重建临时缓存使用量超过基线",
    "托管的可重建缓存压力升高",
])
def test_cache_pattern_requires_managed_rebuildable_temporary_semantics(message):
    parsed = parse_logs(message)[0]
    assert parsed.source == "server"
    assert parsed.failure_type == "managed_cache_pressure"
    assert parsed.severity == "warning"


@pytest.mark.parametrize("message", [
    "WARNING temporary cache usage above baseline",
    "WARNING managed persistent cache usage above baseline",
    "WARNING cache usage high",
    "WARNING 临时缓存压力过高",
    "WARNING 托管缓存压力升高",
    "WARNING 可重建缓存压力升高",
])
def test_generic_cache_words_do_not_enable_managed_cache_type(message):
    assert parse_logs(message, "server")[0].failure_type == "degraded_service"


@pytest.mark.parametrize("suffix,severity,failure_type", [
    ("kernel OOMKilled", "critical", "out_of_memory"),
    ("out of memory", "critical", "out_of_memory"),
    ("No space left on device", "critical", "disk_full"),
    ("disk full", "critical", "disk_full"),
    ("read-only file system", "critical", "disk_full"),
    ("ERROR", "error", "unknown_error"),
    ("CRITICAL", "critical", "unknown_critical"),
])
def test_cache_hint_never_downgrades_errors_or_resource_exhaustion(suffix, severity, failure_type):
    parsed = parse_logs(f"{CACHE} {suffix}", "server")[0]
    assert parsed.failure_type == failure_type
    assert parsed.severity == severity


@pytest.mark.parametrize("danger,expected", [
    ("CRITICAL kernel Out of memory: Killed process", "out_of_memory"),
    ("ERROR No space left on device", "disk_full"),
    ("ERROR application failure", "unknown_error"),
])
def test_repeated_cache_warnings_cannot_outvote_dangerous_agent_evidence(danger, expected):
    agent = ReActAgent()
    agent.mode = "local"
    result = agent.diagnose("\n".join([f"WARNING {CACHE}"] * 5 + [danger]), "server")
    assert result.failure_type == expected
    assert result.severity in {"error", "critical"}
    assert result.evidence[0].message == danger


def test_cache_rag_returns_matching_runbook_and_only_read_only_command_advice():
    agent = ReActAgent()
    agent.mode = "local"
    result = agent.diagnose(f"server WARNING {CACHE}", "server")
    assert result.failure_type == "managed_cache_pressure"
    assert result.severity == "warning"
    assert result.knowledge[0].id == KNOWLEDGE_ID
    assert all(match.id != "server-queue-backlog" for match in result.knowledge)
    assert "托管" in result.root_cause
    assert "没有全磁盘或 inode 耗尽证据" in result.root_cause
    assert "消息生产速率" not in result.root_cause
    assert result.evidence[0].message == f"server WARNING {CACHE}"
    assert any("保留策略" in step.description and "回滚" in step.description for step in result.steps)
    commands = [step.command for step in result.steps if step.command]
    assert commands
    assert all(command_risk(command) == "read_only" for command in commands)
    assert all(step.execution == "advice_only" for step in result.steps)
    assert all(not any(word in command for word in ("rm ", "unlink", "truncate", "delete")) for command in commands)


def test_resolved_cache_pressure_is_not_a_new_fault():
    assert parse_logs(f"INFO {CACHE} recovered", "server")[0].failure_type == "normal"
