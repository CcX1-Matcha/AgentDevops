"""Parse common Linux, Nginx, Docker and Kubernetes diagnostic output."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass

from .models import Evidence


_LEVEL = re.compile(r"\b(?P<level>CRITICAL|FATAL|ERROR|ERR|WARN(?:ING)?|NOTICE|INFO|DEBUG)\b", re.I)
_NGINX = re.compile(r"\s(?P<status>[1-5]\d\d)\s")
_DOCKER = re.compile(r"(?:docker|container(?:d)?)[^:]*:\s*", re.I)
_KUBERNETES = re.compile(
    r"(?:kubernetes|kubelet|kubectl|crashloopbackoff|imagepullbackoff|errimagepull|"
    r"failedscheduling|readiness probe|liveness probe|startup probe|"
    r"back-off restarting failed container|\breason:\s*oomkilled\b|pod/[a-z0-9]|pod\s+\S+|"
    r"deployment\.apps|statefulset\.apps|replicaset\.apps|serviceaccount|kube-proxy|"
    r"0/\d+ nodes? are available|no endpoints available|endpointslice|"
    r"no active endpoints|has no endpoints|ingress|"
    r"^\s*(?:namespace|endpoints):)",
    re.I,
)
_TIMESTAMP = re.compile(r"^(?:\[[^]]+\]|\d{4}-\d\d-\d\d[T ][^ ]+|\w{3}\s+\d+\s+\d\d:\d\d:\d\d)")

_SOURCE_ALIASES = {"k8s": "kubernetes", "kubernetes": "kubernetes"}

_EXTENDED_PATTERNS = (
    ("database_connection_exhausted", re.compile(r"too many connections|remaining connection slots are reserved|sorry, too many clients already|connection pool (?:is )?exhausted|connection is not available, request timed out|数据库连接(?:数)?(?:耗尽|打满)|连接池耗尽", re.I)),
    ("database_slow_query", re.compile(r"slow query (?:detected|threshold exceeded|took)|canceling statement due to statement timeout|lock wait timeout exceeded|deadlock detected|数据库慢查询(?:告警|超时)|锁等待超时", re.I)),
    ("certificate_error", re.compile(r"certificate (?:has expired|is expired|is not yet valid|verify failed)|cert_has_expired|unable to get local issuer certificate|ssl_do_handshake\(\) failed|cannot load certificate|pem_read_bio_x509_aux\(\) failed|key values mismatch|证书(?:已过期|过期|验证失败|链不完整)", re.I)),
    ("cpu_saturation", re.compile(r"\bhigh cpu (?:usage|utilization)\b|\bcpu (?:usage|utilization) (?:is )?(?:high|exceeds? threshold)\b|\bcpu (?:saturation|saturated)\b|\bcpu throttling (?:detected|high|exceeds? threshold)\b|cpu\s*(?:使用率过高|持续饱和|资源耗尽|节流严重)", re.I)),
    ("message_queue_backlog", re.compile(r"\bconsumer lag (?:exceeds? threshold|high|is high|too high|increasing|above threshold)\b|\b(?:queue|message) backlog (?:detected|high|exceeds? threshold|increasing)\b|\bmessages_(?:ready|unacknowledged) increasing\b|消息积压(?:告警|过高|严重|增长|超过)|消费滞后(?:告警|严重|超过)", re.I)),
)
_CPU_VALUE = re.compile(r"\bcpu (?:usage|utilization)\s*[=:]?\s*(\d+(?:\.\d+)?)\s*%", re.I)
_QUERY_TIME = re.compile(r"\bquery_time:\s*(\d+(?:\.\d+)?)", re.I)
_POSTGRES_DURATION = re.compile(r"\bduration:\s*(\d+(?:\.\d+)?)\s*ms\s+statement:", re.I)
_RECOVERY = re.compile(r"\b(?:resolved|recovered|back to normal|not detected)\b|已恢复|已解除", re.I)
_SQL_CONFIGURATION = re.compile(r"\bstatement_timeout\s*=|\b(?:query|statement) timeout (?:configured|set|enabled)\b", re.I)
_EXTENDED_ALERT = re.compile(r"\b(?:CPUHigh|HighCPUUsage|CPUThrottlingHigh|ConsumerLagHigh|QueueBacklogHigh)\b", re.I)


def _extended_failure(line: str) -> str | None:
    for kind, pattern in _EXTENDED_PATTERNS:
        if pattern.search(line):
            return kind
    cpu_value = _CPU_VALUE.search(line)
    if cpu_value and 90 <= float(cpu_value.group(1)) <= 100:
        return "cpu_saturation"
    query_time = _QUERY_TIME.search(line)
    duration = _POSTGRES_DURATION.search(line)
    if (query_time and float(query_time.group(1)) >= 1) or (duration and float(duration.group(1)) >= 1000):
        return "database_slow_query"
    alert = _EXTENDED_ALERT.search(line)
    if alert and re.search(r"\bfiring\b", line, re.I):
        return "message_queue_backlog" if alert.group().lower() in {"consumerlaghigh", "queuebackloghigh"} else "cpu_saturation"
    return None


def _docker_state(line: str) -> dict | None:
    if not line.startswith("{"):
        return None
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(value, dict) and isinstance(value.get("State"), dict):
        return value["State"]
    return None


@dataclass(frozen=True)
class ParsedLog:
    line_number: int
    message: str
    severity: str
    source: str
    failure_type: str


def normalize_source(source: str) -> str:
    """Return the canonical source name used in responses and KB filters."""
    return _SOURCE_ALIASES.get(source.strip().lower(), source.strip().lower())


def detect_source(line: str) -> str:
    low = line.lower()
    if _docker_state(line) is not None:
        return "docker"
    if _KUBERNETES.search(line):
        return "kubernetes"
    if _QUERY_TIME.search(line) or _POSTGRES_DURATION.search(line):
        return "server"
    if "nginx" in low or "upstream" in low or "上游" in line or _NGINX.search(line):
        return "nginx"
    if "docker" in low or "containerd" in low or "container=" in low or "container " in low or "oomkilled" in low:
        return "docker"
    if _TIMESTAMP.search(line) or any(word in low for word in ("kernel", "systemd", "oom", "segfault", "journal")):
        return "server"
    if _extended_failure(line):
        return "server"
    return "unknown"


def classify(line: str, source: str) -> tuple[str, str]:
    low = line.lower()
    source = normalize_source(source)
    match = _LEVEL.search(line)
    level = match.group("level").lower() if match else ""
    status = _NGINX.search(line)
    if source == "nginx" and status and status.group("status").startswith("5"):
        level = "error"
    state = _docker_state(line)
    if state is not None:
        if state.get("OOMKilled") is True:
            return "critical", "out_of_memory"
        if state.get("Error") or state.get("ExitCode", 0) != 0:
            return "error", "application_crash"
        return "info", "normal"
    if source == "kubernetes":
        if any(x in low for x in ("oomkilled", "memory cgroup out of memory", "reason: oomkilled", "container killed due to out of memory")):
            return "critical", "k8s_oom"
        if any(x in low for x in ("imagepullbackoff", "errimagepull", "failed to pull image", "back-off pulling image")):
            return "error", "k8s_image_pull"
        if re.search(r"\b0/\d+ nodes? are available", low) or any(x in low for x in ("failedscheduling", "failed scheduling", "insufficient cpu", "insufficient memory", "no nodes available")):
            return "error", "k8s_scheduling_failure"
        if any(x in low for x in ("readiness probe failed", "liveness probe failed", "startup probe failed", "probe failed", "http probe failed")):
            return "error", "k8s_probe_failure"
        if any(x in low for x in ("crashloopbackoff", "restarting failed container")):
            return "error", "k8s_crash_loop"
        if any(x in low for x in ("no endpoints available", "no active endpoints", "has no endpoints", "service unavailable", "connect: connection refused", "upstream connect error")):
            return "error", "k8s_service_unavailable"
    if any(x in low for x in ("oom", "out of memory", "killed process", "cannot allocate memory")):
        return "critical", "out_of_memory"
    extended = _extended_failure(line)
    if extended:
        if _RECOVERY.search(line) and level not in ("critical", "fatal", "error", "err"):
            return "info", "normal"
        return ("critical" if level in ("critical", "fatal") else "error"), extended
    if _SQL_CONFIGURATION.search(line) and level not in ("critical", "fatal", "error", "err"):
        return "info", "normal"
    if any(x in low for x in ("no space left", "disk full", "read-only file system")):
        return "critical", "disk_full"
    if any(x in low for x in ("failed password", "failed publickey", "authentication failure", "maximum authentication attempts", "invalid user")):
        return "warning", "authentication_failure"
    # Keep a 504/upstream timeout distinct from a refused connection: the
    # former points to latency or saturation, while the latter points to a
    # process, port, or network availability problem.
    if any(x in low for x in ("upstream timed out", "while reading response header", "deadline exceeded")):
        return "error", "request_timeout"
    if source == "nginx" and status:
        code = status.group("status")
        if code == "504":
            return "error", "request_timeout"
        if code == "502":
            return "error", "upstream_unavailable"
    if any(x in low for x in ("connection refused", "connect() failed", "no live upstreams", "connection reset")):
        return ("error" if level not in ("critical", "fatal") else "critical"), "upstream_unavailable"
    if any(x in low for x in ("pull access denied", "manifest unknown", "unauthorized: authentication required", "failed to resolve reference", "toomanyrequests", "imagepullbackoff", "cannot find module", "module not found")):
        return "error", "missing_dependency"
    if any(x in low for x in ("permission denied", "access denied", "forbidden")):
        return "error", "permission_denied"
    if any(x in low for x in ("temporary failure in name resolution", "eai_again", "no such host", "network is unreachable")):
        return "error", "upstream_unavailable"
    if any(x in low for x in ("restarting (", "restartcount", "exec format error", "executable file not found", "health check failed", "exited with code")):
        return "error", "application_crash"
    if any(x in low for x in ("no such file",)):
        return "error", "missing_dependency"
    if any(x in low for x in ("timeout", "timed out")):
        return "error", "request_timeout"
    if any(x in low for x in ("segmentation fault", "segfault", "panic", "traceback")):
        return "critical", "application_crash"
    if level in ("critical", "fatal"):
        return "critical", "unknown_critical"
    if level in ("error", "err"):
        return "error", "unknown_error"
    if level in ("warn", "warning", "notice"):
        return "warning", "degraded_service"
    return "info", "normal"


def parse_logs(logs: str, requested_source: str = "auto") -> list[ParsedLog]:
    requested_source = normalize_source(requested_source) if requested_source != "auto" else "auto"
    parsed: list[ParsedLog] = []
    for number, raw in enumerate(logs.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        source = detect_source(line) if requested_source == "auto" else requested_source
        severity, failure_type = classify(line, source)
        parsed.append(ParsedLog(number, line, severity, source, failure_type))
    return parsed


def source_summary(items: list[ParsedLog]) -> str:
    sources = {x.source for x in items if x.source != "unknown"}
    if len(sources) == 1:
        return next(iter(sources))
    if len(sources) > 1:
        return "mixed"
    return "unknown"


def top_evidence(items: list[ParsedLog], limit: int = 10) -> list[Evidence]:
    # Keep all actionable lines first, preserving log order for easy investigation.
    ranked = sorted(items, key=lambda x: (x.severity not in ("critical", "error"), x.line_number))
    return [Evidence(line_number=x.line_number, message=x.message, severity=x.severity, source=x.source) for x in ranked[:limit]]


def counts(items: list[ParsedLog]) -> tuple[int, int, dict[str, int]]:
    errors = sum(x.severity in ("critical", "error") for x in items)
    warnings = sum(x.severity == "warning" for x in items)
    return errors, warnings, dict(Counter(x.source for x in items))
