import pytest

from app.parser import parse_logs


@pytest.mark.parametrize("line,kind", [
    ("CPU usage 95%", "cpu_saturation"),
    ("WARN CPU throttling detected for api", "cpu_saturation"),
    ("ERROR CPU 使用率过高", "cpu_saturation"),
    ("ERROR Too many connections", "database_connection_exhausted"),
    ("FATAL remaining connection slots are reserved for non-replication superuser connections", "database_connection_exhausted"),
    ("HikariPool-1 - Connection is not available, request timed out after 30000ms.", "database_connection_exhausted"),
    ("ERROR canceling statement due to statement timeout", "database_slow_query"),
    ("ERROR Lock wait timeout exceeded; try restarting transaction", "database_slow_query"),
    ("# Query_time: 5.120000 Lock_time: 0.000000 Rows_sent: 1", "database_slow_query"),
    ("LOG duration: 2400.123 ms statement: SELECT * FROM orders", "database_slow_query"),
    ("ERROR x509: certificate has expired or is not yet valid", "certificate_error"),
    ("nginx ERROR SSL_do_handshake() failed: certificate verify failed", "certificate_error"),
    ("ERROR consumer lag exceeds threshold", "message_queue_backlog"),
    ("WARN queue backlog detected for orders", "message_queue_backlog"),
    ("ERROR 消息积压严重", "message_queue_backlog"),
    ("WARN CPUHigh firing service=orders", "cpu_saturation"),
    ("WARN ConsumerLagHigh firing service=orders", "message_queue_backlog"),
])
def test_specific_resource_dependency_failures_take_precedence(line, kind):
    parsed = parse_logs(line)[0]
    assert parsed.failure_type == kind
    assert parsed.severity in {"error", "critical"}
    assert parsed.source == ("nginx" if line.startswith("nginx") else "server")


@pytest.mark.parametrize("line", [
    "INFO CPU usage 15% load average 0.2",
    "INFO CPU utilization normal",
    "INFO CPU throttling metric registered",
    "INFO query completed duration=20ms",
    "INFO slow query log enabled",
    "# Query_time: 0.001000 Lock_time: 0.000000",
    "LOG duration: 12.123 ms statement: SELECT 1",
    "LOG duration: 500 ms statement: SELECT 1",
    "INFO statement_timeout=30s configured",
    "INFO query timeout configured to 30 seconds",
    "INFO CPUHigh alert configured",
    "INFO connection pool available=20 used=5",
    "INFO TLS certificate valid for 180 days",
    "INFO consumer lag 0 and messages_ready=0",
    "INFO queue backlog high alert resolved",
    "INFO CPU saturation recovered",
])
def test_normal_observations_do_not_create_extended_faults(line):
    parsed = parse_logs(line)[0]
    assert parsed.failure_type == "normal"
    assert parsed.severity == "info"
