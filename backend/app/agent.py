"""ReAct-style diagnosis orchestration.

Each tool/action is explicit and recorded in ``trace``. This makes the local
mode deterministic and auditable while allowing a future LLM to choose tools.
"""
from __future__ import annotations

import os
import time
from collections import Counter
from typing import Any

from .command_policy import command_risk
from .knowledge import KnowledgeStore
from .models import DiagnoseResponse, DiagnosisMetrics, DiagnosisStep, TraceEvent
from .parser import ParsedLog, classify, counts, normalize_source, parse_logs, source_summary, top_evidence


_TYPE_LABELS = {
    "out_of_memory": "内存耗尽（OOM）",
    "disk_full": "磁盘空间或 inode 耗尽",
    "upstream_unavailable": "上游服务不可用",
    "request_timeout": "请求超时",
    "permission_denied": "权限拒绝",
    "missing_dependency": "依赖或镜像缺失",
    "authentication_failure": "认证失败",
    "application_crash": "应用崩溃",
    "k8s_crash_loop": "Kubernetes Pod 重启循环",
    "k8s_image_pull": "Kubernetes 镜像拉取失败",
    "k8s_scheduling_failure": "Kubernetes Pod 调度失败",
    "k8s_probe_failure": "Kubernetes 健康探针失败",
    "k8s_oom": "Kubernetes Pod 内存耗尽",
    "k8s_service_unavailable": "Kubernetes 服务不可用",
    "degraded_service": "服务降级或告警",
    "unknown_critical": "严重故障",
    "unknown_error": "应用或系统错误",
    "normal": "未发现明确故障",
    "cpu_saturation": "CPU 饱和或节流",
    "database_connection_exhausted": "数据库连接耗尽",
    "database_slow_query": "数据库慢查询",
    "certificate_error": "TLS 证书或握手异常",
    "message_queue_backlog": "消息队列积压",
    "managed_cache_pressure": "托管可重建缓存压力",
}


class ReActAgent:
    def __init__(self, store: KnowledgeStore | None = None):
        self.store = store or KnowledgeStore(path=os.getenv("KNOWLEDGE_PATH"))
        # The local engine remains the default and has no network dependency.
        # ``LLM_MODE=llm`` lazily constructs the guarded tool-calling engine so
        # a missing key or an unavailable endpoint cannot break health checks.
        self.mode = os.getenv("LLM_MODE", "local").strip().lower()
        self._llm_agent = None

    def diagnose(self, logs: str, source: str = "auto", context: str | None = None, max_knowledge: int = 5,
                 observations: dict[str, Any] | None = None) -> DiagnoseResponse:
        source = normalize_source(source) if source != "auto" else source
        if self.mode == "llm":
            from .llm import LLMReActAgent

            if self._llm_agent is None:
                self._llm_agent = LLMReActAgent(store=self.store)
            return self._llm_agent.diagnose(logs, source, context, max_knowledge, observations=observations)
        if self.mode != "local":
            from .llm import LLMConfigurationError

            raise LLMConfigurationError("LLM_MODE must be 'local' or 'llm'")
        started = time.perf_counter()
        trace: list[TraceEvent] = []

        parsed = parse_logs(logs, source)
        if not parsed:
            raise ValueError("logs must contain at least one nonblank line")
        errors, warnings, source_counts = counts(parsed)
        trace.append(TraceEvent(iteration=1, action="parse_logs", action_input=f"source={source}, lines={len(parsed)}", observation=f"解析 {len(parsed)} 行；错误 {errors}，警告 {warnings}；来源 {source_counts}"))

        if observations:
            sources = observations.get("context_sources", [])
            trace.append(TraceEvent(iteration=len(trace) + 1, action="collect_context", action_input="configured_read_only_connectors",
                         observation="；".join(f"{item.get('name', 'context')}={item.get('status', 'unknown')}" for item in sources),
                         expected_result="关联故障时间窗内的指标、日志、变更和依赖状态", judgment="缺失或失败的数据源不视为正常"))
        dominant = self._dominant_type(parsed)
        query = " ".join([dominant, " ".join(x.message for x in parsed if x.failure_type != "normal")[:3000], context or ""])
        detected_source = source_summary(parsed)
        knowledge = self.store.search(query, dominant, max_knowledge, source=detected_source if detected_source in {"server", "nginx", "docker", "kubernetes"} else None)
        if dominant == "managed_cache_pressure":
            compatible = {document.id for document in self.store.documents if dominant in document.failure_types}
            knowledge = [match for match in knowledge if match.id in compatible]
        trace.append(TraceEvent(iteration=len(trace) + 1, action="retrieve_knowledge", action_input=query[:500], observation=f"检索到 {len(knowledge)} 条知识；首选 {knowledge[0].id if knowledge else '无'}"))

        severity = self._severity(parsed)
        label = _TYPE_LABELS.get(dominant, dominant)
        if dominant == "normal":
            root_cause = "日志中未发现明确的错误模式，建议结合指标和链路追踪继续观察。"
            summary = "未检测到明确故障"
            confidence = 0.4
        else:
            root_cause = self._root_cause(dominant, parsed, knowledge)
            summary = f"检测到{label}，共发现 {errors} 条错误/严重日志。"
            confidence = 0.35 if dominant.startswith("unknown") else (0.72 if knowledge else 0.52)
            if dominant in {"out_of_memory", "k8s_oom", "disk_full"}:
                confidence = 0.82 if knowledge else 0.65
        missing = self._missing_information(observations)
        steps = self._grounded_steps(dominant, source_summary(parsed), knowledge)
        trace.append(TraceEvent(iteration=len(trace) + 1, action="reason", action_input=f"failure_type={dominant}",
                     observation=f"日志支持候选判断：{label}，置信度 {confidence:.2f}", hypothesis=label,
                     expected_result=steps[0].expected_result if steps else "补充故障证据",
                     judgment="日志模式匹配；候选原因需现场核实，重复报错不增加独立证据"))
        trace.append(TraceEvent(iteration=len(trace) + 1, action="finish", action_input="standardize_diagnosis", observation="输出根因候选、证据、建议步骤、知识引用和信息缺口"))

        duration = (time.perf_counter() - started) * 1000
        return DiagnoseResponse(status="completed", mode="local", source=source_summary(parsed), severity=severity, summary=summary, root_cause=root_cause, confidence=round(confidence, 3), failure_type=dominant, evidence=top_evidence(parsed), steps=steps, knowledge=knowledge, trace=trace,
                                missing_information=missing, impact_scope={"log_source": source_summary(parsed), "affected_users": None},
                                boundary="本地规则识别日志现象，知识库提供待验证的原因候选。置信度是启发式分值，不是经过校准的概率；未采集的数据不能视为正常。所有命令仅供人工复核和执行。",
                                metrics=DiagnosisMetrics(total_lines=len(parsed), error_count=errors, warning_count=warnings, sources=source_counts, duration_ms=round(duration, 2)))

    @staticmethod
    def _missing_information(observations: dict | None) -> list[str]:
        if not observations:
            return ["故障时间窗内的资源和业务指标", "最近发布及配置变更", "依赖健康与业务影响范围"]
        return [f"{item.get('name', '上下文')}（{item.get('status', 'unknown')}）" for item in observations.get("context_sources", []) if item.get("status") != "ok"]

    @classmethod
    def _grounded_steps(cls, kind: str, source: str, knowledge) -> list[DiagnosisStep]:
        base = cls._steps(kind, source)
        primary = knowledge[0] if knowledge else None
        selected = base[:1] if primary and primary.steps else base
        if primary and primary.steps:
            selected.extend(DiagnosisStep(title=f"排查步骤 {i + 1}", description=description,
                            knowledge_refs=[primary.id], expected_result="将现场结果与日志证据核对，记录确认结果与仍未排除的原因")
                            for i, description in enumerate(primary.steps[:8]))
            commands = list(dict.fromkeys(primary.commands))[:5]
            selected.extend(DiagnosisStep(title="采集现场证据", description="在对应主机或集群人工核对命令和占位参数后采集结果。",
                            command=command, risk=command_risk(command), knowledge_refs=[primary.id],
                            expected_result="记录故障时间窗、对象与结果，用于验证候选根因") for command in commands if command not in {step.command for step in selected})
        for step in selected:
            step.risk = command_risk(step.command)
            if primary and not step.knowledge_refs:
                step.knowledge_refs = [primary.id]
        return selected

    @staticmethod
    def _dominant_type(items: list[ParsedLog]) -> str:
        for severity in ("critical", "error", "warning"):
            actionable = [item.failure_type for item in items if item.severity == severity and
                          (severity != "warning" or item.failure_type != "degraded_service")]
            if actionable:
                return Counter(actionable).most_common(1)[0][0]
        return "degraded_service" if any(x.severity == "warning" for x in items) else "normal"

    @staticmethod
    def _severity(items: list[ParsedLog]) -> str:
        if any(x.severity == "critical" for x in items): return "critical"
        if any(x.severity == "error" for x in items): return "error"
        if any(x.severity == "warning" for x in items): return "warning"
        return "info"

    @staticmethod
    def _root_cause(kind: str, items: list[ParsedLog], knowledge) -> str:
        sample = next((x.message for x in items if x.failure_type == kind), "")
        hint = knowledge[0].summary if knowledge else ""
        return f"{_TYPE_LABELS.get(kind, kind)}：证据日志显示“{sample[:240]}”。{hint}"

    @staticmethod
    def _steps(kind: str, source: str) -> list[DiagnosisStep]:
        common = {
            "managed_cache_pressure": [("核对托管缓存范围", "只读确认缓存实际路径、占用、基线与服务归属；仅缓存压力告警不能证明全磁盘或 inode 耗尽。", "du -sh <managed-cache-path>", "取得明确的托管缓存路径和占用，未把告警等同于磁盘满载"), ("核对保留与回滚方案", "人工确认缓存可重建、保留要求、重建代价及回滚方案；仅通过已审核剧本按权限处置并核查业务恢复。", None, "保留与回滚要求明确，业务恢复需独立验证")],
            "out_of_memory": [("确认 OOM 事件", "确认内核是否触发 OOM killer，并定位被杀进程。", "dmesg -T | egrep -i 'oom|killed process'", "看到 OOM 时间、进程及内存 cgroup 信息"), ("检查内存压力", "核对主机和容器 limit、工作集及近期流量变化。", "free -h && docker stats --no-stream", "定位内存消耗最大的进程或容器")],
            "disk_full": [("确认容量和 inode", "检查挂载点容量与 inode，区分数据增长还是 inode 耗尽。", "df -h && df -i", "确认满载的挂载点"), ("安全释放空间", "按保留策略清理日志、临时文件并验证服务写入。", "du -xhd1 /var 2>/dev/null | sort -h", "空间回落且服务恢复写入")],
            "upstream_unavailable": [("检查上游进程", "确认应用进程存活并监听 Nginx 配置的端口。", "ss -lntp && systemctl status <service>", "端口处于 LISTEN 且服务为 active"), ("核对网络策略", "检查容器网络、DNS 和安全组，确认 Nginx 到上游可达。", "curl -sv http://<upstream>/health", "健康检查返回 2xx")],
            "request_timeout": [("定位慢请求", "查看应用和依赖耗时，区分线程池、数据库或外部依赖瓶颈。", "curl -w '\\n%{time_total}\\n' -o /dev/null http://<endpoint>", "确认耗时阶段"), ("检查资源饱和", "核对 CPU、连接池、队列和限流指标。", "vmstat 1 5", "资源未持续饱和或已定位瓶颈")],
            "permission_denied": [("核对身份和权限", "确认进程 UID/GID、文件属主、ACL 及挂载选项。", "id && namei -l <path>", "定位拒绝访问的目录层级"), ("应用最小权限修复", "按服务账号授予所需最小读写权限并回归验证。", None, "操作成功且权限范围未扩大")],
            "application_crash": [("保留崩溃证据", "收集完整 traceback、core dump、退出码和对应版本。", "docker inspect <container> --format '{{.State.ExitCode}}'", "得到可关联的版本和崩溃堆栈"), ("回滚或修复", "对比最近发布变更，必要时回滚并观察错误率。", None, "错误率恢复到基线")],
            "missing_dependency": [("确认依赖或镜像", "核对镜像名称、标签、仓库权限以及应用需要的模块和启动文件。", "docker image inspect <image> && docker pull <image>", "镜像或依赖可以被受控环境解析"), ("修复引用并验证", "修正版本、仓库认证或启动配置后重新部署并观察健康检查。", None, "容器成功启动且重启计数停止增长")],
            "authentication_failure": [("确认来源和范围", "按时间、来源地址、账号和认证方式聚合失败事件，区分误配与暴力尝试。", "journalctl -u ssh --since '30 minutes ago' --no-pager", "明确受影响账号、来源 IP 和时间窗口"), ("收敛认证风险", "核对密钥、账号状态和访问策略；按安全流程处置异常来源并验证合法登录。", "sshd -T | egrep 'passwordauthentication|pubkeyauthentication|allowusers|allowgroups'", "合法访问恢复且异常失败率下降")],
            "k8s_crash_loop": [("检查 Pod 退出原因", "查看容器最近一次退出码、重启次数和前一次容器日志，定位启动阶段异常。", "kubectl describe pod <pod> -n <namespace> && kubectl logs <pod> -n <namespace> --previous", "确认首次异常、退出码和关联版本"), ("修复配置并观察恢复", "核对启动命令、环境变量、Secret、依赖和资源限制，再按发布流程修复。", "kubectl get pod <pod> -n <namespace> -o wide", "Pod 稳定为 Running/Ready 且重启次数停止增长")],
            "k8s_image_pull": [("确认镜像拉取错误", "检查镜像仓库、名称标签、ServiceAccount 和 imagePullSecrets，区分认证失败与镜像不存在。", "kubectl describe pod <pod> -n <namespace>", "Events 中明确镜像拉取失败原因"), ("修正镜像或凭据", "修复镜像引用、仓库访问或拉取凭据后重新发布。", "kubectl get pod <pod> -n <namespace> -o jsonpath='{.status.containerStatuses[*].state}'", "容器完成拉取并进入 Running")],
            "k8s_scheduling_failure": [("检查调度约束", "核对节点资源、taint/toleration、nodeSelector、亲和性和 PVC 绑定状态。", "kubectl describe pod <pod> -n <namespace>", "Events 给出不可调度的具体约束"), ("释放或补充资源", "根据约束扩容节点、调整资源请求或修正调度配置，并观察 Pending 是否消失。", "kubectl get nodes -o wide", "Pod 被调度到符合条件的节点")],
            "k8s_probe_failure": [("查看探针配置和事件", "核对探针路径、端口、协议、初始延迟和超时，结合容器日志判断应用是否真正就绪。", "kubectl describe pod <pod> -n <namespace>", "确认失败探针和最近事件"), ("修复应用或探针参数", "修正监听地址、健康检查路径或启动时序，避免盲目延长 timeout。", "kubectl get pod <pod> -n <namespace> -o jsonpath='{.status.containerStatuses[*].ready}'", "readiness 恢复为 true")],
            "k8s_oom": [("确认容器内存限制", "关联 OOMKilled、容器 limit/request、工作集和节点内存压力，区分容器限制与节点级压力。", "kubectl describe pod <pod> -n <namespace> && kubectl top pod <pod> -n <namespace>", "确认被杀容器和内存上限"), ("调整工作负载", "排查内存泄漏和峰值流量，评估应用参数、并发与资源 limit 后再变更。", "kubectl get pod <pod> -n <namespace> -o jsonpath='{.status.containerStatuses[*].lastState}'", "OOM 事件停止且 Pod 稳定")],
            "k8s_service_unavailable": [("核对 Service 端点", "检查 Service selector、Endpoints/EndpointSlice、目标端口和后端 Pod Ready 状态。", "kubectl get svc,endpointslice -n <namespace>", "Service 存在可用后端端点"), ("验证集群内连通性", "从同一命名空间验证 DNS 和目标端口，结合 NetworkPolicy 检查访问路径。", "kubectl run netcheck --rm -it --image=curlimages/curl -- curl -sv http://<service>.<namespace>:<port>/health", "健康检查返回预期状态码")],
        }
        selected = common.get(kind, [("确认影响范围", "结合错误日志、监控和最近变更确认受影响服务。", None, "明确故障时间窗和服务边界"), ("验证修复", "执行低风险修复后重新采集日志和指标。", None, "错误和告警停止增长")])
        return [DiagnosisStep(title=t, description=d, command=c, expected_result=e) for t, d, c, e in selected]
