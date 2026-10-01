# SRE ReAct + RAG 自动故障诊断智能体

系统持续读取接入的日志文件或接收告警 Webhook，发现异常后自动建立故障事件、聚合重复告警、并行采集上下文、检索 Runbook 并生成候选根因、证据和排查建议。首页是事件工作台，无需先提问。支持服务器、Nginx、Docker 和 Kubernetes；`k8s` 是来源别名。

## 快速运行

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

访问 [事件工作台](http://127.0.0.1:8000/) 或 [API 文档](http://127.0.0.1:8000/docs)。默认离线规则模式，不需要模型 API Key。数据源页可填写真实日志路径，默认只监听接入后的新增内容；勾选“读取已有日志”才会扫描历史日志。

工作台提供四个明确标记的演示数据源。“注入演示异常”只向演示文件追加一行报错，后台采集器自行发现并生成诊断，可验证完整链路。演示事件与真实接入事件有独立标签，生产配置可设 `OPS_DEMO_ENABLED=false`。首次运行没有真实生产数据，系统不会自动连接尚未配置的服务器或集群。

## 自动检测与事件处置

- 文件采集保存游标，支持增量追加、未写完的行、日志轮转、截断和重启后继续读取；单次读取最多 256 KiB。采集权限或路径错误会显示失败状态。
- 告警接入支持普通 JSON 与 Alertmanager；按服务、环境、实例、来源、故障类型和默认 5 分钟窗口聚合。支持人工合并、拆分，保留原始告警。
- 自动诊断完成后进入“待确认”。值班人员可确认、补充信息和日志、重新诊断、核查恢复、记录实际根因与解决结果，并导出 Markdown 复盘初稿。
- 恢复核查不会把“没有新增错误”当作恢复证据；需要业务健康、指标等现场证据，再由人员确认解决。
- SQLite 保存事件、诊断版本、时间线、审计记录和文件游标。`OPS_DATA_PATH` 默认 `data/`；导入知识也保存于此。

常见识别范围包括 OOM、磁盘满、502/504、认证和权限失败、容器崩溃；Kubernetes 的 CrashLoopBackOff、ImagePullBackOff、FailedScheduling、探针失败、OOMKilled、Service 无端点；CPU 饱和、数据库连接耗尽、慢查询、TLS 异常和消息积压。单个 Pending、退出码 137 或高 load 不能独立证明具体根因。

## 接入真实数据

日志可在页面登记，或通过 `OPS_SOURCES_PATH` 指向 JSON 配置，格式见 `config/sources.example.json`。路径必须是运行 Agent 的主机可访问的文件。远端服务器需要日志转发或挂载；Kubernetes 应由现有采集器输出 Events/Pod 日志或告警，当前服务不会直接获取 kubeconfig 或扫描集群。

Alertmanager 接收地址是 `POST /api/alerts/webhook`，可配置 HTTP Bearer 令牌 `ALERT_WEBHOOK_TOKEN`。普通告警示例：

```json
{
  "service": "orders-api",
  "environment": "production",
  "instance": "node-01",
  "source": "kubernetes",
  "severity": "error",
  "message": "kubelet Warning BackOff CrashLoopBackOff in pod orders-api",
  "fingerprint": "orders-crashloop-01",
  "starts_at": "2026-10-01T12:00:00Z"
}
```

`CONTEXT_CONFIG_PATH` 指向上下文配置，格式见 `config/context.example.json`。每轮诊断会并行查询配置的 Prometheus、Loki、变更、拓扑 HTTP 接口，携带故障时间窗和服务/实例标签。Prometheus 与 Loki 使用原生查询 API；变更和拓扑需要适配现有平台，接收 `service/instance/start/end` GET 参数并返回 JSON。默认包含故障前一小时，范围上限六小时，请求有超时和响应大小限制。仅访问固定配置地址。

未配置的数据源显示 `not_configured`；超时、权限或格式错误显示 `failed`。诊断输出明确保留信息缺口，未知用户影响为 `null`，不会把缺失数据解释成正常。

## ReAct 与知识库

默认 `LLM_MODE=local` 是确定性规则诊断：解析日志、整理上下文、BM25 检索、输出待验证的原因及引用，置信度是启发式分值。它不是大模型自主推理，也没有完成向量检索或 Rerank。

配置 `LLM_MODE=llm` 后，OpenAI 兼容 Chat Completions 模型在有界 ReAct 循环中选择 `parse_logs`、`collect_context`、`retrieve_knowledge`、`finish` 工具。`collect_context` 查看本轮由只读采集器取得的数据；补充信息或重新诊断会触发新一轮采集。服务端验证证据行、知识 ID、步骤引用、严重度以及必需工具顺序。轨迹展示简短检查假设、工具动作与结果摘要，不展示模型私有思维链。

```powershell
$env:LLM_MODE="llm"
$env:LLM_BASE_URL="http://127.0.0.1:11434/v1"
$env:LLM_MODEL="qwen2.5:7b"
# 公网服务还需设置 LLM_API_KEY
uvicorn app:app --host 127.0.0.1 --port 8000
```

自动事件诊断遇到 LLM 超时或协议异常会降级为本地诊断，明确显示降级原因并写审计；手动诊断 API 保留 502/503/504 失败响应。原始日志与外部数据一律视为不可信内容，不作为工具指令。

内置 25 条 Runbook，检索保留原文片段、来源链接、可信度及已知更新时间。知识库页支持导入结构化 JSON，格式见 `config/knowledge_import.example.json`；上传数组或 `{documents:[...]}`。个人经验标记 `personal`，经人工复核可标记 `reviewed`，不会直接覆盖内置知识。官方手册没有已知更新时间时保留未知。复盘导出和人工导入可用于沉淀经验；自动同步 Wiki、工单推送和自动回灌尚未接入。

## 权限与部署

所有命令仅作为建议，不会执行 shell、重启服务、拉取镜像或修改集群。读取外部数据通过固定 HTTP 连接器和文件只读通道。查询类命令与需要人工审查的变更建议分开标记，所有事件处理和外部查询留审计。

未配置令牌时仅允许回环地址访问 API；异站无令牌写入会拒绝。可设 `OPS_API_TOKEN` 为操作员令牌、`OPS_READ_TOKEN` 为只读令牌、`ALERT_WEBHOOK_TOKEN` 为仅告警接入令牌。页面右上角钥匙按钮填写令牌，保存在当前浏览器会话。当前是共享角色令牌，尚未接入企业 SSO 或细粒度服务权限。

环境变量示例见 `.env.example`。本地可使用 `uvicorn app:app --env-file .env`。Docker Compose 读取 `.env`，需要先设置随机 `OPS_API_TOKEN`，再运行：

```bash
docker compose up --build
```

Compose 绑定 `127.0.0.1:8000`，通过持久卷保存 `data/`。真实日志目录应以只读方式挂载，配置文件中填写容器路径；配置文件挂载到 `/app/config/`，相关环境变量填写容器内路径。多个 Uvicorn worker 会重复启动文件监听器，当前请保持单进程；生产高可用需独立采集服务、共享任务队列和数据库。

## API 与验证

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/overview` | 监控状态、聚合统计、数据源健康、故障分布 |
| GET / POST | `/api/sources` | 列出 / 接入文件数据源 |
| PATCH / DELETE | `/api/sources/{id}` | 开关与修改 / 移除采集源 |
| POST | `/api/sources/{id}/scan-now` | 立即只读采集 |
| POST | `/api/alerts/webhook` | 普通告警或 Alertmanager 接入 |
| GET | `/api/incidents`、`/api/incidents/{id}` | 事件与完整诊断记录 |
| PATCH | `/api/incidents/{id}` | 确认或记录解决结果 |
| POST | `/api/incidents/{id}/followup` | 补充上下文并重新采集诊断 |
| POST | `/api/incidents/{id}/verify` | 核查后续日志与缺失验证数据 |
| POST | `/api/incidents/{id}/merge`、`/split` | 人工合并 / 拆分原始告警 |
| GET | `/api/incidents/{id}/export`、`/api/audit` | 复盘初稿 / 审计 |
| POST | `/api/knowledge/import`、`/api/diagnose` | 导入 Runbook / 独立手动诊断 |

看板准确率和建议采纳率没有人工标注数据时为 `null`；MTTR 仅根据已记录的真实事件解决时间计算，演示事件不参与此值。尚未达成 PRD 的生产 SLA、准确率目标或多租户要求，需要真实数据与压测验收。

```bash
pip install pytest
python -m pytest -q
```

测试覆盖真实后台文件发现、轮转和游标恢复、告警降噪与恢复边界、事件状态和拆并、上下文查询失败、知识引用、LLM 降级、角色权限和知识持久化。PRD 实现范围见 `docs/PRD_IMPLEMENTATION.md`。
