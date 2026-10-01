# SRE ReAct + RAG Diagnosis Agent

一个面向 Linux 服务器、Nginx、Docker、Kubernetes 的持续日志检测与事件诊断服务。后台增量读取登记文件，或接收 Alertmanager/普通 Webhook，自动建立事件并采集上下文、检索知识、输出候选根因和处置建议。默认离线规则模式，SQLite 保存游标、事件和审计。完整配置和实现范围见 [项目说明](../README.md) 与 [PRD 对照](../docs/PRD_IMPLEMENTATION.md)。

## 运行

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate       # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

打开 http://localhost:8000 使用中文控制台，或打开 http://localhost:8000/docs 查看 API。

也可以通过环境变量启用受控的 LLM ReAct 循环：

```bash
# PowerShell
$env:LLM_MODE="llm"
$env:LLM_BASE_URL="https://api.openai.com/v1"
$env:LLM_API_KEY="your-key"
$env:LLM_MODEL="gpt-4o-mini"
```

LLM 模式允许 `parse_logs`、`collect_context`、`retrieve_knowledge`、`finish` 工具，服务端验证证据行与知识引用。自动事件遇到模型异常会明确降级，手动诊断返回错误；所有命令仅给建议。上下文通过 `CONTEXT_CONFIG_PATH` 配置固定只读 HTTP 接口。

或：

```bash
curl -X POST http://localhost:8000/api/diagnose \
  -H 'content-type: application/json' \
  -d '{"source":"nginx","logs":"2026-09-29T12:00:00Z [error] connect() failed (111: Connection refused) while connecting to upstream, client: 10.0.0.1, server: app"}'
```

## API

- `GET /api/overview`、`GET /api/incidents`：后台监控及事件工作台。
- `GET/POST /api/sources`：登记文件采集，默认只读新增日志；支持 PATCH 启停。
- `POST /api/alerts/webhook`：自动触发事件诊断，无需调用问答接口。
- `GET/PATCH /api/incidents/{id}`：事件诊断详情、人工确认和记录解决结果。
- `POST /api/incidents/{id}/followup`、`/verify`：补充证据重新诊断、恢复核查。
- `POST /api/knowledge/import`、`GET /api/audit`：知识持久化导入、查询审计。
- `GET /api/health`：服务和知识条目数量。
- `POST /api/diagnose`：输入 `logs`，可选 `source`（`auto/server/nginx/docker/kubernetes`，`k8s` 为别名）、`context`、`max_knowledge`。响应包含标准化根因、置信度、证据、排查步骤、知识引用和 ReAct `trace`。
- `GET /api/knowledge`：列出知识库。
- `GET /api/knowledge/search?q=oom`：检索知识库。

知识库可通过 `KNOWLEDGE_PATH` 指向 JSON 数组加载，文件缺失或损坏会明确报配置错误。结构化手册字段为 `id,title,source,root_cause,steps,commands,tags,symptoms`，另支持来源与可信度；兼容旧知识结构。导入格式见 `config/knowledge_import.example.json`，自定义条目持久保存于 `OPS_DATA_PATH`。
