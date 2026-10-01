"""FastAPI entrypoint for the SRE diagnosis agent."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .agent import ReActAgent
from .context import ContextCollector
from .demo import DemoSources, create_demo_router
from .knowledge_api import KnowledgeRepository, create_knowledge_router
from .llm import LLMConfigurationError, LLMProtocolError, LLMTimeoutError
from .models import DiagnoseRequest, DiagnoseResponse, KnowledgeListResponse
from .operations import OperationsService, create_ops_router
from .ops_models import SourcePatch
from .security import AccessMiddleware


_ROOT = Path(__file__).resolve().parents[2]
_DATA = Path(os.getenv("OPS_DATA_PATH", str(_ROOT / "data"))).resolve()
repository = KnowledgeRepository(_DATA, os.getenv("KNOWLEDGE_PATH"))
agent = ReActAgent(store=repository.store)
collector = ContextCollector()
operations = OperationsService(_DATA / "operations.sqlite3", agent, context_provider=collector.collect)
demo = DemoSources(operations, _DATA)


@asynccontextmanager
async def lifespan(application: FastAPI):
    sources_path = os.getenv("OPS_SOURCES_PATH")
    if sources_path:
        configured = json.loads(Path(sources_path).read_text(encoding="utf-8-sig"))
        if not isinstance(configured, list):
            raise ValueError("OPS_SOURCES_PATH must contain a JSON array")
        for source in configured:
            operations.ensure_source(source, update_existing=True)
    if os.getenv("OPS_DEMO_ENABLED", "true").lower() in {"1", "true", "yes"}:
        demo.initialize()
    else:
        for source in operations.list_sources()["items"]:
            if source["is_demo"] and source["enabled"]:
                operations.update_source(source["id"], SourcePatch(enabled=False))
    await operations.start()
    try:
        yield
    finally:
        drained = await operations.stop()
        if drained and agent._llm_agent is not None:
            agent._llm_agent.close()
            agent._llm_agent = None


app = FastAPI(title="SRE ReAct-RAG Operations Agent", version="0.2.0", lifespan=lifespan,
              description="Continuously detect, correlate and diagnose incidents from logs and alerts.")
app.add_middleware(AccessMiddleware)
app.include_router(create_ops_router(operations))
app.include_router(create_demo_router(demo))
app.include_router(create_knowledge_router(repository, agent, operations))
app.state.operations = operations

# The static UI is optional for API-only deployments.  Mounting from the
# repository root keeps ``uvicorn app:app`` useful in both local and Docker
# runs without making the diagnosis service depend on a frontend build tool.
_FRONTEND = _ROOT / "frontend"
_EXAMPLES = _ROOT / "examples"
if _FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=_FRONTEND), name="static")
if _EXAMPLES.exists():
    app.mount("/examples", StaticFiles(directory=_EXAMPLES), name="examples")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Serve the lightweight operator console when the UI assets are present."""
    page = _FRONTEND / "index.html"
    if not page.exists():
        raise HTTPException(status_code=404, detail="frontend is not installed")
    return FileResponse(page)


@app.get("/api/health")
def health() -> dict:
    configured = agent.mode in {"local", "llm"}
    monitor = operations.monitor_health()
    status = "configuration_error" if not configured else "degraded" if monitor["status"] == "degraded" else "ok"
    return {"status": status, "mode": agent.mode,
            "service": "sre-diagnosis-agent", "knowledge_documents": len(agent.store.documents),
            "monitor_running": monitor["running"], "monitor": monitor, "context_connectors": len(collector.connectors),
            "context_configuration_error": collector.config_error,
            "demo_enabled": os.getenv("OPS_DEMO_ENABLED", "true").lower() in {"1", "true", "yes"}, "version": "0.2.0"}


@app.post("/api/diagnose", response_model=DiagnoseResponse)
def diagnose(request: DiagnoseRequest, http_request: Request) -> DiagnoseResponse:
    try:
        result = agent.diagnose(request.logs, request.source, request.context, request.max_knowledge)
        operations.audit("manual_diagnosis_completed", "diagnosis", result.id, getattr(http_request.state, "operator", "operator"),
                         {"mode": result.mode, "failure_type": result.failure_type, "duration_ms": result.metrics.duration_ms})
        return result
    except LLMConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except LLMTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except LLMProtocolError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:  # Convert malformed custom KBs into an API error.
        raise HTTPException(status_code=500, detail=f"diagnosis failed: {exc}") from exc


@app.get("/api/knowledge", response_model=KnowledgeListResponse)
def knowledge() -> KnowledgeListResponse:
    items = agent.store.all()
    return KnowledgeListResponse(items=items, total=len(items))


@app.get("/api/knowledge/search", response_model=KnowledgeListResponse)
def search_knowledge(q: str, limit: int = 5) -> KnowledgeListResponse:
    if not q.strip():
        raise HTTPException(status_code=400, detail="q must not be blank")
    items = agent.store.search(q, limit=max(1, min(limit, 20)))
    return KnowledgeListResponse(items=items, total=len(items))
