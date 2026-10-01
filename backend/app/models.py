"""API and domain models for log diagnosis."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


Source = Literal["auto", "server", "nginx", "docker", "kubernetes", "k8s"]


class DiagnoseRequest(BaseModel):
    logs: str = Field(..., min_length=1, max_length=2_000_000, description="Raw server/Nginx/Docker/Kubernetes logs and events")
    source: Source = Field("auto", description="Log source, or auto-detect")
    context: str | None = Field(None, max_length=10_000, description="Optional incident context")
    max_knowledge: int = Field(5, ge=1, le=20)

    @field_validator("logs")
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("logs must not be blank")
        return value


class Evidence(BaseModel):
    line_number: int
    message: str
    severity: Literal["critical", "error", "warning", "info"]
    source: Literal["server", "nginx", "docker", "kubernetes", "unknown"]


class DiagnosisStep(BaseModel):
    title: str
    description: str
    command: str | None = None
    expected_result: str | None = None
    risk: Literal["read_only", "manual"] = "manual"
    execution: Literal["advice_only"] = "advice_only"
    knowledge_refs: list[str] = Field(default_factory=list)


class KnowledgeMatch(BaseModel):
    id: str
    title: str
    category: str
    tags: list[str] = Field(default_factory=list)
    summary: str
    score: float = Field(ge=0, le=1)
    excerpt: str
    steps: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    source_urls: list[str] = Field(default_factory=list)
    updated_at: str | None = None
    trust_level: str = "unverified"


class TraceEvent(BaseModel):
    iteration: int
    action: Literal["parse_logs", "retrieve_knowledge", "collect_context", "verify", "reason", "finish"]
    action_input: str
    observation: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hypothesis: str | None = None
    expected_result: str | None = None
    judgment: str | None = None


class DiagnosisMetrics(BaseModel):
    total_lines: int
    error_count: int
    warning_count: int
    sources: dict[str, int]
    duration_ms: float


class DiagnoseResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    status: Literal["completed", "failed"]
    mode: Literal["local", "llm"]
    source: Literal["server", "nginx", "docker", "kubernetes", "mixed", "unknown"]
    severity: Literal["critical", "error", "warning", "info"]
    summary: str
    root_cause: str
    confidence: float = Field(ge=0, le=1)
    failure_type: str
    evidence: list[Evidence] = Field(default_factory=list)
    steps: list[DiagnosisStep] = Field(default_factory=list)
    knowledge: list[KnowledgeMatch] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    metrics: DiagnosisMetrics
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    impact_scope: dict[str, str | int | None] = Field(default_factory=dict)
    missing_information: list[str] = Field(default_factory=list)
    boundary: str | None = None
    degraded: bool = False


class KnowledgeListResponse(BaseModel):
    items: list[KnowledgeMatch]
    total: int
