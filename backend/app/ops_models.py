"""Inputs for persistent incident monitoring and read-only log collection."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .models import Source


IncidentStatus = Literal["new", "diagnosing", "awaiting_confirmation", "acknowledged", "resolved", "failed"]


class SourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    path: str = Field(min_length=1, max_length=2000)
    source: Source = "auto"
    service: str = Field("unknown", min_length=1, max_length=120)
    environment: str = Field("unknown", min_length=1, max_length=120)
    instance: str = Field("unknown", min_length=1, max_length=200)
    enabled: bool = True
    read_existing: bool = False
    is_demo: bool = False
    poll_interval_seconds: float = Field(2, ge=0.25, le=300)

    @field_validator("name", "path", "service", "environment", "instance")
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("must contain non-blank text without NUL characters")
        return value.strip()


class SourcePatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=120)
    enabled: bool | None = None
    poll_interval_seconds: float | None = Field(None, ge=0.25, le=300)


class AlertInput(BaseModel):
    service: str = Field("unknown", max_length=120)
    environment: str = Field("unknown", max_length=120)
    instance: str = Field("unknown", max_length=200)
    source: Source = "auto"
    severity: Literal["critical", "error", "warning", "info"] = "error"
    message: str = Field(min_length=1, max_length=32_768)
    status: Literal["firing", "resolved"] = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    starts_at: str | None = Field(None, max_length=100)
    ends_at: str | None = Field(None, max_length=100)
    fingerprint: str | None = Field(None, max_length=200)
    generator_url: str | None = Field(None, max_length=2000)
    is_demo: bool = False


class IncidentPatch(BaseModel):
    status: Literal["acknowledged", "resolved", "awaiting_confirmation"]
    operator: str = Field("operator", min_length=1, max_length=120)
    resolution: str | None = Field(None, max_length=10_000)


class FollowupInput(BaseModel):
    message: str = Field(min_length=1, max_length=10_000)
    logs: str | None = Field(None, max_length=65_536)
    operator: str = Field("operator", min_length=1, max_length=120)


class MergeInput(BaseModel):
    incident_ids: list[str] = Field(min_length=1, max_length=20)
    operator: str = Field("operator", min_length=1, max_length=120)


class SplitInput(BaseModel):
    alert_ids: list[str] = Field(min_length=1, max_length=100)
    operator: str = Field("operator", min_length=1, max_length=120)
