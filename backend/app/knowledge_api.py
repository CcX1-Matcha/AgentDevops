"""Validated, persistent runbook imports alongside the bundled knowledge base."""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator, model_validator

from .knowledge import KnowledgeStore
from .rag import KnowledgeBase, default_kb_path


class RunbookDocument(BaseModel):
    id: str = Field(default_factory=lambda: f"user-{uuid4().hex[:12]}", min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=300)
    source: Literal["server", "nginx", "docker", "kubernetes"]
    root_cause: str = Field(min_length=1, max_length=20000)
    steps: list[str] = Field(min_length=1, max_length=30)
    commands: list[str] = Field(default_factory=list, max_length=30)
    tags: list[str] = Field(default_factory=list, max_length=50)
    symptoms: list[str] = Field(default_factory=list, max_length=50)
    references: list[str] = Field(default_factory=list, max_length=10)
    source_urls: list[str] = Field(default_factory=list, max_length=10)
    failure_types: list[str] = Field(default_factory=list, max_length=20)
    trust_level: Literal["personal", "reviewed"] = "personal"
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), max_length=100)

    @model_validator(mode="before")
    @classmethod
    def normalize_runbook(cls, value):
        if not isinstance(value, dict):
            return value
        value = dict(value)
        steps = value.get("steps")
        if isinstance(steps, list) and any(isinstance(item, dict) for item in steps):
            raw_commands = value.get("commands", [])
            if not isinstance(raw_commands, list):
                raise ValueError("knowledge commands must be a list")
            descriptions, commands = [], list(raw_commands)
            for item in steps:
                if isinstance(item, dict):
                    descriptions.append(item.get("description") or item.get("title") or "")
                    if item.get("command"):
                        commands.append(item["command"])
                else:
                    descriptions.append(item)
            value["steps"], value["commands"] = descriptions, commands
        references, source_urls = value.get("references", []), value.get("source_urls", [])
        if isinstance(references, list) and isinstance(source_urls, list) and all(isinstance(item, str) for item in [*references, *source_urls]):
            value["source_urls"] = list(dict.fromkeys([*references, *source_urls]))
        return value

    @field_validator("id", "title", "root_cause")
    @classmethod
    def nonblank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("knowledge identifiers and text must not be blank")
        return value.strip()

    @field_validator("updated_at")
    @classmethod
    def valid_update_time(cls, value: str) -> str:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc).isoformat()

    @field_validator("steps", "commands", "tags", "symptoms", "failure_types")
    @classmethod
    def bounded_items(cls, items: list[str]) -> list[str]:
        if any(len(item) > 5000 or not item.strip() for item in items):
            raise ValueError("knowledge fields must contain nonblank strings of at most 5000 characters")
        return items

    @field_validator("references", "source_urls")
    @classmethod
    def safe_links(cls, links: list[str]) -> list[str]:
        for link in links:
            parsed = urlparse(link)
            local = re.fullmatch(r"/api/incidents/[a-zA-Z0-9-]+(?:/(?:report|export))?", link)
            if len(link) > 5000 or any(ord(char) < 32 for char in link) or parsed.username or parsed.password:
                raise ValueError("source links must not contain credentials or control characters")
            if not (parsed.scheme in {"http", "https"} and parsed.hostname) and not local:
                raise ValueError("source links must be HTTP(S) URLs or local incident references")
        return links


class KnowledgeImport(BaseModel):
    documents: list[RunbookDocument] = Field(min_length=1, max_length=50)


class KnowledgeRepository:
    def __init__(self, data_path: Path, base_path: str | None = None):
        self.data_path = data_path
        self.custom_path = data_path / "knowledge.custom.json"
        self.active_path = data_path / "knowledge.active.json"
        self.lock = threading.RLock()
        self.base_path = Path(base_path) if base_path else default_kb_path()
        self._activate()

    def _activate(self) -> None:
        self.data_path.mkdir(parents=True, exist_ok=True)
        base = self._read_base()
        custom = self._read_custom({str(item["id"]) for item in base})
        active = self._merge(base, custom)
        store = self._build_store(active)
        self._atomic_write(self.active_path, active)
        self.store = store

    def _read_base(self) -> list[dict]:
        base = json.loads(self.base_path.read_text(encoding="utf-8-sig"))
        if not isinstance(base, list) or any(not isinstance(item, dict) or not str(item.get("id", "")).strip() for item in base):
            raise ValueError("Knowledge base must be a JSON array of records with identifiers")
        identifiers = [str(item["id"]) for item in base]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Knowledge base contains duplicate identifiers")
        return base

    def _read_custom(self, base_ids: set[str]) -> list[dict]:
        if not self.custom_path.exists():
            return []
        custom = json.loads(self.custom_path.read_text(encoding="utf-8-sig"))
        if not isinstance(custom, list):
            raise ValueError("Imported knowledge must be a JSON array")
        validated = [RunbookDocument.model_validate(item).model_dump() for item in custom]
        if any(item["id"] in base_ids for item in validated):
            raise ValueError("导入条目 ID 与内置知识重复，请为个人知识使用新的 ID。")
        if len({item["id"] for item in validated}) != len(validated):
            raise ValueError("Imported knowledge contains duplicate identifiers")
        return validated

    @staticmethod
    def _merge(base: list[dict], custom: list[dict]) -> list[dict]:
        merged = {str(item["id"]): item for item in base}
        for item in custom:
            merged[str(item["id"])] = item
        return list(merged.values())

    @staticmethod
    def _build_store(records: list[dict]) -> KnowledgeStore:
        # Build both document mapping and BM25 before replacing any live files.
        mapped = [KnowledgeStore._from_record(item) for item in records]
        store = KnowledgeStore(documents=mapped)
        store.documents = mapped
        store._bm25 = KnowledgeBase(documents=records)
        return store

    @staticmethod
    def _stage(path: Path, records: list[dict] | bytes) -> Path:
        payload = records if isinstance(records, bytes) else json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
        descriptor, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return temporary

    @classmethod
    def _atomic_write(cls, path: Path, records: list[dict] | bytes) -> None:
        temporary = cls._stage(path, records)
        try:
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _commit(self, active: list[dict], custom: list[dict]) -> None:
        previous_active = self.active_path.read_bytes() if self.active_path.exists() else None
        staged: list[Path] = []
        active_replaced = False
        try:
            active_temp = self._stage(self.active_path, active)
            staged.append(active_temp)
            custom_temp = self._stage(self.custom_path, custom)
            staged.append(custom_temp)
            active_temp.replace(self.active_path)
            active_replaced = True
            # Custom is authoritative on restart; commit it only after the
            # derived active snapshot and both staged files are ready.
            custom_temp.replace(self.custom_path)
        except BaseException:
            if active_replaced:
                if previous_active is not None:
                    self._atomic_write(self.active_path, previous_active)
                else:
                    self.active_path.unlink(missing_ok=True)
            raise
        finally:
            for temporary in staged:
                temporary.unlink(missing_ok=True)

    def import_documents(self, documents: list[RunbookDocument]) -> list[str]:
        with self.lock:
            base = self._read_base()
            base_ids = {str(item["id"]) for item in base}
            if any(item.id in base_ids for item in documents):
                raise ValueError("导入条目 ID 与内置知识重复，请为个人知识使用新的 ID。")
            if len({item.id for item in documents}) != len(documents):
                raise ValueError("同一次导入不能包含重复 ID。")
            custom = self._read_custom(base_ids)
            merged = {str(item["id"]): item for item in custom}
            merged.update({item.id: item.model_dump() for item in documents})
            custom = list(merged.values())
            active = self._merge(base, custom)
            store = self._build_store(active)
            self._commit(active, custom)
            self.store = store
            return [item.id for item in documents]


def create_knowledge_router(repository: KnowledgeRepository, agent, operations) -> APIRouter:
    router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])

    @router.post("/import", status_code=201)
    def import_runbooks(payload: KnowledgeImport, request: Request):
        try:
            identifiers = repository.import_documents(payload.documents)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OSError as exc:
            raise HTTPException(status_code=503, detail="知识库写入失败，已有知识仍可使用。") from exc
        agent.store = repository.store
        if agent._llm_agent is not None:
            agent._llm_agent.store = repository.store
        operations.audit("knowledge_imported", "knowledge", ",".join(identifiers), getattr(request.state, "operator", "operator"), {"ids": identifiers})
        return {"ids": identifiers, "total": len(repository.store.documents)}

    return router
