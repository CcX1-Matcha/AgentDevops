"""Local BM25 knowledge retrieval with runbook provenance and metadata."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .models import KnowledgeMatch
from .rag import KnowledgeBase, default_kb_path


@dataclass(frozen=True)
class KnowledgeDocument:
    id: str
    title: str
    category: str
    tags: tuple[str, ...]
    summary: str
    content: str
    failure_types: tuple[str, ...]
    steps: tuple[str, ...] = ()
    commands: tuple[str, ...] = ()
    source_urls: tuple[str, ...] = ()
    updated_at: str | None = None
    trust_level: str = "unverified"


DEFAULT_DOCUMENTS = [
    KnowledgeDocument("KB-001", "Nginx upstream connection refused", "nginx", ("nginx", "upstream", "502", "connection"), "Nginx cannot connect to the upstream application.", "Check upstream process health, listening port and network policy. A 502 with connection refused usually means no process is listening or a service restarted.", ("upstream_unavailable",)),
    KnowledgeDocument("KB-002", "Nginx upstream timeout", "nginx", ("nginx", "timeout", "504", "upstream"), "The upstream did not respond within the proxy timeout.", "Inspect application latency, saturation and dependency health. Compare proxy_read_timeout with the request's p95 latency before changing a timeout.", ("request_timeout", "upstream_unavailable")),
    KnowledgeDocument("KB-003", "Linux OOM killer", "server", ("linux", "oom", "memory", "killed"), "The kernel terminated a process because available memory was exhausted.", "Check dmesg/journalctl for the OOM event, identify the largest process, inspect memory limits and add capacity or tune the workload.", ("out_of_memory",)),
    KnowledgeDocument("KB-004", "Filesystem full", "server", ("linux", "disk", "storage", "inode"), "A full filesystem prevents writes and can cascade into service failures.", "Check df -h and df -i, identify large files with du, rotate or remove safe artifacts, then verify application recovery.", ("disk_full",)),
    KnowledgeDocument("KB-005", "Docker container restart loop", "docker", ("docker", "restart", "exit", "healthcheck"), "A container repeatedly exits or fails its health check.", "Inspect docker ps and docker logs, check the exit code and health check, validate environment/secrets and resource limits before restarting.", ("application_crash", "missing_dependency", "unknown_error")),
    KnowledgeDocument("KB-006", "Permission denied", "server", ("linux", "permission", "uid", "gid"), "A process cannot read, write or execute a required resource.", "Confirm the effective UID/GID and ownership with ls -l, inspect ACLs and mount options, and apply the narrowest safe permission fix.", ("permission_denied",)),
    KnowledgeDocument("KB-007", "Service dependency unavailable", "server", ("systemd", "service", "connection", "dependency"), "An application dependency is stopped or unreachable.", "Check systemctl status and service endpoints, inspect recent deploys and network policy, then restore the dependency and re-test.", ("upstream_unavailable", "unknown_error")),
    KnowledgeDocument("KB-008", "Application crash or panic", "server", ("crash", "panic", "traceback", "segfault"), "The process crashed due to an unhandled exception or memory fault.", "Capture the complete stack trace/core dump, correlate with the release, reproduce if possible, and roll back or patch the triggering change.", ("application_crash",)),
]

_TOKEN = re.compile(r"[a-z0-9_/-]+", re.I)
_STOP = {"the", "and", "for", "with", "from", "that", "this", "line", "error", "warn", "info"}


class KnowledgeStore:
    def __init__(self, documents: list[KnowledgeDocument] | None = None, path: str | Path | None = None):
        self._bm25: KnowledgeBase | None = None
        if documents:
            self.documents = documents
        else:
            # Prefer the repository's structured incident KB.  KnowledgeBase
            # owns tokenization and BM25 ranking; this class only normalizes
            # its records into the API's stable response shape.
            kb_path = Path(path) if path else default_kb_path()
            if kb_path.exists():
                try:
                    self._bm25 = KnowledgeBase(path=kb_path)
                    self.documents = [self._from_record(record) for record in self._bm25.documents]
                except (OSError, ValueError, json.JSONDecodeError):
                    self.documents = self._load(path) or DEFAULT_DOCUMENTS
            else:
                self.documents = self._load(path) or DEFAULT_DOCUMENTS

    @staticmethod
    def _from_record(record: dict) -> KnowledgeDocument:
        identifier = str(record.get("id", "kb-unknown"))
        failure_map = {
            "oom": "out_of_memory", "disk": "disk_full", "storage": "disk_full",
            "upstream-refused": "upstream_unavailable", "upstream-timeout": "request_timeout",
            "permission": "permission_denied", "image-pull": "missing_dependency",
            "crash-loop": "application_crash", "service-failed": "application_crash",
            "dns-failed": "upstream_unavailable", "tls-certificate": "certificate_error", "ssh-auth-failure": "authentication_failure",
            "cpu-saturation": "cpu_saturation", "database-connections": "database_connection_exhausted",
            "database-slow-query": "database_slow_query", "queue-backlog": "message_queue_backlog",
        }
        failure_types = tuple(str(item) for item in record.get("failure_types", [])) or tuple(value for key, value in failure_map.items() if key in identifier)
        tags = tuple(str(tag) for tag in record.get("tags", []))
        steps = record.get("steps", [])
        commands = record.get("commands", [])
        symptoms = record.get("symptoms", [])
        content = " ".join(str(part) for part in [record.get("root_cause", ""), *symptoms, *steps, *commands] if part)
        summary = str(record.get("root_cause", record.get("summary", record.get("title", ""))))
        category = str(record.get("source", record.get("category", "general")))
        if not content:
            content = str(record.get("content", summary))
        references = record.get("source_urls", record.get("references", []))
        source_urls = tuple(str(item.get("url", "")) if isinstance(item, dict) else str(item) for item in references if item)
        source_urls = tuple(url for url in source_urls if url.startswith(("https://", "http://", "/api/incidents/")))
        return KnowledgeDocument(identifier, str(record.get("title", identifier)), category, tags, summary, content, failure_types, tuple(str(item) for item in steps), tuple(str(item) for item in commands), source_urls, str(record["updated_at"]) if record.get("updated_at") else None, str(record.get("trust_level", "curated_runbook" if source_urls else "unverified")))

    @staticmethod
    def _load(path: str | Path | None) -> list[KnowledgeDocument] | None:
        if not path or not Path(path).exists():
            return None
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return [KnowledgeStore._from_record(d) for d in raw if isinstance(d, dict)]

    def search(self, query: str, failure_type: str | None = None, limit: int = 5, *, source: str | None = None, metadata_filters: dict | None = None) -> list[KnowledgeMatch]:
        if limit <= 0:
            return []
        source = "kubernetes" if source == "k8s" else source
        if self._bm25 is not None:
            records = self._bm25.search(query, source=source, limit=limit, metadata_filters=metadata_filters)
            # BM25 scores are unbounded. Normalize against the best result so
            # the API stays in [0, 1] and the UI exposes useful relative
            # relevance instead of several saturated 100% values.
            best = max((float(record.get("score", 0.0)) for record in records), default=0.0)
            return [self._match(self._from_record(record), (float(record.get("score", 0.0)) / best) if best > 0 else 0.0) for record in records]
        q = set(t for t in _TOKEN.findall(query.lower()) if t not in _STOP)
        scored: list[tuple[float, KnowledgeDocument]] = []
        for doc in self.documents:
            if source and doc.category.lower() != source.lower():
                continue
            if metadata_filters and not all(getattr(doc, key, None) == value for key, value in metadata_filters.items()):
                continue
            text = " ".join((doc.title, doc.category, " ".join(doc.tags), doc.summary, doc.content, " ".join(doc.failure_types))).lower()
            terms = set(_TOKEN.findall(text))
            overlap = len(q & terms) / max(1, len(q))
            type_bonus = 0.45 if failure_type and failure_type in doc.failure_types else 0
            score = min(1.0, overlap * 0.6 + type_bonus)
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda pair: (-pair[0], pair[1].id))
        return [self._match(d, score) for score, d in scored[:limit]]

    @staticmethod
    def _match(document: KnowledgeDocument, score: float) -> KnowledgeMatch:
        return KnowledgeMatch(id=document.id, title=document.title, category=document.category, tags=list(document.tags), summary=document.summary, score=round(max(0.0, min(1.0, score)), 4), excerpt=document.content, steps=list(document.steps), commands=list(document.commands), source_urls=list(document.source_urls), updated_at=document.updated_at, trust_level=document.trust_level)

    def all(self) -> list[KnowledgeMatch]:
        return [self._match(d, 1.0) for d in self.documents]
