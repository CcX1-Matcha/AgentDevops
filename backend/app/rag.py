"""Small, dependency-free retrieval layer for the operations incident KB.

The project keeps retrieval deliberately local so it can be used in a restricted
SRE environment.  Documents are JSON records in ``knowledge_base/incidents.json``
and are indexed in memory with a BM25-style ranker.  The class is also useful in
unit tests because it accepts an explicit list of documents.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


_ASCII_TERM = re.compile(r"[a-z0-9][a-z0-9_.:/-]*", re.I)
_CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
_STOPWORDS = {"a", "an", "and", "are", "as", "at", "by", "for", "from", "in", "is", "it", "no", "of", "on", "or", "the", "to", "with"}


def tokenize(text: str | None) -> list[str]:
    """Tokenize mixed log text.

    ASCII words (including terms such as ``ECONNREFUSED`` and ``overlay2``) are
    kept intact.  Chinese is represented as unigrams and adjacent bigrams to
    support both short labels (``磁盘``) and longer Chinese queries without a
    third-party segmenter.
    """

    if not text:
        return []
    lowered = text.lower()
    terms: list[str] = [term for term in _ASCII_TERM.findall(lowered) if term not in _STOPWORDS]
    cjk = "".join(_CJK.findall(lowered))
    terms.extend(cjk)
    terms.extend(cjk[i : i + 2] for i in range(len(cjk) - 1))
    return terms


def _text(document: Mapping[str, Any]) -> str:
    fields = ("title", "source", "severity", "tags", "symptoms", "root_cause", "steps", "commands", "failure_types")
    values: list[str] = []
    for field in fields:
        value = document.get(field, "")
        if isinstance(value, (list, tuple)):
            values.extend(str(item) for item in value)
        else:
            values.append(str(value))
    return " ".join(values)


class KnowledgeBase:
    """In-memory BM25 index over structured incident records."""

    def __init__(self, documents: Iterable[Mapping[str, Any]] | None = None, path: str | Path | None = None) -> None:
        if documents is None:
            path = Path(path) if path else default_kb_path()
            documents = load_documents(path)
        self.documents: list[dict[str, Any]] = [dict(item) for item in documents]
        self._tokens = [Counter(tokenize(_text(item))) for item in self.documents]
        self._lengths = [sum(counter.values()) for counter in self._tokens]
        self._avgdl = sum(self._lengths) / len(self._lengths) if self._lengths else 1.0
        df: Counter[str] = Counter()
        for counter in self._tokens:
            df.update(counter.keys())
        self._idf = {
            term: math.log(1.0 + (len(self.documents) - count + 0.5) / (count + 0.5))
            for term, count in df.items()
        }

    def search(self, query: str, *, source: str | None = None, limit: int = 4, metadata_filters: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """Return the highest-scoring matching incidents.

        Source and supplied metadata filters are exact and
        case-insensitive.  Results with no lexical overlap are omitted, which
        prevents an unrelated KB article from being presented as a diagnosis.
        """

        if limit <= 0:
            return []
        query_tokens = Counter(tokenize(query))
        if not query_tokens:
            return []
        wanted = ("kubernetes" if source.lower() == "k8s" else source.lower()) if source else None
        scored: list[tuple[float, dict[str, Any]]] = []
        k1, b = 1.4, 0.75
        for index, (document, terms, length) in enumerate(zip(self.documents, self._tokens, self._lengths)):
            doc_source = str(document.get("source", "")).lower()
            if wanted and doc_source != wanted:
                continue
            if metadata_filters and not self._matches_metadata(document, metadata_filters):
                continue
            score = 0.0
            for term, qtf in query_tokens.items():
                tf = terms.get(term, 0)
                if not tf:
                    continue
                idf = self._idf.get(term, 0.0)
                norm = tf * (k1 + 1.0) / (tf + k1 * (1.0 - b + b * length / self._avgdl))
                score += idf * norm * min(qtf, 3)

            # Short labels from structured fields are useful tie breakers when
            # a query contains a status code or canonical error token.
            query_lower = query.lower()
            if query_lower and any(query_lower in str(tag).lower() for tag in document.get("tags", [])):
                score += 1.5
            if any(token in query_lower and token in _text(document).lower() for token in ("502", "504", "oom", "enospc", "eacces", "econnrefused")):
                score += 0.5
            if score <= 0.0:
                continue
            result = dict(document)
            result["score"] = round(score, 6)
            result["matched_terms"] = sorted(term for term in query_tokens if term in terms)
            scored.append((score, result))
        scored.sort(key=lambda item: (-item[0], str(item[1].get("id", ""))))
        return [result for _, result in scored[:limit]]

    @staticmethod
    def _matches_metadata(document: Mapping[str, Any], filters: Mapping[str, Any]) -> bool:
        for key, expected in filters.items():
            actual = document.get(key)
            if actual is None and isinstance(document.get("metadata"), Mapping):
                actual = document["metadata"].get(key)
            if isinstance(actual, (list, tuple)):
                if expected not in actual:
                    return False
            elif actual != expected:
                return False
        return True


def default_kb_path() -> Path:
    """Resolve the repository KB path independent of the current directory."""

    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / "knowledge_base" / "incidents.json"
        if candidate.exists():
            return candidate
    return Path("knowledge_base/incidents.json")


def load_documents(path: str | Path) -> list[dict[str, Any]]:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, list):
        raise ValueError(f"Knowledge base must be a JSON array: {file_path}")
    return [dict(item) for item in payload if isinstance(item, Mapping)]


__all__ = ["KnowledgeBase", "default_kb_path", "load_documents", "tokenize"]
