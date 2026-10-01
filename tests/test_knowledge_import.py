import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.agent import ReActAgent
from app.knowledge_api import KnowledgeRepository, RunbookDocument, create_knowledge_router


def _document(identifier="custom-allocator", **overrides):
    return RunbookDocument.model_validate({
        "id": identifier,
        "title": "Custom allocator incident runbook",
        "source": "server",
        "root_cause": "An application allocator limit is exhausted.",
        "symptoms": ["customallocator Out of memory"],
        "tags": ["customallocator", "out_of_memory"],
        "failure_types": ["out_of_memory"],
        "steps": ["Inspect customallocator configured quota and compare with the incident window."],
        "commands": ["ps aux --sort=-rss"],
        "references": ["https://wiki.example.test/customallocator"],
        **overrides,
    })


def _base(tmp_path, *, bom=False):
    path = tmp_path / "base.json"
    path.write_text(json.dumps([{
        "id": "builtin-io", "title": "Disk I/O", "source": "server", "root_cause": "A device failed.",
        "steps": ["Inspect device health"], "commands": [], "symptoms": ["I/O error"], "tags": ["disk"],
    }]), encoding="utf-8-sig" if bom else "utf-8")
    return path


def test_import_survives_restart_and_participates_in_local_diagnosis(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MODE", "local")
    base = _base(tmp_path, bom=True)
    repository = KnowledgeRepository(tmp_path / "data", str(base))
    imported = _document()
    assert repository.import_documents([imported]) == [imported.id]
    restarted = KnowledgeRepository(tmp_path / "data", str(base))
    assert len(restarted.store.documents) == 2
    result = ReActAgent(store=restarted.store).diagnose("ERROR customallocator Out of memory", "server")
    assert result.knowledge[0].id == imported.id
    assert result.knowledge[0].source_urls == imported.references
    assert result.knowledge[0].trust_level == "personal"
    assert result.knowledge[0].updated_at
    assert any(step.description == imported.steps[0] and imported.id in step.knowledge_refs for step in result.steps)
    assert any(step.command == imported.commands[0] for step in result.steps)
    assert all(step.execution == "advice_only" for step in result.steps)


def test_import_can_update_personal_id_without_duplicate_record(tmp_path):
    repository = KnowledgeRepository(tmp_path / "data", str(_base(tmp_path)))
    repository.import_documents([_document()])
    repository.import_documents([_document(title="Updated allocator runbook")])
    reloaded = KnowledgeRepository(tmp_path / "data", str(repository.base_path))
    assert len(reloaded.store.documents) == 2
    assert next(item.title for item in reloaded.store.documents if item.id == "custom-allocator") == "Updated allocator runbook"


def test_builtin_override_and_duplicate_batch_do_not_mutate_active_store(tmp_path):
    repository = KnowledgeRepository(tmp_path / "data", str(_base(tmp_path)))
    before = repository.active_path.read_bytes()
    old_store = repository.store
    with pytest.raises(ValueError, match="内置知识"):
        repository.import_documents([_document("builtin-io")])
    with pytest.raises(ValueError, match="重复 ID"):
        repository.import_documents([_document(), _document()])
    assert repository.store is old_store
    assert repository.active_path.read_bytes() == before
    assert not repository.custom_path.exists()


def test_existing_custom_file_cannot_override_builtins_on_restart(tmp_path):
    repository = KnowledgeRepository(tmp_path / "data", str(_base(tmp_path)))
    before = repository.active_path.read_bytes()
    repository.custom_path.write_text(json.dumps([_document("builtin-io").model_dump()]), encoding="utf-8-sig")
    with pytest.raises(ValueError, match="内置知识"):
        KnowledgeRepository(tmp_path / "data", str(repository.base_path))
    assert repository.active_path.read_bytes() == before


@pytest.mark.parametrize("failed_target", ["active", "custom"])
def test_write_failure_rolls_back_disk_and_keeps_memory_store(tmp_path, monkeypatch, failed_target):
    repository = KnowledgeRepository(tmp_path / "data", str(_base(tmp_path)))
    repository.import_documents([_document()])
    active = repository.active_path.read_bytes()
    custom = repository.custom_path.read_bytes()
    old_store = repository.store
    original_replace = Path.replace
    fail_path = repository.active_path if failed_target == "active" else repository.custom_path
    failed = False

    def replace(path, target):
        nonlocal failed
        if Path(target) == fail_path and not failed:
            failed = True
            raise OSError("injected write failure")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", replace)
    with pytest.raises(OSError, match="injected write failure"):
        repository.import_documents([_document("another-personal", title="New runbook")])
    assert repository.store is old_store
    assert repository.active_path.read_bytes() == active
    assert repository.custom_path.read_bytes() == custom
    assert list(repository.data_path.glob("*.tmp")) == []
    restarted = KnowledgeRepository(repository.data_path, str(repository.base_path))
    assert {item.id for item in restarted.store.documents} == {"builtin-io", "custom-allocator"}


def test_candidate_validation_failure_preserves_previous_disk(tmp_path, monkeypatch):
    repository = KnowledgeRepository(tmp_path / "data", str(_base(tmp_path)))
    before = repository.active_path.read_bytes()
    old_store = repository.store
    def fail_build(records):
        raise ValueError("candidate invalid")
    monkeypatch.setattr(repository, "_build_store", fail_build)
    with pytest.raises(ValueError, match="candidate invalid"):
        repository.import_documents([_document()])
    assert repository.active_path.read_bytes() == before
    assert repository.store is old_store
    assert not repository.custom_path.exists()


def test_runbook_accepts_structured_steps_and_retains_all_sources():
    document = _document(steps=[{"title": "Check quota", "description": "Check allocator quota", "command": "free -h"}], commands=[], source_urls=["/api/incidents/incident-123/export"])
    assert document.steps == ["Check allocator quota"]
    assert document.commands == ["free -h"]
    assert document.source_urls == ["https://wiki.example.test/customallocator", "/api/incidents/incident-123/export"]
    from app.knowledge import KnowledgeStore
    match = KnowledgeStore._match(KnowledgeStore._from_record(document.model_dump()), 1.0)
    assert match.source_urls == document.source_urls


@pytest.mark.parametrize("overrides", [
    {"id": " "}, {"title": " "}, {"root_cause": " "},
    {"references": ["javascript:alert(1)"]}, {"references": ["/api/incidents/../evil"]},
    {"references": [{"url": "https://example.test"}]},
    {"updated_at": "not-a-date"}, {"steps": [{"command": "free -h"}]},
    {"steps": [{"description": "Check memory"}], "commands": 123},
])
def test_invalid_import_fields_return_validation_errors(overrides):
    with pytest.raises(ValidationError):
        _document(**overrides)


def test_json_bom_upload_and_api_store_refresh(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MODE", "local")
    repository = KnowledgeRepository(tmp_path / "data", str(_base(tmp_path)))
    agent = ReActAgent(store=repository.store)
    audit = []
    operations = SimpleNamespace(audit=lambda *args: audit.append(args))
    app = FastAPI()
    app.include_router(create_knowledge_router(repository, agent, operations))
    content = b"\xef\xbb\xbf" + json.dumps({"documents": [_document().model_dump()]}).encode("utf-8")
    response = TestClient(app).post("/api/knowledge/import", content=content, headers={"Content-Type": "application/json"})
    assert response.status_code == 201, response.text
    assert response.json()["ids"] == ["custom-allocator"]
    assert agent.store is repository.store
    assert audit[0][0] == "knowledge_imported"
