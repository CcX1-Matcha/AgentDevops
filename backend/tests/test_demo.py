import asyncio

import pytest
from fastapi import HTTPException

from app.agent import ReActAgent
from app.demo import DemoSources
from app.operations import OperationsService
from app.ops_models import SourcePatch


def test_removed_demo_source_is_registered_before_append(tmp_path):
    async def scenario():
        service = OperationsService(tmp_path / "ops.sqlite3", ReActAgent())
        demo = DemoSources(service, tmp_path)
        demo.initialize()
        old_id = demo.sources["kubernetes"]["id"]
        service.delete_source(old_id)
        result = demo.append("kubernetes")
        assert result["source_id"] != old_id
        await service.start()
        try:
            await service.scan_source(result["source_id"])
            await service.wait_for_idle()
            incident = service.list_incidents()["items"][0]
            assert incident["failure_type"] == "k8s_crash_loop"
            assert incident["is_demo"] and incident["diagnosis"]
        finally:
            await service.stop()
    asyncio.run(scenario())


def test_paused_demo_does_not_report_an_undetectable_append_as_success(tmp_path):
    service = OperationsService(tmp_path / "ops.sqlite3", ReActAgent())
    demo = DemoSources(service, tmp_path)
    demo.initialize()
    source = demo.sources["nginx"]
    service.update_source(source["id"], SourcePatch(enabled=False))
    with pytest.raises(HTTPException) as error:
        demo.append("nginx")
    assert error.value.status_code == 409
