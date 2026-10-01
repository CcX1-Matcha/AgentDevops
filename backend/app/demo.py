"""Demo events go through the same file collector as registered real logs."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel


class DemoEvent(BaseModel):
    scenario: Literal["nginx", "docker", "kubernetes", "server"] = "nginx"


class DemoSources:
    def __init__(self, service, data_path: Path):
        self.service = service
        self.path = data_path / "demo"
        self.sources: dict[str, dict] = {}

    def initialize(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        for scenario, name in [("nginx", "订单网关"), ("docker", "容器任务"), ("kubernetes", "集群工作负载"), ("server", "日志主机")]:
            path = self.path / f"{scenario}.log"
            path.touch(exist_ok=True)
            self.sources[scenario] = self.service.ensure_source({
                "name": f"演示 · {name}", "path": str(path.resolve()), "source": scenario,
                "service": f"demo-{scenario}", "environment": "demo", "instance": "local-demo",
                "enabled": True, "read_existing": False, "is_demo": True, "poll_interval_seconds": 1,
            })

    def append(self, scenario: str) -> dict:
        source = self.service.ensure_source(self.sources[scenario])
        self.sources[scenario] = source
        if not source["enabled"]:
            raise HTTPException(status_code=409, detail="演示数据源已暂停，请在数据源页启用监控后重试。")
        stamp = datetime.now(timezone.utc).isoformat()
        messages = {
            "nginx": "nginx [error] connect() failed (111: Connection refused) while connecting to upstream upstream=http://127.0.0.1:8080/api/orders",
            "docker": 'docker container oom orders-worker OOMKilled=true memory_limit=512Mi',
            "kubernetes": 'kubelet Warning BackOff restarting failed container api in pod orders-api; Reason: CrashLoopBackOff namespace=demo',
            "server": "server ERROR write /var/log/orders.log: No space left on device ENOSPC",
        }
        with Path(source["path"]).open("a", encoding="utf-8") as stream:
            stream.write(f"{stamp} {messages[scenario]}\n")
        # The HTTP request only appends data. The polling worker detects and
        # diagnoses the error, exactly as it does for externally written logs.
        return {"status": "accepted", "source_id": source["id"], "is_demo": True, "scenario": scenario}


def create_demo_router(demo: DemoSources) -> APIRouter:
    router = APIRouter(prefix="/api/demo", tags=["demo"])

    @router.post("/events", status_code=202)
    def inject(payload: DemoEvent, request: Request):
        if os.getenv("OPS_DEMO_ENABLED", "true").lower() not in {"1", "true", "yes"}:
            raise HTTPException(status_code=403, detail="此环境已关闭演示异常注入。")
        if not demo.sources:
            demo.initialize()
        result = demo.append(payload.scenario)
        demo.service.audit("demo_event_appended", "source", result["source_id"], getattr(request.state, "operator", "local-operator"), result)
        return result

    return router
