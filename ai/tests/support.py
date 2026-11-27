"""Общие константы и помощники тестов."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

import httpx

from admintwin_ai.agents import AgentDefinition
from admintwin_ai.tools import ToolContext

TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "22222222-2222-4222-8222-222222222222"
ASSET_WEB = "aaaaaaaa-0000-4000-8000-000000000001"
ASSET_DB = "aaaaaaaa-0000-4000-8000-000000000002"
ASSET_B_ONLY = "bbbbbbbb-0000-4000-8000-000000000009"
INCIDENT = "cccccccc-0000-4000-8000-000000000001"
CORE_URL = "http://core.test"


class CoreRecorder:
    """MockTransport ядра: записывает все HTTP-запросы Tool Layer."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responder: Callable[[httpx.Request], httpx.Response] = self.default

    @staticmethod
    def default(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(202, json={"id": str(uuid.uuid4()), "status": "waiting_approval",
                                         "runbook_id": body["runbook_id"]})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responder(request)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def default_fixtures() -> dict[str, Any]:
    return {
        "asset.get": {"asset_id": ASSET_WEB, "name": "web01", "type": "linux_host",
                      "environment": "production", "criticality": "high", "data_class": "internal",
                      "legal_hold": False},
        "metrics.query": {"asset_id": ASSET_WEB, "metric": "node_load1", "window": "15m",
                          "series": [{"labels": {"instance": "web01"},
                                      "points": [["2026-11-09T05:00:00Z", 3.2]]}]},
        "logs.search": {"entries": [{"ts": "2026-11-09T05:00:00Z", "line": "upstream timed out"}]},
        "events.list": {"events": []},
        "topology.blast_radius": {"asset_id": ASSET_WEB, "nodes": [], "edges": []},
        "linux.service.status": {"unit": "nginx.service", "active_state": "active",
                                 "sub_state": "running"},
        "linux.disk.usage": {"filesystems": [{"mount": "/var", "size_bytes": 100, "used_bytes": 97,
                                              "avail_bytes": 3, "use_percent": 97.0}]},
        "docker.container.inspect": {"container": "shop-api", "image": "shop/api:1.4.2",
                                     "state": {"status": "exited", "running": False,
                                               "exit_code": 137}},
        "postgres.activity": {"max_connections": 200, "total_connections": 42, "sessions": []},
        "fortigate.policy.status": {"policies": []},
    }



def ctx_for(agent: AgentDefinition, tenant: str = TENANT_A, **kw: Any) -> ToolContext:
    return ToolContext(tenant_id=tenant, agent=agent, task_id="task-1", **kw)
