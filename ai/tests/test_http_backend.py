"""HTTP ReadBackend: read tools через Tool Service ядра (contracts §0, §1)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from admintwin_ai.agents import AgentDefinition
from admintwin_ai.audit import InMemoryAuditSink, ToolCallRecord
from admintwin_ai.classification import DataClass
from admintwin_ai.tools import ChangeProposeHandler, ToolInvoker, build_tool_registry, parse_wrapped
from admintwin_ai.tools.http_backend import HttpReadBackend

from support import ASSET_WEB, CORE_URL, TENANT_A, ctx_for

TOKEN = "svc-token-0123456789abcdef"


class Core:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.body: dict[str, Any] | None = None
        self.headers: dict[str, str] = {}
        self.fail_first: int = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path.startswith("/api/v1/assets/"):
            ok = request.url.path.endswith(ASSET_WEB)
            return httpx.Response(200 if ok else 404, json={"id": ASSET_WEB} if ok else
                                  {"type": "https://errors.admintwin.io/not-found"})
        if self.fail_first > 0:
            self.fail_first -= 1
            return httpx.Response(503, json={"title": "unavailable"})
        if request.url.path == "/api/v1/changes":
            return httpx.Response(202, json={"id": "chg-1", "status": "waiting_approval"})
        tool = request.url.path.rsplit("/", 1)[-1]
        body = self.body if self.body is not None else {
            "tool": tool, "version": "1.0.0", "data_class": "internal",
            "data": {"unit": "nginx.service", "active_state": "active", "sub_state": "running"}}
        return httpx.Response(self.status, json=body, headers=self.headers)


def _setup(core: Core) -> tuple[HttpReadBackend, ToolInvoker, InMemoryAuditSink]:
    client = httpx.Client(transport=httpx.MockTransport(core.handler))
    backend = HttpReadBackend(CORE_URL, service_token=TOKEN, client=client)
    registry = build_tool_registry(backend, ChangeProposeHandler(CORE_URL, client=client,
                                                                 service_token=TOKEN))
    audit = InMemoryAuditSink()
    return backend, ToolInvoker(registry, audit, assets=backend), audit


PARAMS = {"asset_id": ASSET_WEB, "unit": "nginx.service"}


def test_calls_core_tool_service_with_service_identity(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    _, invoker, _ = _setup(core)
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status", PARAMS)
    assert res.status == "ok", res.content
    tool_reqs = [r for r in core.requests if r.url.path.startswith("/api/v1/tools/")]
    assert len(tool_reqs) == 1
    req = tool_reqs[0]
    assert (req.method, req.url.path) == ("POST", "/api/v1/tools/linux.service.status")
    assert json.loads(req.content) == {"input": PARAMS}
    assert req.headers["X-AdminTwin-Service-Token"] == TOKEN
    assert req.headers["X-AdminTwin-Tenant"] == TENANT_A
    assert req.headers["X-AdminTwin-Actor"] == "linux-admin"
    assert req.headers["X-AdminTwin-Actor-Kind"] == "ai_agent"
    # локальная обёртка «данные, не инструкции» сохраняется
    header, body = parse_wrapped(res.content)  # type: ignore[misc]
    assert header["tool"] == "linux.service.status" and "nginx.service" in body


def test_data_class_is_max_of_core_and_contract(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    _, invoker, _ = _setup(core)
    agent = agents["linux-admin"]  # data_sensitivity_max = pii
    core.body = {"tool": "linux.service.status", "version": "1", "data_class": "pii",
                 "data": {"unit": "nginx.service", "active_state": "active",
                          "sub_state": "running"}}
    res = invoker.invoke(ctx_for(agent), "linux.service.status", PARAMS)
    assert res.status == "ok" and res.data_class is DataClass.PII
    core.body = {"tool": "linux.service.status", "version": "1", "data_class": "public",
                 "data": {"unit": "nginx.service", "active_state": "active",
                          "sub_state": "running"}}
    res = invoker.invoke(ctx_for(agent), "linux.service.status", PARAMS)
    assert res.data_class is DataClass.INTERNAL  # класс контракта не понижается ядром
    core.body = {"tool": "linux.service.status", "version": "1", "data_class": "secret",
                 "data": {"unit": "nginx.service", "active_state": "active",
                          "sub_state": "running"}}
    res = invoker.invoke(ctx_for(agent), "linux.service.status", PARAMS)
    assert res.status == "refused" and res.reason == "data_sensitivity_exceeded"
    core.body = {"tool": "linux.service.status", "version": "1", "data_class": "bogus",
                 "data": {"unit": "nginx.service", "active_state": "active",
                          "sub_state": "running"}}
    res = invoker.invoke(ctx_for(agent), "linux.service.status", PARAMS)
    assert res.status == "refused"  # неизвестный класс → unknown → fail closed


@pytest.mark.parametrize(("status", "slug"), [
    (404, "not-found"), (403, "forbidden"), (422, "invalid-params"),
    (409, "kill-switch-active"), (409, "conflict")])
def test_problem_json_becomes_refusal(agents: dict[str, AgentDefinition], status: int,
                                      slug: str) -> None:
    core = Core()
    _, invoker, audit = _setup(core)
    core.status = status
    core.body = {"type": f"https://errors.admintwin.io/{slug}", "title": "x", "status": status,
                 "detail": "core says no"}
    core.headers = {"content-type": "application/problem+json"}
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status", PARAMS)
    assert res.status == "refused" and res.reason == slug
    assert res.problem is not None and res.problem["status"] == status
    rec = [r for r in audit.records if isinstance(r, ToolCallRecord)][-1]
    assert rec.status == "refused" and rec.reason == slug


def test_unauthenticated_and_5xx_are_backend_errors(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    _, invoker, _ = _setup(core)
    core.status = 401
    core.body = {"type": "https://errors.admintwin.io/unauthenticated"}
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status", PARAMS)
    assert res.status == "error" and res.reason == "backend_error"
    core.status = 500
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status", PARAMS)
    assert res.status == "error"


def test_retries_transient_503_then_succeeds(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    _, invoker, _ = _setup(core)
    core.fail_first = 1
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status", PARAMS)
    assert res.status == "ok"
    assert len([r for r in core.requests if "/tools/" in r.url.path]) == 2


def test_output_outside_contract_is_rejected_locally(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    _, invoker, _ = _setup(core)
    core.body = {"tool": "linux.service.status", "version": "1", "data_class": "internal",
                 "data": {"unit": "x", "active_state": "exploded", "sub_state": "x",
                          "shell": "rm -rf /"}}
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status", PARAMS)
    assert res.status == "error" and res.reason == "invalid_tool_output"
    core.body = {"tool": "other.tool", "version": "1", "data_class": "internal", "data": {}}
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status", PARAMS)
    assert res.status == "error"


def test_secrets_in_core_output_are_masked(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    _, invoker, _ = _setup(core)
    secret = "AKIA" + "Q" * 16
    core.body = {"tool": "logs.search", "version": "1", "data_class": "confidential",
                 "data": {"entries": [{"ts": "2026-11-09T05:00:00Z",
                                       "line": f"password=hunter2secret aws_key={secret}"}]}}
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "logs.search",
                         {"query": "error", "window": "15m"})
    assert res.status == "ok"
    assert "hunter2secret" not in res.content and secret not in res.content


def test_asset_check_uses_cmdb_with_cache(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    backend, invoker, _ = _setup(core)
    other = "aaaaaaaa-0000-4000-8000-0000000000ff"
    res = invoker.invoke(ctx_for(agents["linux-admin"]), "linux.service.status",
                         {"asset_id": other, "unit": "nginx.service"})
    assert res.status == "refused" and res.reason == "asset_not_in_tenant"
    assert not [r for r in core.requests if "/tools/" in r.url.path]  # до ядра не дошло
    for _ in range(3):
        assert backend.asset_exists(TENANT_A, ASSET_WEB)
    asset_reqs = [r for r in core.requests if r.url.path.startswith("/api/v1/assets/")]
    assert len(asset_reqs) == 2  # other + ASSET_WEB один раз (кэш)
    assert all(r.headers["X-AdminTwin-Service-Token"] == TOKEN for r in asset_reqs)


def test_change_propose_sends_service_token(agents: dict[str, AgentDefinition]) -> None:
    core = Core()
    _, invoker, _ = _setup(core)
    res = invoker.invoke(ctx_for(agents["devops-engineer"]), "change.propose", {
        "runbook_id": "docker.container.restart", "asset_id": ASSET_WEB,
        "params": {"container_id": "3f2a9c1b7d4e"}, "reason": "container exited 137 OOM"})
    assert res.status == "ok", res.content
    req = next(r for r in core.requests if r.url.path == "/api/v1/changes")
    assert req.headers["X-AdminTwin-Service-Token"] == TOKEN
    assert req.headers["X-AdminTwin-Actor"] == "devops-engineer"
    assert req.headers["X-AdminTwin-Actor-Kind"] == "ai_agent"
    assert req.headers["Idempotency-Key"]
