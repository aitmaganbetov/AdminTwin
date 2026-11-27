"""Kill switch на уровне оркестратора (§11.7, §21): задачи отменяются < 5 с, даже когда
агенты «висят» в вызове LLM или инструмента; новые задачи отклоняются."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import httpx

from admintwin_ai.contracts.task_state import TaskState
from admintwin_ai.evals.harness import FixtureBackend
from admintwin_ai.orchestrator.tasks import TaskRejectedError
from admintwin_ai.service.app import create_app
from admintwin_ai.service.runtime import fake_registry
from admintwin_ai.tools.registry import ToolOutput

from support import TENANT_A, TENANT_B
from svc import MVP_PROFILES, TOKEN, BlockingDiagnostician, golden, make_runtime, scope_of

KILL_BUDGET_MS = 5000


class BlockingBackend(FixtureBackend):
    """Вызов инструмента «зависает» (медленный коннектор) до release."""

    def __init__(self, *a: Any, block_tool: str, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.block_tool = block_tool
        self.release = threading.Event()
        self.entered = threading.Semaphore(0)

    def fetch(self, tool: str, tenant_id: str, params: dict[str, Any]) -> ToolOutput:
        if tool == self.block_tool:
            self.entered.release()
            self.release.wait(timeout=60)
        return super().fetch(tool, tenant_id, params)


class MultiTenantBackend:
    def __init__(self, backends: dict[str, Any]) -> None:
        self.backends = backends

    def asset_exists(self, tenant_id: str, asset_id: str) -> bool:
        b = self.backends.get(tenant_id)
        return b is not None and b.asset_exists(tenant_id, asset_id)

    def fetch(self, tool: str, tenant_id: str, params: dict[str, Any]) -> ToolOutput:
        return self.backends[tenant_id].fetch(tool, tenant_id, params)


async def _acquire(sem: threading.Semaphore, n: int, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    got = 0
    while got < n:
        if sem.acquire(blocking=False):
            got += 1
            continue
        assert time.monotonic() < deadline, f"only {got}/{n} calls in flight"
        await asyncio.sleep(0.005)


async def test_kill_cancels_tasks_mid_llm_and_mid_tool_call_under_5s() -> None:
    case = golden("http502-upstream-oom-002")
    provider = BlockingDiagnostician({"network-engineer", "dba-engineer"})
    blocking = BlockingBackend(case, TENANT_A, block_tool="docker.container.inspect")
    backend = MultiTenantBackend({TENANT_A: blocking, TENANT_B: FixtureBackend(case, TENANT_B)})
    rt, core = make_runtime(backend=backend, registry=fake_registry(MVP_PROFILES,
                                                                     provider=provider))
    orch = rt.orchestrator
    await orch.start()
    try:
        tasks_a = []
        for _ in range(3):
            t = orch.manager.create(tenant_id=TENANT_A, kind="rca", objective="HTTP 502",
                                    incident_id=None, asset_ids=scope_of(case))
            orch.manager.start(t)
            tasks_a.append(t)
        t_b = orch.manager.create(tenant_id=TENANT_B, kind="diagnose", objective="HTTP 502",
                                  asset_ids=scope_of(case))
        orch.manager.start(t_b)
        # агенты tenant A «висят»: 6 вызовов LLM (network+dba × 3) и 3 вызова инструмента
        await _acquire(provider.entered, 6)
        await _acquire(blocking.entered, 3)
        assert all(t.state is TaskState.RUNNING for t in tasks_a)

        started = time.monotonic()
        report = await orch.manager.kill(TENANT_A, platform=False, actor="user:operator",
                                         reason="operator pressed kill switch")
        elapsed_ms = (time.monotonic() - started) * 1000
        assert elapsed_ms < KILL_BUDGET_MS and report.elapsed_ms < KILL_BUDGET_MS
        assert set(report.cancelled) >= {t.id for t in tasks_a}
        assert report.cancellation_pending == []  # успех только с подтверждением
        assert set(report.confirmed) == set(report.cancelled)
        for t in tasks_a:
            assert t.state is TaskState.CANCELLED
            assert "kill switch" in (t.reason or "")
            for cid in t.children:
                assert orch.manager.get(cid).terminal
        # новые задачи tenant A отклоняются немедленно
        try:
            orch.manager.create(tenant_id=TENANT_A, kind="rca", objective="x")
            raise AssertionError("new task must be rejected")
        except TaskRejectedError:
            pass
        # tenant B не затронут
        assert t_b.state is not TaskState.CANCELLED
    finally:
        provider.release.set()
        blocking.release.set()
        await asyncio.sleep(0.2)
        # потоки, завершившие «зависший» вызов после kill, ничего не записали в ядро
        assert not [r for r in core.requests if r.url.path == "/api/v1/changes"
                    and r.headers.get("X-AdminTwin-Tenant") == TENANT_A]
        await orch.close()


async def test_platform_kill_over_http_cancels_everything_under_5s() -> None:
    case = golden("http502-upstream-oom-002")
    provider = BlockingDiagnostician({"network-engineer", "devops-engineer", "dba-engineer"})
    backend = MultiTenantBackend({TENANT_A: FixtureBackend(case, TENANT_A),
                                  TENANT_B: FixtureBackend(case, TENANT_B)})
    rt, _ = make_runtime(backend=backend, registry=fake_registry(MVP_PROFILES,
                                                                  provider=provider))
    app = create_app(rt)
    headers = {"X-AdminTwin-Service-Token": TOKEN}
    try:
        async with app.router.lifespan_context(app), httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://orch") as client:
            ids = []
            for tenant in (TENANT_A, TENANT_B):
                r = await client.post("/v1/tasks", headers=headers, json={
                    "kind": "rca", "tenant_id": tenant, "objective": "HTTP 502",
                    "scope": {"asset_ids": scope_of(case)}, "requested_by": "user-1"})
                assert r.status_code == 202, r.text
                ids.append((tenant, r.json()["task_id"]))
            await _acquire(provider.entered, 6)
            started = time.monotonic()
            r = await client.post("/v1/kill", headers={**headers,
                                                       "X-AdminTwin-Actor-Kind": "service"},
                                  json={"platform": True, "reason": "platform kill"})
            elapsed_ms = (time.monotonic() - started) * 1000
            assert r.status_code == 200, r.text
            body = r.json()
            assert elapsed_ms < KILL_BUDGET_MS and body["elapsed_ms"] < KILL_BUDGET_MS
            assert body["scope"] == "platform" and body["cancellation_pending"] == []
            for tenant, tid in ids:
                r = await client.get(f"/v1/tasks/{tid}", headers={
                    **headers, "X-AdminTwin-Tenant": tenant})
                assert r.json()["status"] == "cancelled"
                assert all(c["status"] in ("cancelled", "completed", "failed", "timed_out")
                           for c in r.json()["children"])
            r = await client.post("/v1/tasks", headers=headers, json={
                "kind": "diagnose", "tenant_id": TENANT_A, "objective": "x"})
            assert r.status_code == 409
            assert r.json()["type"] == "https://errors.admintwin.io/kill-switch-active"
            # снятие kill switch (ядро вызывает с active=false)
            r = await client.post("/v1/kill", headers={**headers,
                                                       "X-AdminTwin-Actor-Kind": "service"},
                                  json={"platform": True, "active": False})
            assert r.status_code == 200 and r.json()["active"] is False
            r = await client.post("/v1/tasks", headers=headers, json={
                "kind": "diagnose", "tenant_id": TENANT_A, "objective": "x"})
            assert r.status_code == 202
    finally:
        provider.release.set()


async def test_bus_handlers_in_flight_are_cancelled_by_kill() -> None:
    case = golden("http502-upstream-oom-002")
    provider = BlockingDiagnostician({"devops-engineer"})
    rt, _ = make_runtime(case=case, registry=fake_registry(MVP_PROFILES, provider=provider))
    orch = rt.orchestrator
    await orch.start()
    try:
        t = orch.manager.create(tenant_id=TENANT_A, kind="diagnose", objective="HTTP 502",
                                asset_ids=scope_of(case))
        orch.manager.start(t)
        await _acquire(provider.entered, 1)
        report = await orch.manager.kill(TENANT_A, platform=False)
        assert report.cancellation_pending == []
        await asyncio.sleep(0.05)
        assert orch.bus._cancel._inflight == {}  # type: ignore[attr-defined]
        devops = [orch.manager.get(c) for c in t.children
                  if orch.manager.get(c).agent_id == "devops-engineer"]
        assert devops and devops[0].state is TaskState.CANCELLED
    finally:
        provider.release.set()
        await orch.close()
