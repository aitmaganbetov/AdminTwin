"""Помощники тестов сервиса оркестратора: runtime на фикстурах golden-кейсов, мок ядра."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Callable, Iterable
from typing import Any

import httpx

from admintwin_ai.bus.inprocess import InProcessBus
from admintwin_ai.contracts.task_state import TaskState
from admintwin_ai.evals.fake_model import ScriptedDiagnostician
from admintwin_ai.evals.harness import FixtureBackend
from admintwin_ai.evals.metrics import EvalCase, load_dataset
from admintwin_ai.orchestrator.engine import BudgetSettings, EngineSettings
from admintwin_ai.orchestrator.tasks import Task
from admintwin_ai.profiles import ProfileRegistry
from admintwin_ai.providers.base import CompletionRequest, CompletionResult
from admintwin_ai.resources import data_path
from admintwin_ai.service.runtime import Runtime, build_runtime, fake_registry
from admintwin_ai.service.settings import ServiceSettings

from support import TENANT_A

TOKEN = "test-service-token-0123456789abcdef"
CORE = "http://core.test"
MVP_PROFILES = ["claude-primary", "openai-secondary"]


def golden(case_id: str) -> EvalCase:
    for c in load_dataset(data_path("evals", "golden", "mvp-v2.jsonl")):
        if c.case_id == case_id:
            return c
    raise KeyError(case_id)


class CoreMock:
    """Ядро для тестов: записывает запросы; ``/api/v1/changes`` → waiting_approval."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.lock = threading.Lock()
        self.tool_responder: Callable[[httpx.Request], httpx.Response] | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.requests.append(request)
        path = request.url.path
        if path == "/api/v1/changes":
            body = json.loads(request.content)
            return httpx.Response(202, json={"id": f"chg-{len(self.requests)}",
                                             "status": "waiting_approval",
                                             "runbook_id": body["runbook_id"]})
        if path.startswith("/api/v1/tools/") and self.tool_responder is not None:
            return self.tool_responder(request)
        if path.startswith("/api/v1/assets/"):
            return httpx.Response(200, json={"id": path.rsplit("/", 1)[-1]})
        return httpx.Response(202, json={})

    def sync(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def async_(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    def paths(self) -> list[str]:
        with self.lock:
            return [r.url.path for r in self.requests]

    def rca_posts(self) -> list[httpx.Request]:
        with self.lock:
            return [r for r in self.requests if r.url.path.endswith("/rca")]


def make_runtime(*, backend: Any | None = None, case: EvalCase | None = None,
                 tenant: str = TENANT_A, registry: ProfileRegistry | None = None,
                 core: CoreMock | None = None, budgets: BudgetSettings | None = None,
                 engine: EngineSettings | None = None, token: str | None = TOKEN,
                 bus: Any | None = None, core_url: str = CORE, ledger: Any | None = None
                 ) -> tuple[Runtime, CoreMock]:
    core = core or CoreMock()
    settings = ServiceSettings(service_token=token, dev_insecure=token is None,
                               core_url=core_url,
                               engine=engine or EngineSettings(result_grace_s=5.0),
                               budgets=budgets or BudgetSettings())
    if backend is None and case is not None:
        backend = FixtureBackend(case, tenant)
    registry = registry or fake_registry([*MVP_PROFILES, "claude-economy", "local-default"])
    rt = build_runtime(settings, registry=registry, backend=backend, core_http=core.sync(),
                       core_async=core.async_(), bus=bus or InProcessBus(), ledger=ledger)
    return rt, core


async def wait_for(task: Task, states: Iterable[TaskState], timeout_s: float = 20.0) -> Task:
    targets = set(states)
    async with asyncio.timeout(timeout_s):
        while task.state not in targets:
            await asyncio.sleep(0.005)
    return task


def scope_of(case: EvalCase) -> list[str]:
    return list(case.input["scope"])


class BlockingDiagnostician(ScriptedDiagnostician):
    """Офлайн-модель, «зависающая» в вызове LLM у выбранных агентов (kill switch)."""

    def __init__(self, block_agents: set[str], **kw: Any) -> None:
        super().__init__(**kw)
        self.block_agents = block_agents
        self.release = threading.Event()
        self.entered = threading.Semaphore(0)

    def complete(self, request: CompletionRequest) -> CompletionResult:
        system = request.system or ""
        if any(f"agent_id: {a};" in system for a in self.block_agents):
            self.entered.release()
            self.release.wait(timeout=60)
        return super().complete(request)
