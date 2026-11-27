"""Маркерный тест (§21 [MVP]): ``pii``/``secret`` и неопределённая
классификация никогда не доходят до внешнего провайдера."""

from __future__ import annotations

import itertools

import pytest

from admintwin_ai.agents import AgentDefinition
from admintwin_ai.audit import InMemoryAuditSink
from admintwin_ai.budgets import BudgetLedger
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.gateway import AIGateway, CallContext, GatewayStatus
from admintwin_ai.masking import Masker
from admintwin_ai.orchestrator import gateway_caller, run_agent
from admintwin_ai.profiles import ModelProfile, ProfileRegistry
from admintwin_ai.providers import ChatMessage, CompletionRequest, CompletionResult, ToolCall
from admintwin_ai.routing.router import Router, TenantAIPolicy
from admintwin_ai.tools import InMemoryReadBackend, ToolInvoker, ToolOutput, ToolRegistry

from fakes import FakeProvider, make_registry, tool_call_result
from support import ASSET_WEB, TENANT_A, ctx_for

MARKER = "MARKER-PII-7f3a ivan.petrov@acme.kz 10.66.66.66 ACME\\ipetrov"
PERIMETER_BOUND = [DataClass.PII, DataClass.SECRET, DataClass.UNKNOWN]


def _setup(local: bool = True,
           tenant: TenantAIPolicy | None = None) -> tuple[AIGateway, list[FakeProvider]]:
    claude = FakeProvider("claude", external=True)
    openai = FakeProvider("openai", external=True)
    if local:
        registry = make_registry(claude=claude, openai=openai)
    else:
        registry = ProfileRegistry(
            [ModelProfile(id="claude-primary", provider="claude", model="c"),
             ModelProfile(id="openai-secondary", provider="openai", model="o")],
            {"claude": claude, "openai": openai})
    gw = AIGateway(registry, Router(registry), BudgetLedger(), InMemoryAuditSink(),
                   masker=Masker())
    return gw, [claude, openai]


def _ctx(tenant: TenantAIPolicy | None = None) -> CallContext:
    return CallContext(tenant=tenant or TenantAIPolicy(tenant_id=TENANT_A),
                       agent_id="linux-admin", primary_profile="claude-primary",
                       secondary_profile="openai-secondary")


@pytest.mark.parametrize(("dc", "task"), list(itertools.product(PERIMETER_BOUND, list(TaskClass))))
def test_never_reaches_external_with_local(dc: DataClass, task: TaskClass) -> None:
    gw, externals = _setup()
    req = CompletionRequest(messages=[ChatMessage(role="user", content=MARKER)])
    resp = gw.complete(_ctx(), req, data_class=dc, task_class=task)
    assert resp.status is GatewayStatus.OK
    assert resp.served_by is not None and not resp.served_by.external
    for ext in externals:
        assert ext.requests == [], f"{dc}/{task} leaked to {ext.provider_id}"


@pytest.mark.parametrize("dc", PERIMETER_BOUND)
def test_fail_closed_without_local(dc: DataClass) -> None:
    gw, externals = _setup(local=False)
    req = CompletionRequest(messages=[ChatMessage(role="user", content=MARKER)])
    resp = gw.complete(_ctx(), req, data_class=dc, task_class=TaskClass.RCA)
    assert resp.status is GatewayStatus.HUMAN_REVIEW
    assert all(ext.requests == [] for ext in externals)
    status, _ = gw.embed(_ctx(), [MARKER], data_class=dc)
    assert status is GatewayStatus.HUMAN_REVIEW
    assert all(ext.embedded == [] for ext in externals)


def test_secret_never_external_even_with_masking_opt_in() -> None:
    tenant = TenantAIPolicy(tenant_id=TENANT_A, pii_masked_external=True)
    gw, externals = _setup(local=False)
    req = CompletionRequest(messages=[ChatMessage(role="user", content=MARKER)])
    resp = gw.complete(_ctx(tenant), req, data_class=DataClass.SECRET, task_class=TaskClass.RCA)
    assert resp.status is GatewayStatus.HUMAN_REVIEW
    assert all(ext.requests == [] for ext in externals)


def test_pii_opt_in_sends_only_masked_values() -> None:
    tenant = TenantAIPolicy(tenant_id=TENANT_A, pii_masked_external=True)
    gw, externals = _setup(local=False)
    req = CompletionRequest(messages=[ChatMessage(role="user", content=MARKER)])
    resp = gw.complete(_ctx(tenant), req, data_class=DataClass.PII, task_class=TaskClass.RCA)
    assert resp.status is GatewayStatus.OK
    seen = externals[0].all_text()
    for raw in ("ivan.petrov@acme.kz", "10.66.66.66", "ACME\\ipetrov"):
        assert raw not in seen


def test_pii_tool_output_moves_conversation_to_local(
        tool_registry: ToolRegistry, backend: InMemoryReadBackend,
        agents: dict[str, AgentDefinition]) -> None:
    """Сквозной путь: журнал с ПДн (data_class=pii от источника) → следующий
    вызов модели уходит на Local, внешние провайдеры его не видят."""
    backend.set_fixture(TENANT_A, "logs.search", ToolOutput(
        data={"entries": [{"ts": "2026-11-09T05:00:00Z", "line": MARKER}]},
        data_class=DataClass.PII))
    step = {"n": 0}

    def responder(req: CompletionRequest) -> CompletionResult:
        step["n"] += 1
        if step["n"] == 1:
            return tool_call_result(ToolCall(id="c1", name="logs.search",
                                             arguments={"query": "error", "window": "15m",
                                                        "asset_id": ASSET_WEB}))
        return CompletionResult(text="done")

    claude = FakeProvider("claude", external=True, responder=responder)
    local = FakeProvider("local", external=False, responder=responder)
    registry = make_registry(claude=claude, local=local)
    gw = AIGateway(registry, Router(registry), BudgetLedger(), InMemoryAuditSink())
    agent = agents["linux-admin"]
    caller = gateway_caller(gw, _ctx(), system="linux-admin", task_class=TaskClass.RCA,
                            prompt_version=agent.prompt_version)
    invoker = ToolInvoker(tool_registry, InMemoryAuditSink(), assets=backend)
    result = run_agent(agent, tool_registry, invoker, ctx_for(agent), caller, "disk alert on web01")
    assert result.stopped == "final"
    assert result.data_class is DataClass.PII
    assert len(claude.requests) == 1  # только первый шаг, до получения ПДн
    assert "MARKER-PII-7f3a" not in claude.all_text()
    assert "MARKER-PII-7f3a" in local.all_text()
