"""AI Provider Gateway: маршрут + маскирование + fallback + бюджет + аудит."""

from __future__ import annotations

import json

from admintwin_ai.audit import InMemoryAuditSink, LLMCallRecord, sha256_of
from admintwin_ai.budgets import BudgetLedger, BudgetLevel, BudgetLimits, BudgetScope
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.errors import (
    ProviderRateLimitedError,
    ProviderRequestError,
    ProviderUnavailableError,
)
from admintwin_ai.gateway import AIGateway, CallContext, GatewayStatus
from admintwin_ai.masking import Masker
from admintwin_ai.providers import ChatMessage, CompletionRequest, CompletionResult, ToolCall, Usage
from admintwin_ai.routing.router import Router, TenantAIPolicy

from fakes import FakeProvider, make_registry

PROMPT = "nginx on web01.prod.acme.kz (10.20.0.15) returns 502; user=ivanov"


def _gateway(registry=None, ledger=None):  # type: ignore[no-untyped-def]
    registry = registry or make_registry()
    audit = InMemoryAuditSink()
    gw = AIGateway(registry, Router(registry), ledger or BudgetLedger(), audit, masker=Masker())
    return gw, audit, registry


def _ctx(**kw: object) -> CallContext:
    base: dict[str, object] = {
        "tenant": TenantAIPolicy(tenant_id="t1", local_profile="local-default"),
        "agent_id": "linux-admin", "task_id": "task-1", "primary_profile": "claude-primary",
        "secondary_profile": "openai-secondary",
    }
    base.update(kw)
    return CallContext.model_validate(base)


def _request(content: str = PROMPT) -> CompletionRequest:
    return CompletionRequest(system="You are linux-admin", prompt_version="linux-admin-v1",
                             messages=[ChatMessage(role="user", content=content)])


def test_external_call_is_masked_and_unmasked() -> None:
    claude = FakeProvider("claude", external=True, responder=lambda req: CompletionResult(
        text=f"echo: {req.messages[0].content}",
        tool_calls=[ToolCall(id="c1", name="logs.search",
                             arguments={"query": "<HOST_1> 502", "window": "15m"})],
        finish_reason="tool_calls", usage=Usage(input_tokens=1000, output_tokens=500),
        model=req.model))
    gw, _, _ = _gateway(make_registry(claude=claude))
    resp = gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL,
                       task_class=TaskClass.RCA)
    assert resp.status is GatewayStatus.OK
    sent = claude.requests[0]
    assert sent.model == "claude-model-from-config"
    for raw in ("web01.prod.acme.kz", "10.20.0.15", "ivanov"):
        assert raw not in claude.all_text()
    assert "<HOST_1>" in sent.messages[0].content and "<IP_1>" in sent.messages[0].content
    # ответ демаскирован, включая аргументы вызова инструмента
    assert resp.result is not None
    assert "web01.prod.acme.kz" in resp.result.text
    assert resp.result.tool_calls[0].arguments["query"] == "web01.prod.acme.kz 502"
    assert resp.served_by is not None and resp.served_by.profile_id == "claude-primary"


def test_audit_record_has_required_fields_and_no_raw_prompt() -> None:
    gw, audit, _ = _gateway()
    gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL, task_class=TaskClass.RCA)
    llm = [r for r in audit.records if isinstance(r, LLMCallRecord)]
    assert len(llm) == 1
    rec = llm[0]
    assert rec.provider == "claude" and rec.mode == "api_key"
    assert rec.model == "claude-model-from-config" and rec.profile_id == "claude-primary"
    assert rec.prompt_version == "linux-admin-v1"
    assert rec.input_tokens == 100 and rec.output_tokens == 50
    assert rec.cost_usd == (100 * 4.0 + 50 * 20.0) / 1e6
    assert len(rec.input_sha256) == 64 and rec.latency_ms >= 0
    assert rec.masked and rec.external and rec.status == "ok"
    dumped = json.dumps(rec.model_dump(mode="json"), ensure_ascii=False)
    for fragment in ("nginx on", "web01", "10.20.0.15", "ivanov", "You are linux-admin"):
        assert fragment not in dumped
    routing = audit.of_type("routing")
    assert routing and routing[0].reasons[0].startswith("data_class:")  # type: ignore[union-attr]


def test_input_hash_is_of_payload_sent() -> None:
    claude = FakeProvider("claude", external=True)
    gw, audit, _ = _gateway(make_registry(claude=claude))
    gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL, task_class=TaskClass.RCA)
    rec = audit.of_type("llm_call")[0]
    assert rec.input_sha256 == sha256_of(claude.requests[0])  # type: ignore[union-attr]


def test_fallback_primary_to_secondary_mid_call() -> None:
    claude = FakeProvider("claude", external=True, errors=[ProviderUnavailableError("down")])
    openai = FakeProvider("openai", external=True)
    gw, audit, _ = _gateway(make_registry(claude=claude, openai=openai))
    resp = gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL,
                       task_class=TaskClass.RCA)
    assert resp.status is GatewayStatus.OK
    assert resp.served_by is not None and resp.served_by.profile_id == "openai-secondary"
    records = audit.of_type("llm_call")
    assert [(r.attempt, r.status) for r in records] == [(0, "error"), (1, "ok")]  # type: ignore[union-attr]
    assert records[0].error_type == "ProviderUnavailableError"  # type: ignore[union-attr]


def test_fallback_to_local_when_all_external_fail_and_circuit_opens() -> None:
    claude = FakeProvider("claude", external=True,
                          errors=[ProviderRateLimitedError("rl", retry_after_s=60)] * 5)
    openai = FakeProvider("openai", external=True,
                          errors=[ProviderUnavailableError("x")] * 5)
    local = FakeProvider("local", external=False)
    gw, _, _ = _gateway(make_registry(claude=claude, openai=openai, local=local))
    resp = gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL,
                       task_class=TaskClass.RCA)
    assert resp.served_by is not None and resp.served_by.profile_id == "local-default"
    # local получает немаскированный запрос — данные не покидают периметр
    assert "10.20.0.15" in local.requests[0].messages[0].content
    # rate-limit с retry_after открыл цепь claude: следующий вызов его пропускает
    resp2 = gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL,
                        task_class=TaskClass.RCA)
    assert len(claude.requests) == 1
    assert "availability:skip_circuit_open (claude-primary)" in resp2.decision.reason_chain()


def test_non_retryable_error_does_not_fall_back() -> None:
    claude = FakeProvider("claude", external=True, errors=[ProviderRequestError("400")])
    openai = FakeProvider("openai", external=True)
    gw, _, _ = _gateway(make_registry(claude=claude, openai=openai))
    resp = gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL,
                       task_class=TaskClass.RCA)
    assert resp.status is GatewayStatus.FAILED
    assert openai.requests == []


def test_budget_exhausted_blocks_without_calling_providers() -> None:
    registry = make_registry()
    ledger = BudgetLedger()
    scope = BudgetScope(level=BudgetLevel.TASK, key="task-1", limits=BudgetLimits(tokens=150))
    gw, _, _ = _gateway(registry, ledger)
    ctx = _ctx(budget_scopes=[scope])
    first = gw.complete(ctx, _request(), data_class=DataClass.INTERNAL, task_class=TaskClass.RCA)
    assert first.status is GatewayStatus.OK and first.budget.exhausted  # 150 токенов израсходовано
    second = gw.complete(ctx, _request(), data_class=DataClass.INTERNAL,
                         task_class=TaskClass.RCA)
    assert second.status is GatewayStatus.BLOCKED and second.error == "budget.exhausted"
    claude = registry.provider_for("claude-primary")
    assert len(claude.requests) == 1  # type: ignore[attr-defined]


def test_soft_budget_downgrades_profile() -> None:
    registry = make_registry()
    ledger = BudgetLedger()
    scope = BudgetScope(level=BudgetLevel.TASK, key="task-1", limits=BudgetLimits(tokens=1000))
    ledger.consume([scope], tokens=850)
    gw, _, _ = _gateway(registry, ledger)
    resp = gw.complete(_ctx(budget_scopes=[scope]), _request(), data_class=DataClass.INTERNAL,
                       task_class=TaskClass.RCA)
    assert resp.served_by is not None and resp.served_by.profile_id == "claude-economy"
    assert resp.result is not None


def test_refusal_is_audited() -> None:
    claude = FakeProvider("claude", external=True, responder=lambda req: CompletionResult(
        finish_reason="refusal", model="m"))
    gw, audit, _ = _gateway(make_registry(claude=claude))
    resp = gw.complete(_ctx(), _request(), data_class=DataClass.INTERNAL,
                       task_class=TaskClass.RCA)
    assert resp.result is not None and resp.result.finish_reason == "refusal"
    assert audit.of_type("llm_call")[0].status == "refused"  # type: ignore[union-attr]


def test_embeddings_route_local() -> None:
    local = FakeProvider("local", external=False)
    gw, _, _ = _gateway(make_registry(local=local))
    status, res = gw.embed(_ctx(), ["web01 disk full"], data_class=DataClass.INTERNAL)
    assert status is GatewayStatus.OK and res is not None and res.model == "local-embed"
    assert local.embedded == [["web01 disk full"]]
