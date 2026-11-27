"""AI Provider Gateway: единая точка вызова LLM для агентов.

Связывает бюджеты → маршрутизатор → маскирование → провайдера → аудит:

1. проверка бюджетов (task/incident/agent/tenant);
2. ``Router.decide`` (класс данных, класс задачи, бюджет, доступность);
3. маскирование всего, что уходит внешнему провайдеру (обратная карта —
   в ``MaskingSession`` памяти задачи);
4. вызов кандидатов по порядку с circuit breaker: primary → secondary → local;
5. запись ``LLMCallRecord`` на каждую попытку (без сырого промпта);
6. учёт токенов/стоимости и повторная проверка бюджета;
7. демаскирование ответа (текст и аргументы вызовов инструментов).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from admintwin_ai.audit import AuditSink, LLMCallRecord, RoutingRecord, sha256_of
from admintwin_ai.budgets import BudgetCheck, BudgetLedger, BudgetScope
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.errors import ProviderError, ProviderRateLimitedError
from admintwin_ai.masking import Masker, MaskingSession
from admintwin_ai.profiles import CapabilityRequirements, ProfileRegistry
from admintwin_ai.providers.base import (
    Capability,
    CompletionRequest,
    CompletionResult,
    EmbeddingResult,
    ToolCall,
)
from admintwin_ai.routing.router import (
    Router,
    RouteStatus,
    RouteTarget,
    RoutingDecision,
    RoutingRequest,
    TenantAIPolicy,
)


class GatewayStatus(StrEnum):
    OK = "ok"
    BLOCKED = "blocked"
    HUMAN_REVIEW = "human_review"
    FAILED = "failed"


class CallContext(BaseModel):
    """Контекст вызова; ``masking_session`` — память задачи (не сериализуется)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    tenant: TenantAIPolicy
    agent_id: str
    task_id: str | None = None
    primary_profile: str
    secondary_profile: str | None = None
    requirements: CapabilityRequirements = Field(default_factory=CapabilityRequirements)
    budget_scopes: list[BudgetScope] = Field(default_factory=list)
    subtask_depth: int = 0
    masking_session: MaskingSession = Field(default_factory=MaskingSession, exclude=True)


class GatewayResponse(BaseModel):
    status: GatewayStatus
    result: CompletionResult | None = None
    decision: RoutingDecision
    budget: BudgetCheck
    error: str | None = None
    served_by: RouteTarget | None = None


class AIGateway:
    def __init__(
        self,
        registry: ProfileRegistry,
        router: Router,
        ledger: BudgetLedger,
        audit: AuditSink,
        *,
        masker: Masker | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._registry = registry
        self._router = router
        self._ledger = ledger
        self._audit = audit
        self._masker = masker or Masker()
        self._clock = clock

    # --- completion / tool_call ----------------------------------------------

    def complete(self, ctx: CallContext, request: CompletionRequest, *,
                 data_class: DataClass, task_class: TaskClass) -> GatewayResponse:
        caps = set(ctx.requirements.capabilities)
        if request.tools:
            caps.add(Capability.TOOL_CALLING)
        if request.response_schema is not None:
            caps.add(Capability.STRUCTURED_OUTPUT)
        requirements = ctx.requirements.model_copy(update={"capabilities": frozenset(caps)})

        decision, budget = self._decide(ctx, data_class, task_class, requirements)
        if decision.status is not RouteStatus.ROUTE:
            return self._not_routed(decision, budget)

        last_error = "no_candidates"
        for attempt, target in enumerate(decision.candidates):
            profile = self._registry.get(target.profile_id)
            provider = self._registry.provider_for(target.profile_id)
            send = request.model_copy(update={
                "model": profile.model,
                "max_tokens": min(request.max_tokens, profile.max_output_tokens),
                "params": {**request.params, **profile.params},
            })
            if target.mask:
                send = self._mask_request(send, ctx.masking_session)
            input_hash = sha256_of(send)
            breaker = self._router.breakers.get(target.profile_id)
            started = self._clock()
            try:
                result = provider.tool_call(send) if send.tools else provider.complete(send)
            except ProviderError as exc:
                latency = (self._clock() - started) * 1000
                self._audit_call(ctx, target, profile.model, send, input_hash, data_class,
                                 decision, attempt, latency, error=exc)
                last_error = type(exc).__name__
                if not exc.retryable:
                    return GatewayResponse(status=GatewayStatus.FAILED, decision=decision,
                                           budget=budget, error=last_error)
                retry_after = exc.retry_after_s if isinstance(exc, ProviderRateLimitedError) \
                    else None
                breaker.record_failure(last_error, retry_after_s=retry_after)
                continue
            latency = (self._clock() - started) * 1000
            breaker.record_success()
            cost = profile.pricing.cost(result.usage.input_tokens, result.usage.output_tokens)
            self._ledger.consume(ctx.budget_scopes, tokens=result.usage.total, cost_usd=cost)
            self._audit_call(ctx, target, profile.model, send, input_hash, data_class, decision,
                             attempt, latency, result=result, cost=cost)
            if target.mask:
                result = _unmask_result(result, ctx.masking_session)
            post = self._ledger.check(ctx.budget_scopes, subtask_depth=ctx.subtask_depth)
            return GatewayResponse(status=GatewayStatus.OK, result=result, decision=decision,
                                   budget=post, served_by=target)
        return GatewayResponse(status=GatewayStatus.FAILED, decision=decision, budget=budget,
                               error=f"all candidates failed: {last_error}")

    # --- embeddings -------------------------------------------------------------

    def embed(self, ctx: CallContext, texts: Sequence[str], *,
              data_class: DataClass) -> tuple[GatewayStatus, EmbeddingResult | None]:
        requirements = CapabilityRequirements(capabilities=frozenset({Capability.EMBEDDINGS}))
        decision, _ = self._decide(ctx, data_class, TaskClass.EMBED, requirements)
        if decision.status is not RouteStatus.ROUTE:
            return GatewayStatus(decision.status.value), None
        for target in decision.candidates:
            profile = self._registry.get(target.profile_id)
            inputs = list(texts)
            if target.mask:
                inputs = [self._masker.mask(t, ctx.masking_session).text for t in inputs]
            try:
                res = self._registry.provider_for(target.profile_id).embed(
                    inputs, model=profile.embedding_model or profile.model)
            except ProviderError as exc:
                if not exc.retryable:
                    return GatewayStatus.FAILED, None
                self._router.breakers.get(target.profile_id).record_failure(type(exc).__name__)
                continue
            self._ledger.consume(ctx.budget_scopes, tokens=res.usage.total)
            return GatewayStatus.OK, res
        return GatewayStatus.FAILED, None

    # --- внутреннее -------------------------------------------------------------

    def _decide(self, ctx: CallContext, data_class: DataClass, task_class: TaskClass,
                requirements: CapabilityRequirements) -> tuple[RoutingDecision, BudgetCheck]:
        budget = self._ledger.check(ctx.budget_scopes, subtask_depth=ctx.subtask_depth)
        decision = self._router.decide(RoutingRequest(
            tenant=ctx.tenant, agent_id=ctx.agent_id, primary_profile=ctx.primary_profile,
            secondary_profile=ctx.secondary_profile, data_class=data_class,
            task_class=task_class, budget_state=budget.state, requirements=requirements,
        ))
        self._audit.emit(RoutingRecord(
            tenant_id=ctx.tenant.tenant_id, task_id=ctx.task_id, agent_id=ctx.agent_id,
            status=decision.status.value, block_reason=decision.block_reason,
            data_class=data_class, task_class=task_class.value, reasons=decision.reason_chain(),
        ))
        return decision, budget

    @staticmethod
    def _not_routed(decision: RoutingDecision, budget: BudgetCheck) -> GatewayResponse:
        status = GatewayStatus.HUMAN_REVIEW if decision.status is RouteStatus.HUMAN_REVIEW \
            else GatewayStatus.BLOCKED
        return GatewayResponse(status=status, decision=decision, budget=budget,
                               error=decision.block_reason)

    def _mask_request(self, req: CompletionRequest, session: MaskingSession) -> CompletionRequest:
        m = self._masker
        messages = [
            msg.model_copy(update={
                "content": m.mask(msg.content, session).text,
                "tool_calls": [
                    tc.model_copy(update={"arguments": m.mask_obj(tc.arguments, session)})
                    for tc in msg.tool_calls
                ],
            })
            for msg in req.messages
        ]
        system = m.mask(req.system, session).text if req.system else req.system
        return req.model_copy(update={"messages": messages, "system": system})

    def _audit_call(self, ctx: CallContext, target: RouteTarget, requested_model: str,
                    send: CompletionRequest, input_hash: str, data_class: DataClass,
                    decision: RoutingDecision, attempt: int, latency_ms: float, *,
                    result: CompletionResult | None = None, cost: float = 0.0,
                    error: Exception | None = None) -> None:
        status: Literal["ok", "error", "refused"]
        if error is not None:
            status = "error"
        elif result is not None and result.finish_reason == "refusal":
            status = "refused"
        else:
            status = "ok"
        self._audit.emit(LLMCallRecord(
            tenant_id=ctx.tenant.tenant_id, task_id=ctx.task_id, agent_id=ctx.agent_id,
            provider=target.provider_id,
            model=(result.model if result and result.model else requested_model),
            requested_model=requested_model,
            mode=self._registry.mode(target.profile_id).value, profile_id=target.profile_id,
            prompt_version=send.prompt_version, input_sha256=input_hash,
            input_tokens=result.usage.input_tokens if result else 0,
            output_tokens=result.usage.output_tokens if result else 0,
            cost_usd=cost, latency_ms=round(latency_ms, 3), status=status,
            error_type=type(error).__name__ if error else None,
            finish_reason=result.finish_reason if result else None,
            data_class=data_class, masked=target.mask, external=target.external,
            attempt=attempt, routing_reasons=decision.reason_chain(),
        ))


def _unmask_result(result: CompletionResult, session: MaskingSession) -> CompletionResult:
    calls = [ToolCall(id=tc.id, name=tc.name, arguments=session.unmask_obj(tc.arguments),
                      malformed=tc.malformed) for tc in result.tool_calls]
    return result.model_copy(update={"text": session.unmask(result.text), "tool_calls": calls})


__all__ = [
    "AIGateway",
    "CallContext",
    "GatewayResponse",
    "GatewayStatus",
]
