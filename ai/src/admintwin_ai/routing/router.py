"""Маршрутизатор AI Provider Layer (§6.4).

Правила применяются строго по порядку:

1. **Класс данных.** ``pii``/``secret`` не покидают периметр: только Local
   (для ``pii`` — либо внешний провайдер с обязательным маскированием, если
   tenant явно включил ``pii_masked_external``; для ``secret`` — никогда).
   Неопределённая классификация (``unknown``) — fail closed: Local или
   human review. Tenant может включить «только Local для всего».
2. **Класс задачи.** classify/summarize/extract/embed → Local первым;
   plan/rca/multi_step → внешний primary; code_analysis — по настройке tenant.
3. **Бюджет.** ≥ мягкого порога — downgrade профилей; ≥ жёсткого — только
   Local (если tenant так настроил) или остановка AI (``blocked``,
   ``budget.exhausted``).
4. **Доступность.** primary → secondary → local; кандидаты с открытым
   circuit breaker или без нужных capabilities исключаются.

Результат — ``RoutingDecision`` с упорядоченными кандидатами и цепочкой
причин для аудита.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from admintwin_ai.budgets import BudgetState
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.profiles import CapabilityRequirements, ProfileRegistry
from admintwin_ai.providers.base import ConnectionMode
from admintwin_ai.routing.circuit_breaker import BreakerBoard


class TenantAIPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    local_only: bool = False
    local_profile: str | None = None
    #: разрешить pii внешнему провайдеру только после маскирования (по умолчанию — нет)
    pii_masked_external: bool = False
    #: маскировать всё, что уходит внешнему провайдеру (IP, хосты, логины...)
    mask_external: bool = True
    code_analysis_target: Literal["local", "external"] = "external"
    on_budget_exhausted: Literal["local_only", "stop"] = "stop"
    #: подписочный канал — только Enterprise и только собственная учётная запись (§6.8)
    subscription_allowed: bool = False


class RouteStatus(StrEnum):
    ROUTE = "route"
    HUMAN_REVIEW = "human_review"
    BLOCKED = "blocked"


class ReasonStep(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule: Literal["tenant", "data_class", "task_class", "budget", "availability",
                  "capabilities", "result"]
    outcome: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.rule}:{self.outcome}" + (f" ({self.detail})" if self.detail else "")


class RouteTarget(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile_id: str
    provider_id: str
    model: str
    external: bool
    mask: bool


class RoutingRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant: TenantAIPolicy
    agent_id: str
    primary_profile: str
    secondary_profile: str | None = None
    data_class: DataClass
    task_class: TaskClass
    budget_state: BudgetState = BudgetState.OK
    requirements: CapabilityRequirements = Field(default_factory=CapabilityRequirements)


class RoutingDecision(BaseModel):
    status: RouteStatus
    candidates: list[RouteTarget] = Field(default_factory=list)
    reasons: list[ReasonStep] = Field(default_factory=list)
    block_reason: str | None = None

    @property
    def target(self) -> RouteTarget | None:
        return self.candidates[0] if self.candidates else None

    def reason_chain(self) -> list[str]:
        return [str(r) for r in self.reasons]


class Router:
    def __init__(self, registry: ProfileRegistry, breakers: BreakerBoard | None = None) -> None:
        self._registry = registry
        self._breakers = breakers or BreakerBoard()

    @property
    def breakers(self) -> BreakerBoard:
        return self._breakers

    def _local_profile(self, tenant: TenantAIPolicy) -> str | None:
        if tenant.local_profile and tenant.local_profile in self._registry:
            return tenant.local_profile
        local = self._registry.local_profiles()
        return local[0] if local else None

    def decide(self, req: RoutingRequest) -> RoutingDecision:
        reasons: list[ReasonStep] = []
        tenant = req.tenant
        dc = req.data_class
        allow_external = True
        mask_external = tenant.mask_external
        local = self._local_profile(tenant)

        # --- 1. класс данных --------------------------------------------
        if tenant.local_only:
            allow_external = False
            reasons.append(ReasonStep(rule="tenant", outcome="local_only"))
        if dc is DataClass.SECRET:
            allow_external = False
            reasons.append(ReasonStep(rule="data_class", outcome="secret_local_only"))
        elif dc is DataClass.UNKNOWN:
            allow_external = False
            reasons.append(ReasonStep(rule="data_class", outcome="unknown_fail_closed",
                                      detail="local or human_review"))
        elif dc is DataClass.PII:
            if tenant.pii_masked_external and allow_external:
                mask_external = True
                reasons.append(ReasonStep(rule="data_class", outcome="pii_external_masked_only"))
            else:
                allow_external = False
                reasons.append(ReasonStep(rule="data_class", outcome="pii_local_only"))
        else:
            reasons.append(ReasonStep(rule="data_class", outcome=f"{dc.value}_external_allowed"
                                      if allow_external else f"{dc.value}_local_only"))

        # --- 2. класс задачи --------------------------------------------
        prefer_local = req.task_class.prefers_local or (
            req.task_class is TaskClass.CODE_ANALYSIS and tenant.code_analysis_target == "local"
        )
        order: list[str | None] = (
            [local, req.primary_profile, req.secondary_profile] if prefer_local
            else [req.primary_profile, req.secondary_profile, local]
        )
        reasons.append(ReasonStep(rule="task_class",
                                  outcome="local_first" if prefer_local else "external_primary",
                                  detail=req.task_class.value))

        # --- 3. бюджет ----------------------------------------------------
        if req.budget_state is BudgetState.HARD:
            if tenant.on_budget_exhausted == "local_only" and local is not None:
                allow_external = False
                order = [local]
                reasons.append(ReasonStep(rule="budget", outcome="exhausted_local_only"))
            else:
                reasons.append(ReasonStep(rule="budget", outcome="exhausted_stop_ai"))
                return RoutingDecision(status=RouteStatus.BLOCKED, reasons=reasons,
                                       block_reason="budget.exhausted")
        elif req.budget_state is BudgetState.SOFT:
            downgraded: list[str | None] = []
            for pid in order:
                if pid is not None and self._registry.is_external(pid):
                    target = self._registry.get(pid).downgrade_to or pid
                    if target != pid:
                        reasons.append(ReasonStep(rule="budget", outcome="downgrade",
                                                  detail=f"{pid}->{target}"))
                    downgraded.append(target)
                else:
                    downgraded.append(pid)
            order = downgraded
        else:
            reasons.append(ReasonStep(rule="budget", outcome="ok"))

        # --- 4. доступность и возможности --------------------------------
        candidates: list[RouteTarget] = []
        seen: set[str] = set()
        for pid in order:
            if pid is None or pid in seen:
                continue
            seen.add(pid)
            profile = self._registry.get(pid)
            external = self._registry.is_external(pid)
            if external and not allow_external:
                reasons.append(ReasonStep(rule="availability", outcome="skip_external",
                                          detail=pid))
                continue
            if self._registry.mode(pid) is ConnectionMode.SUBSCRIPTION and not (
                tenant.subscription_allowed and profile.owner_tenant_id == tenant.tenant_id
            ):
                reasons.append(ReasonStep(rule="tenant", outcome="skip_subscription_not_owned",
                                          detail=pid))
                continue
            missing = self._registry.missing(pid, req.requirements)
            if missing:
                reasons.append(ReasonStep(rule="capabilities", outcome="skip",
                                          detail=f"{pid}: missing {', '.join(missing)}"))
                continue
            if not self._breakers.get(pid).allow():
                reasons.append(ReasonStep(rule="availability", outcome="skip_circuit_open",
                                          detail=pid))
                continue
            candidates.append(RouteTarget(
                profile_id=pid, provider_id=profile.provider, model=profile.model,
                external=external, mask=external and mask_external,
            ))

        if candidates:
            reasons.append(ReasonStep(rule="result", outcome="route",
                                      detail=" -> ".join(c.profile_id for c in candidates)))
            return RoutingDecision(status=RouteStatus.ROUTE, candidates=candidates,
                                   reasons=reasons)
        if not allow_external or dc.is_perimeter_bound:
            reasons.append(ReasonStep(rule="result", outcome="human_review",
                                      detail="no permitted local candidate (fail closed)"))
            return RoutingDecision(status=RouteStatus.HUMAN_REVIEW, reasons=reasons,
                                   block_reason="no_permitted_provider")
        reasons.append(ReasonStep(rule="result", outcome="blocked", detail="no provider available"))
        return RoutingDecision(status=RouteStatus.BLOCKED, reasons=reasons,
                               block_reason="no_provider_available")
