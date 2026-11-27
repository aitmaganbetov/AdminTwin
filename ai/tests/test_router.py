"""Маршрутизатор (§6.4): порядок правил, fail closed, бюджет, доступность."""

from __future__ import annotations

import pytest

from admintwin_ai.budgets import BudgetState
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.profiles import CapabilityRequirements, ModelProfile, ProfileRegistry
from admintwin_ai.providers import Capability, ConnectionMode, ProviderCapabilities
from admintwin_ai.routing.circuit_breaker import BreakerBoard, BreakerState, CircuitBreaker
from admintwin_ai.routing.router import Router, RouteStatus, RoutingRequest, TenantAIPolicy

from fakes import FakeProvider, make_registry

TENANT = TenantAIPolicy(tenant_id="t1", local_profile="local-default")


def _req(**kw: object) -> RoutingRequest:
    base: dict[str, object] = {"tenant": TENANT, "agent_id": "linux-admin",
                               "primary_profile": "claude-primary",
                               "secondary_profile": "openai-secondary",
                               "data_class": DataClass.INTERNAL, "task_class": TaskClass.RCA}
    base.update(kw)
    return RoutingRequest.model_validate(base)


def _profiles(decision_candidates: list[object]) -> list[str]:
    return [c.profile_id for c in decision_candidates]  # type: ignore[attr-defined]


def test_rca_goes_external_primary_then_secondary_then_local() -> None:
    d = Router(make_registry()).decide(_req())
    assert d.status is RouteStatus.ROUTE
    assert _profiles(d.candidates) == ["claude-primary", "openai-secondary", "local-default"]
    assert d.target is not None and d.target.external and d.target.mask  # mask_external default
    assert d.reason_chain()[0].startswith("data_class:internal_external_allowed")
    assert [r.rule for r in d.reasons][:3] == ["data_class", "task_class", "budget"]


@pytest.mark.parametrize("task", [TaskClass.CLASSIFY, TaskClass.SUMMARIZE, TaskClass.EXTRACT])
def test_light_tasks_go_local_first(task: TaskClass) -> None:
    d = Router(make_registry()).decide(_req(task_class=task))
    assert _profiles(d.candidates)[0] == "local-default"
    assert d.target is not None and not d.target.mask


def test_code_analysis_is_configurable() -> None:
    router = Router(make_registry())
    ext = router.decide(_req(task_class=TaskClass.CODE_ANALYSIS))
    loc = router.decide(_req(task_class=TaskClass.CODE_ANALYSIS,
                             tenant=TENANT.model_copy(update={"code_analysis_target": "local"})))
    assert _profiles(ext.candidates)[0] == "claude-primary"
    assert _profiles(loc.candidates)[0] == "local-default"


@pytest.mark.parametrize("dc", [DataClass.PII, DataClass.SECRET, DataClass.UNKNOWN])
def test_perimeter_bound_data_never_routed_external(dc: DataClass) -> None:
    d = Router(make_registry()).decide(_req(data_class=dc))
    assert d.status is RouteStatus.ROUTE
    assert _profiles(d.candidates) == ["local-default"]
    assert all(not c.external for c in d.candidates)


@pytest.mark.parametrize("dc", [DataClass.PII, DataClass.SECRET, DataClass.UNKNOWN])
def test_fail_closed_to_human_review_without_local(dc: DataClass) -> None:
    providers = {"claude": FakeProvider("claude", external=True)}
    reg = ProfileRegistry([ModelProfile(id="claude-primary", provider="claude", model="m")],
                          providers)
    d = Router(reg).decide(_req(data_class=dc, secondary_profile=None,
                                tenant=TenantAIPolicy(tenant_id="t1")))
    assert d.status is RouteStatus.HUMAN_REVIEW
    assert d.candidates == []
    assert d.block_reason == "no_permitted_provider"


def test_pii_masked_external_only_when_tenant_opts_in() -> None:
    tenant = TENANT.model_copy(update={"pii_masked_external": True, "mask_external": False})
    d = Router(make_registry()).decide(_req(data_class=DataClass.PII, tenant=tenant))
    assert d.target is not None and d.target.external and d.target.mask
    # secret — никогда, даже при opt-in
    d2 = Router(make_registry()).decide(_req(data_class=DataClass.SECRET, tenant=tenant))
    assert all(not c.external for c in d2.candidates)


def test_tenant_local_only() -> None:
    tenant = TENANT.model_copy(update={"local_only": True})
    d = Router(make_registry()).decide(_req(tenant=tenant))
    assert _profiles(d.candidates) == ["local-default"]
    assert d.reasons[0].outcome == "local_only"


def test_soft_budget_downgrades_profiles() -> None:
    d = Router(make_registry()).decide(_req(budget_state=BudgetState.SOFT))
    assert _profiles(d.candidates) == ["claude-economy", "local-default"]
    assert "budget:downgrade (claude-primary->claude-economy)" in d.reason_chain()


def test_hard_budget_stops_ai_or_goes_local() -> None:
    router = Router(make_registry())
    stop = router.decide(_req(budget_state=BudgetState.HARD))
    assert stop.status is RouteStatus.BLOCKED and stop.block_reason == "budget.exhausted"
    local = router.decide(_req(budget_state=BudgetState.HARD, tenant=TENANT.model_copy(
        update={"on_budget_exhausted": "local_only"})))
    assert _profiles(local.candidates) == ["local-default"]


def test_capabilities_filter_candidates() -> None:
    weak = FakeProvider("local", external=False,
                        caps=ProviderCapabilities(streaming=True, max_context=8192))
    d = Router(make_registry(local=weak)).decide(_req(
        data_class=DataClass.PII,
        requirements=CapabilityRequirements(capabilities=frozenset({Capability.TOOL_CALLING}))))
    assert d.status is RouteStatus.HUMAN_REVIEW
    assert any(r.rule == "capabilities" for r in d.reasons)


def test_open_circuit_skips_candidate() -> None:
    board = BreakerBoard()
    for _ in range(3):
        board.get("claude-primary").record_failure("ProviderUnavailableError")
    d = Router(make_registry(), board).decide(_req())
    assert _profiles(d.candidates) == ["openai-secondary", "local-default"]
    assert "availability:skip_circuit_open (claude-primary)" in d.reason_chain()


def test_subscription_profile_only_for_owner_tenant() -> None:
    sub = FakeProvider("sub", external=True, mode=ConnectionMode.SUBSCRIPTION)
    reg = ProfileRegistry([ModelProfile(id="sub-p", provider="sub", model="m",
                                        owner_tenant_id="t-owner")], {"sub": sub})
    other = Router(reg).decide(_req(primary_profile="sub-p", secondary_profile=None,
                                    tenant=TenantAIPolicy(tenant_id="t1",
                                                          subscription_allowed=True)))
    assert other.status is RouteStatus.BLOCKED
    owner = Router(reg).decide(_req(primary_profile="sub-p", secondary_profile=None,
                                    tenant=TenantAIPolicy(tenant_id="t-owner",
                                                          subscription_allowed=True)))
    assert _profiles(owner.candidates) == ["sub-p"]


def test_circuit_breaker_backoff_and_half_open() -> None:
    now = [0.0]
    cb = CircuitBreaker(failure_threshold=2, base_backoff_s=1.0, max_backoff_s=4.0,
                        clock=lambda: now[0])
    cb.record_failure()
    assert cb.allow()
    cb.record_failure()
    assert cb.state is BreakerState.OPEN and not cb.allow()
    now[0] = 1.0
    assert cb.state is BreakerState.HALF_OPEN and cb.allow()
    cb.record_failure()  # проба не удалась — backoff удваивается
    assert cb.state is BreakerState.OPEN
    now[0] = 2.5
    assert not cb.allow()
    now[0] = 3.0
    assert cb.allow()
    cb.record_success()
    assert cb.state is BreakerState.CLOSED


def test_rate_limit_retry_after_opens_immediately() -> None:
    now = [0.0]
    cb = CircuitBreaker(clock=lambda: now[0])
    cb.record_failure("rate_limited", retry_after_s=30)
    assert not cb.allow()
    now[0] = 30.0
    assert cb.allow()
