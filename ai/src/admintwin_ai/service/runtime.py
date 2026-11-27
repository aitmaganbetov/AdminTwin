"""Сборка оркестратора из настроек: провайдеры, Tool Layer поверх ядра, шина, движок."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

from admintwin_ai.agents.registry import AgentRegistry, load_agents
from admintwin_ai.audit import AuditRecord, AuditSink
from admintwin_ai.budgets import BudgetLedger
from admintwin_ai.bus import AgentBus, build_bus
from admintwin_ai.classification import DataClass
from admintwin_ai.config import EnvSecretResolver, build_registry, load_config
from admintwin_ai.evals.fake_model import ScriptedDiagnostician
from admintwin_ai.gateway import AIGateway, CallContext, GatewayStatus
from admintwin_ai.orchestrator.cases import CaseStore
from admintwin_ai.orchestrator.core_client import CoreClient
from admintwin_ai.orchestrator.costs import CostTrackingSink
from admintwin_ai.orchestrator.engine import Orchestrator
from admintwin_ai.profiles import ModelProfile, Pricing, ProfileRegistry
from admintwin_ai.providers.base import LLMProvider
from admintwin_ai.routing.router import Router, TenantAIPolicy
from admintwin_ai.service.core_audit import CoreAuditSink
from admintwin_ai.service.settings import ConfigurationError, ServiceSettings
from admintwin_ai.tools import ChangeProposeHandler, ToolInvoker, build_tool_registry
from admintwin_ai.tools.http_backend import HttpReadBackend
from admintwin_ai.tools.read import ReadBackend

log = logging.getLogger("admintwin.runtime")


class LoggingAuditSink:
    """Аудит LLM/tool-вызовов в структурированный журнал (сырые промпты не пишутся)."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or logging.getLogger("admintwin.audit")

    def emit(self, record: AuditRecord) -> None:
        self._log.info(record.model_dump_json())


@dataclass
class Runtime:
    settings: ServiceSettings
    orchestrator: Orchestrator
    profiles: ProfileRegistry
    router: Router

    def provider_states(self, *, probe: bool = False) -> list[dict[str, Any]]:
        states: list[dict[str, Any]] = []
        snapshot = self.router.breakers.snapshot()
        for p in self.profiles.all():
            provider = self.profiles.provider_for(p.id)
            breaker = self.router.breakers.get(p.id)
            item: dict[str, Any] = {
                "profile": p.id, "provider": p.provider, "model": p.model,
                "kind": provider.kind, "mode": provider.mode.value,
                "external": bool(provider.is_external), "enabled": p.enabled,
                "circuit": snapshot.get(p.id, "closed"),
                "last_error": breaker.last_error or None,
            }
            if probe:
                try:
                    h = provider.health(p.model)
                    item["health"] = {"ok": h.ok, "detail": h.detail[:200],
                                      "latency_ms": h.latency_ms}
                except Exception as exc:
                    item["health"] = {"ok": False, "detail": type(exc).__name__}
            states.append(item)
        return states


def fake_registry(profile_ids: Sequence[str], *, external: bool = False,
                  provider: ScriptedDiagnostician | None = None) -> ProfileRegistry:
    """Все профили обслуживает офлайн-модель (dev, CI, тесты)."""
    fake = provider or ScriptedDiagnostician(external=external)
    profiles = [ModelProfile(id=pid, provider=fake.provider_id, model=f"scripted-{pid}",
                             pricing=Pricing(input_per_mtok=1.0, output_per_mtok=2.0),
                             embedding_model="scripted-embed")
                for pid in dict.fromkeys(profile_ids)]
    providers: dict[str, LLMProvider] = {fake.provider_id: fake}
    return ProfileRegistry(profiles, providers)


def agent_profile_ids(agents: AgentRegistry) -> list[str]:
    ids: list[str] = []
    for a in agents.all():
        ids.append(a.model_profile)
        if a.fallback_model_profile:
            ids.append(a.fallback_model_profile)
    return list(dict.fromkeys(ids))


def load_tenant_policies(path: str | None) -> Callable[[str], TenantAIPolicy]:
    policies: dict[str, TenantAIPolicy] = {}
    if path:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for tid, body in (raw.get("tenants") or {}).items():
            policies[str(tid)] = TenantAIPolicy(tenant_id=str(tid), **(body or {}))

    def get(tenant_id: str) -> TenantAIPolicy:
        return policies.get(tenant_id) or TenantAIPolicy(tenant_id=tenant_id)

    return get


def build_runtime(settings: ServiceSettings, *,
                  registry: ProfileRegistry | None = None,
                  backend: ReadBackend | None = None,
                  core_http: httpx.Client | None = None,
                  core_async: httpx.AsyncClient | None = None,
                  bus: AgentBus | None = None,
                  audit: AuditSink | None = None,
                  provider_clients: Mapping[str, Any] | None = None,
                  ledger: BudgetLedger | None = None,
                  agent_profile_override: str | None = None) -> Runtime:
    agents_list = load_agents()
    if agent_profile_override:
        # один профиль для всех агентов (сравнение провайдеров на одном dataset, §6.10)
        agents_list = [a.model_copy(update={"model_profile": agent_profile_override,
                                            "fallback_model_profile": None})
                       for a in agents_list]
    plain_agents = AgentRegistry(agents_list)
    if registry is None:
        if settings.offline_fake:
            log.warning("ADMINTWIN_AI_OFFLINE_FAKE=true: all profiles are served by the scripted "
                        "offline model (dev/CI only)")
            registry = fake_registry(agent_profile_ids(plain_agents))
        elif settings.ai_config:
            registry = build_registry(load_config(settings.ai_config), EnvSecretResolver(),
                                      clients=provider_clients)
        else:
            registry = ProfileRegistry([], {})
            log.warning("ADMINTWIN_AI_CONFIG is not set: no LLM providers; agent tasks will be "
                        "blocked (monitoring is unaffected)")
    router = Router(registry)
    http = core_http or httpx.Client(timeout=20.0)
    if audit is None:
        audit = LoggingAuditSink()
        if settings.service_token and settings.core_url and settings.audit_to_core:
            # Метаданные вызовов LLM/инструментов — в неизменяемый аудит ядра (§6.3, §21);
            # тот же HTTP-клиент ядра, что и у инструментов.
            audit = CoreAuditSink(settings.core_url, settings.service_token, audit, client=http)
    costs = CostTrackingSink(audit)
    ledger = ledger or BudgetLedger()
    gateway = AIGateway(registry, router, ledger, costs)
    read_backend = backend or HttpReadBackend(settings.core_url,
                                              service_token=settings.service_token, client=http)
    propose = ChangeProposeHandler(settings.core_url, client=http,
                                   service_token=settings.service_token)
    tools = build_tool_registry(read_backend, propose)
    configured = {p.id for p in registry.all()}
    missing = sorted({pid for pid in agent_profile_ids(plain_agents)} - configured)
    if configured and missing:
        raise ConfigurationError(f"model profiles referenced by agents are not configured: "
                                 f"{missing}")
    agents = AgentRegistry(agents_list, tools=tools,
                           profiles=registry if configured else None)
    invoker = ToolInvoker(tools, costs, assets=read_backend)
    tenant_policy = load_tenant_policies(settings.tenant_policies)

    def embedder(texts: Sequence[str]) -> list[list[float]] | None:
        commander = agents.get("ai-commander")
        ctx = CallContext(tenant=TenantAIPolicy(tenant_id="platform", local_only=True),
                          agent_id="case-memory", primary_profile=commander.model_profile,
                          secondary_profile=commander.fallback_model_profile)
        if not configured:
            return None
        status, res = gateway.embed(ctx, texts, data_class=DataClass.INTERNAL)
        return res.vectors if status is GatewayStatus.OK and res is not None else None

    orchestrator = Orchestrator(
        agents=agents, tools=tools, invoker=invoker, gateway=gateway, ledger=ledger,
        costs=costs, bus=bus or build_bus(settings.nats_url), cases=CaseStore(embedder),
        core=CoreClient(settings.core_url, service_token=settings.service_token,
                        client=core_async),
        tenant_policy=tenant_policy, settings=settings.engine, budgets=settings.budgets,
        llm_configured=bool(configured))
    return Runtime(settings=settings, orchestrator=orchestrator, profiles=registry,
                   router=router)
