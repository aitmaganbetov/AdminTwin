"""Настройки сервиса ``admintwin-orchestrator`` из переменных окружения."""

from __future__ import annotations

import os
from collections.abc import Mapping

from pydantic import BaseModel, Field

from admintwin_ai.orchestrator.engine import BudgetSettings, EngineSettings


class ConfigurationError(RuntimeError):
    """Сервис не может стартовать с такой конфигурацией (fail closed)."""


def _bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _num(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from exc


class ServiceSettings(BaseModel):
    service_token: str | None = Field(default=None, repr=False)
    dev_insecure: bool = False
    core_url: str = "http://localhost:8080"
    host: str = "0.0.0.0"  # noqa: S104 - сервис в контейнере, доступ только с сервисным токеном
    port: int = 8090
    ai_config: str | None = None
    offline_fake: bool = False
    # Метаданные вызовов LLM/инструментов — в аудит ядра (POST /api/v1/audit/ai-calls).
    audit_to_core: bool = True
    nats_url: str | None = None
    tenant_policies: str | None = None
    log_level: str = "info"
    engine: EngineSettings = Field(default_factory=EngineSettings)
    budgets: BudgetSettings = Field(default_factory=BudgetSettings)

    @property
    def auth_enabled(self) -> bool:
        return bool(self.service_token)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServiceSettings:
        env = os.environ if env is None else env
        token = env.get("ADMINTWIN_SERVICE_TOKEN") or None
        insecure = _bool(env, "ADMINTWIN_DEV_INSECURE")
        if token is None and not insecure:
            raise ConfigurationError(
                "ADMINTWIN_SERVICE_TOKEN is required (set ADMINTWIN_DEV_INSECURE=true only for "
                "local development without authentication)")
        if token is not None and len(token) < 16:
            raise ConfigurationError("ADMINTWIN_SERVICE_TOKEN must be at least 16 characters")
        engine = EngineSettings(
            post_rca=_bool(env, "ADMINTWIN_POST_RCA", True),
            blocked_timeout_s=_num(env, "ADMINTWIN_BLOCKED_TIMEOUT_S", 3600.0),
            worker_threads=int(_num(env, "ADMINTWIN_WORKER_THREADS", 64)),
            agent_max_steps=int(_num(env, "ADMINTWIN_AGENT_MAX_STEPS", 8)),
        )
        d = BudgetSettings()
        budgets = BudgetSettings(
            task_tokens=int(_num(env, "ADMINTWIN_BUDGET_TASK_TOKENS", d.task_tokens)),
            task_cost_usd=_num(env, "ADMINTWIN_BUDGET_TASK_COST_USD", d.task_cost_usd),
            task_wall_time_s=_num(env, "ADMINTWIN_BUDGET_TASK_WALL_TIME_S", d.task_wall_time_s),
            incident_cost_usd=_num(env, "ADMINTWIN_BUDGET_INCIDENT_COST_USD",
                                   d.incident_cost_usd),
            agent_tokens_per_hour=int(_num(env, "ADMINTWIN_BUDGET_AGENT_TOKENS_PER_HOUR",
                                           d.agent_tokens_per_hour)),
            tenant_tokens_per_day=int(_num(env, "ADMINTWIN_BUDGET_TENANT_TOKENS_PER_DAY",
                                           d.tenant_tokens_per_day)),
            tenant_cost_per_day_usd=_num(env, "ADMINTWIN_BUDGET_TENANT_COST_PER_DAY_USD",
                                         d.tenant_cost_per_day_usd),
        )
        return cls(
            service_token=token, dev_insecure=insecure,
            core_url=env.get("ADMINTWIN_CORE_URL", "http://localhost:8080"),
            host=env.get("ADMINTWIN_ORCHESTRATOR_HOST", "0.0.0.0"),  # noqa: S104
            port=int(_num(env, "ADMINTWIN_ORCHESTRATOR_PORT", 8090)),
            ai_config=env.get("ADMINTWIN_AI_CONFIG") or None,
            offline_fake=_bool(env, "ADMINTWIN_AI_OFFLINE_FAKE"),
            audit_to_core=env.get("ADMINTWIN_AUDIT_TO_CORE", "true").lower() != "false",
            nats_url=env.get("ADMINTWIN_NATS_URL") or None,
            tenant_policies=env.get("ADMINTWIN_TENANT_POLICIES") or None,
            log_level=env.get("ADMINTWIN_LOG_LEVEL", "info"),
            engine=engine, budgets=budgets,
        )
