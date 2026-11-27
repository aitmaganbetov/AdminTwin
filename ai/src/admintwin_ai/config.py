"""Загрузка конфигурации провайдеров и Model Profiles.

Ключи провайдеров никогда не хранятся в конфигурации: в ней только ссылки
(``api_key_ref``), которые разрешает ``SecretResolver`` (в production —
Vault клиента, §6.1 BYO; в dev — переменные окружения). Агентам ключи не
передаются никогда (§23 п.10): ими владеет только этот слой.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field

from admintwin_ai.errors import ProviderConfigError
from admintwin_ai.profiles import ModelProfile, ProfileRegistry
from admintwin_ai.providers.base import ConnectionMode, LLMProvider, ProviderCapabilities
from admintwin_ai.providers.claude import ClaudeProvider
from admintwin_ai.providers.local import LocalProvider
from admintwin_ai.providers.openai import OpenAIProvider


class SecretResolver(Protocol):
    def resolve(self, ref: str) -> str: ...


class EnvSecretResolver:
    """Dev-резолвер: ``env:NAME``. Ссылки ``vault:`` требуют Vault-резолвера."""

    def resolve(self, ref: str) -> str:
        scheme, _, name = ref.partition(":")
        if scheme != "env" or not name:
            raise ProviderConfigError(f"secret ref '{ref}' is not supported by EnvSecretResolver")
        value = os.environ.get(name)
        if not value:
            raise ProviderConfigError(f"secret ref '{ref}' is not set")
        return value


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["claude", "openai", "local"]
    mode: ConnectionMode = ConnectionMode.API_KEY
    api_key_ref: str | None = None
    base_url: str | None = None
    timeout_s: float = 120.0
    max_retries: int = 2
    # claude
    server_side_fallback: bool = False
    # openai
    organization: str | None = None
    # local
    allowed_endpoints: list[str] = Field(default_factory=list)
    declared_capabilities: ProviderCapabilities | None = None


class AIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    providers: dict[str, ProviderConfig]
    profiles: dict[str, dict[str, Any]]

    def model_profiles(self) -> list[ModelProfile]:
        return [ModelProfile(id=pid, **body) for pid, body in self.profiles.items()]


def load_config(path: str | Path) -> AIConfig:
    with Path(path).open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return AIConfig.model_validate(raw)


def build_provider(provider_id: str, cfg: ProviderConfig, resolver: SecretResolver,
                   client: Any | None = None) -> LLMProvider:
    api_key = resolver.resolve(cfg.api_key_ref) if cfg.api_key_ref and client is None else None
    if cfg.kind == "claude":
        return ClaudeProvider(provider_id, mode=cfg.mode, api_key=api_key, base_url=cfg.base_url,
                              timeout_s=cfg.timeout_s, max_retries=cfg.max_retries,
                              server_side_fallback=cfg.server_side_fallback, client=client)
    if cfg.kind == "openai":
        return OpenAIProvider(provider_id, mode=cfg.mode, api_key=api_key, base_url=cfg.base_url,
                              organization=cfg.organization, timeout_s=cfg.timeout_s,
                              max_retries=cfg.max_retries, client=client)
    if cfg.base_url is None or cfg.declared_capabilities is None:
        raise ProviderConfigError(
            f"local provider '{provider_id}' needs base_url and declared_capabilities"
        )
    return LocalProvider(provider_id, base_url=cfg.base_url,
                         allowed_endpoints=cfg.allowed_endpoints,
                         declared_capabilities=cfg.declared_capabilities, api_key=api_key,
                         timeout_s=cfg.timeout_s, max_retries=cfg.max_retries, client=client)


def build_registry(config: AIConfig, resolver: SecretResolver,
                   clients: Mapping[str, Any] | None = None) -> ProfileRegistry:
    """``clients`` — подмена SDK-клиентов по id провайдера (тесты, DI)."""
    clients = clients or {}
    providers = {
        pid: build_provider(pid, cfg, resolver, clients.get(pid))
        for pid, cfg in config.providers.items()
    }
    return ProfileRegistry(config.model_profiles(), providers)
