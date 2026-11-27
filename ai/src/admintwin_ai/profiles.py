"""Model Profiles и проверка покрытия capabilities агента (§6.3).

Model Profile — конфигурация провайдера/модели/лимитов. Агент привязан к
профилю; смена профиля — настройка, но платформа отказывает в
переключении, если новый профиль не покрывает требуемые capabilities агента.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from admintwin_ai.errors import ProfileSwitchRefusedError, ProviderConfigError
from admintwin_ai.providers.base import (
    Capability,
    ConnectionMode,
    LLMProvider,
    ProviderCapabilities,
)


class Pricing(BaseModel):
    """Цены за 1M токенов в USD (для учёта стоимости и бюджетов)."""

    model_config = ConfigDict(frozen=True)

    input_per_mtok: float = Field(default=0.0, ge=0)
    output_per_mtok: float = Field(default=0.0, ge=0)

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self.input_per_mtok + output_tokens * self.output_per_mtok) / 1e6


class ModelProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    provider: str  # id провайдера из конфигурации
    model: str = Field(min_length=1)  # идентификатор модели — только из конфигурации
    capabilities: ProviderCapabilities | None = None  # None — как у провайдера×режима
    max_output_tokens: int = Field(default=4096, gt=0)
    params: dict[str, Any] = Field(default_factory=dict)
    pricing: Pricing = Field(default_factory=Pricing)
    downgrade_to: str | None = None  # профиль при ≥80% бюджета
    embedding_model: str | None = None
    enabled: bool = True  # feature flag провайдера×режима (§23 п.7)
    # Подписочный канал: только учётная запись самого клиента (§6.7, §6.8)
    owner_tenant_id: str | None = None


class CapabilityRequirements(BaseModel):
    """Что агент требует от модели."""

    model_config = ConfigDict(frozen=True)

    capabilities: frozenset[Capability] = frozenset()
    min_context: int = Field(default=0, ge=0)


class ProfileRegistry:
    """Профили + экземпляры провайдеров; вычисляет эффективные возможности."""

    def __init__(self, profiles: Iterable[ModelProfile],
                 providers: Mapping[str, LLMProvider]) -> None:
        self._profiles: dict[str, ModelProfile] = {}
        self._providers = dict(providers)
        for p in profiles:
            if p.id in self._profiles:
                raise ProviderConfigError(f"duplicate model profile '{p.id}'")
            if p.provider not in self._providers:
                raise ProviderConfigError(
                    f"profile '{p.id}' references unknown provider '{p.provider}'"
                )
            self._profiles[p.id] = p
        for p in self._profiles.values():
            if p.downgrade_to is not None and p.downgrade_to not in self._profiles:
                raise ProviderConfigError(
                    f"profile '{p.id}' downgrades to unknown profile '{p.downgrade_to}'"
                )

    def __contains__(self, profile_id: object) -> bool:
        return profile_id in self._profiles

    def get(self, profile_id: str) -> ModelProfile:
        try:
            return self._profiles[profile_id]
        except KeyError:
            raise ProviderConfigError(f"unknown model profile '{profile_id}'") from None

    def all(self) -> list[ModelProfile]:
        return list(self._profiles.values())

    def provider_for(self, profile_id: str) -> LLMProvider:
        return self._providers[self.get(profile_id).provider]

    def is_external(self, profile_id: str) -> bool:
        return bool(self.provider_for(profile_id).is_external)

    def mode(self, profile_id: str) -> ConnectionMode:
        return self.provider_for(profile_id).mode

    def effective_capabilities(self, profile_id: str) -> ProviderCapabilities:
        profile = self.get(profile_id)
        provider_caps = self.provider_for(profile_id).capabilities()
        if profile.capabilities is None:
            return provider_caps
        return provider_caps.intersect(profile.capabilities)

    def missing(self, profile_id: str, req: CapabilityRequirements) -> list[str]:
        """Пустой список — профиль покрывает требования."""
        profile = self.get(profile_id)
        caps = self.effective_capabilities(profile_id)
        missing = sorted(c.value for c in req.capabilities - caps.supported())
        if req.min_context and caps.max_context < req.min_context:
            missing.append(f"max_context>={req.min_context} (has {caps.max_context})")
        if not profile.enabled:
            missing.append("profile_enabled")
        return missing

    def local_profiles(self) -> list[str]:
        return [p.id for p in self._profiles.values() if not self.is_external(p.id)]


def check_profile_switch(registry: ProfileRegistry, agent_id: str, new_profile_id: str,
                         requirements: CapabilityRequirements) -> None:
    """Бросает ``ProfileSwitchRefusedError``, если профиль не покрывает требования."""
    if new_profile_id not in registry:
        raise ProfileSwitchRefusedError(agent_id, new_profile_id, ["profile_exists"])
    missing = registry.missing(new_profile_id, requirements)
    if missing:
        raise ProfileSwitchRefusedError(agent_id, new_profile_id, missing)
