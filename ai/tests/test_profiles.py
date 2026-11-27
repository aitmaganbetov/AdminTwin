"""Model Profiles: проверка покрытия capabilities при смене профиля (§6.3)."""

from __future__ import annotations

import pytest

from admintwin_ai.agents import AgentRegistry, load_agents
from admintwin_ai.config import EnvSecretResolver, build_registry, load_config
from admintwin_ai.errors import ProfileSwitchRefusedError, ProviderConfigError
from admintwin_ai.profiles import (
    CapabilityRequirements,
    ModelProfile,
    ProfileRegistry,
    check_profile_switch,
)
from admintwin_ai.providers import Capability, ProviderCapabilities
from admintwin_ai.resources import data_path

from fakes import FakeAnthropicClient, FakeOpenAIClient, FakeProvider, make_registry

NO_TOOLS = ProviderCapabilities(tool_calling=False, structured_output=False, streaming=True,
                                embeddings=True, max_context=8192)


def _registry_with_weak_local() -> ProfileRegistry:
    return make_registry(local=FakeProvider("local", external=False, caps=NO_TOOLS))


def test_effective_capabilities_are_intersection() -> None:
    providers = {"p": FakeProvider("p", external=True, caps=NO_TOOLS)}
    # профиль не может заявить больше, чем провайдер×режим
    profile = ModelProfile(id="x", provider="p", model="m",
                           capabilities=ProviderCapabilities(tool_calling=True, streaming=True,
                                                             max_context=100_000))
    reg = ProfileRegistry([profile], providers)
    caps = reg.effective_capabilities("x")
    assert caps.tool_calling is False
    assert caps.max_context == 8192


def test_switch_refused_when_capabilities_missing() -> None:
    reg = _registry_with_weak_local()
    agents = AgentRegistry(load_agents(), profiles=reg)
    before = agents.get("linux-admin")
    with pytest.raises(ProfileSwitchRefusedError) as info:
        agents.switch_profile("linux-admin", "local-default")
    assert "tool_calling" in info.value.missing
    assert any(m.startswith("max_context>=") for m in info.value.missing)
    assert agents.get("linux-admin") == before  # агент не изменился


def test_switch_allowed_when_covered() -> None:
    reg = make_registry()
    agents = AgentRegistry(load_agents(), profiles=reg)
    updated = agents.switch_profile("linux-admin", "openai-secondary")
    assert updated.model_profile == "openai-secondary"
    updated = agents.switch_profile("linux-admin", "local-default", fallback=True)
    assert updated.fallback_model_profile == "local-default"


def test_switch_refused_for_disabled_or_unknown_profile() -> None:
    providers = {"p": FakeProvider("p", external=True)}
    reg = ProfileRegistry([ModelProfile(id="off", provider="p", model="m", enabled=False)],
                          providers)
    req = CapabilityRequirements(capabilities=frozenset({Capability.TOOL_CALLING}))
    with pytest.raises(ProfileSwitchRefusedError, match="profile_enabled"):
        check_profile_switch(reg, "a", "off", req)
    with pytest.raises(ProfileSwitchRefusedError, match="profile_exists"):
        check_profile_switch(reg, "a", "nope", req)


def test_registry_rejects_bad_references() -> None:
    providers = {"p": FakeProvider("p", external=True)}
    with pytest.raises(ProviderConfigError, match="unknown provider"):
        ProfileRegistry([ModelProfile(id="a", provider="zzz", model="m")], providers)
    with pytest.raises(ProviderConfigError, match="downgrades to unknown"):
        ProfileRegistry([ModelProfile(id="a", provider="p", model="m", downgrade_to="b")],
                        providers)


def test_example_config_builds_with_injected_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_config(data_path("config", "model-profiles.example.yaml"))
    reg = build_registry(cfg, EnvSecretResolver(), clients={
        "claude-api": FakeAnthropicClient(), "openai-api": FakeOpenAIClient(),
        "local-vllm": FakeOpenAIClient(),
    })
    assert reg.is_external("claude-primary") and not reg.is_external("local-default")
    # модели заданы только в конфигурации
    assert reg.get("claude-primary").model == "claude-opus-5-5"
    assert reg.get("claude-primary").downgrade_to == "claude-economy"
    assert Capability.EMBEDDINGS not in reg.effective_capabilities("claude-primary").supported()
    assert reg.effective_capabilities("openai-secondary").max_context == 400_000
    # агенты MVP покрываются профилями примера
    AgentRegistry(load_agents(), profiles=reg)


def test_env_secret_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AT_TEST_KEY", "value")
    r = EnvSecretResolver()
    assert r.resolve("env:AT_TEST_KEY") == "value"
    with pytest.raises(ProviderConfigError):
        r.resolve("vault:secret/data/x")
    monkeypatch.delenv("AT_TEST_KEY")
    with pytest.raises(ProviderConfigError):
        r.resolve("env:AT_TEST_KEY")
