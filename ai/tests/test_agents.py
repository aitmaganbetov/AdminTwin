"""Agent Registry (§5.2): MVP-агенты как данные и инварианты безопасности."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from admintwin_ai.agents import MVP_AGENT_IDS, AgentDefinition, AgentRegistry, load_agents
from admintwin_ai.classification import DataClass
from admintwin_ai.tools import ToolKind, ToolRegistry


def test_mvp_agents_loaded(tool_registry: ToolRegistry) -> None:
    agents = load_agents()
    assert tuple(a.id for a in agents) == MVP_AGENT_IDS
    registry = AgentRegistry(agents, tools=tool_registry)
    for agent in registry.all():
        assert agent.is_active and agent.allowed_tools
        kinds = {tool_registry.get(t).kind for t in agent.allowed_tools}  # type: ignore[union-attr]
        assert kinds <= {ToolKind.READ, ToolKind.PROPOSE}
        assert agent.data_sensitivity_max.rank <= DataClass.PII.rank
        if "change.propose" in agent.allowed_tools:
            assert agent.allowed_runbooks
        else:
            assert not agent.allowed_runbooks


def test_mvp_runbooks_match_spec() -> None:
    agents = {a.id: a for a in load_agents()}
    proposable = set().union(*(a.allowed_runbooks for a in agents.values()))
    assert proposable == {"docker.container.restart", "linux.service.restart",
                          "linux.logs.rotate_cleanup"}
    assert "change.propose" not in agents["ai-commander"].allowed_tools


def _base() -> dict[str, object]:
    return load_agents()[1].model_dump()


@pytest.mark.parametrize("tool", ["shell.exec", "ssh.run", "change.approve", "vault.read",
                                  "secrets.get", "execution.create", "break_glass.start",
                                  "linux.command.exec"])
def test_forbidden_tools_rejected(tool: str) -> None:
    data = _base()
    data["allowed_tools"] = [*data["allowed_tools"], tool]  # type: ignore[misc]
    with pytest.raises(ValidationError, match="never hold"):
        AgentDefinition.model_validate(data)


def test_no_execute_level_and_no_secret_access() -> None:
    data = _base()
    data["capability_levels"] = ["observe", "execute"]
    with pytest.raises(ValidationError, match="propose"):
        AgentDefinition.model_validate(data)
    data = _base()
    data["data_sensitivity_max"] = "secret"
    with pytest.raises(ValidationError, match="secrets"):
        AgentDefinition.model_validate(data)


@pytest.mark.parametrize("field", ["api_key", "credentials", "shell", "approver"])
def test_agent_model_has_no_secret_or_approval_fields(field: str) -> None:
    data = _base()
    data[field] = "x"
    with pytest.raises(ValidationError):
        AgentDefinition.model_validate(data)
