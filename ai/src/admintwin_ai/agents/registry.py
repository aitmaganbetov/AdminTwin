"""Agent Registry (M02): загрузка определений агентов и проверка инвариантов."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from admintwin_ai.agents.model import AgentDefinition
from admintwin_ai.errors import AgentDefinitionError
from admintwin_ai.profiles import ProfileRegistry, check_profile_switch
from admintwin_ai.resources import data_path

if TYPE_CHECKING:
    from admintwin_ai.tools.registry import ToolRegistry

MVP_AGENT_IDS = ("ai-commander", "linux-admin", "network-engineer", "devops-engineer",
                 "dba-engineer")


def load_agents(path: str | Path | None = None) -> list[AgentDefinition]:
    path = Path(path) if path is not None else data_path("agents", "mvp-agents.yaml")
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return [AgentDefinition.model_validate(item) for item in raw["agents"]]


class AgentRegistry:
    def __init__(self, agents: Iterable[AgentDefinition], *,
                 tools: ToolRegistry | None = None,
                 profiles: ProfileRegistry | None = None) -> None:
        self._agents: dict[str, AgentDefinition] = {}
        self._profiles = profiles
        for agent in agents:
            if agent.id in self._agents:
                raise AgentDefinitionError(f"duplicate agent '{agent.id}'")
            if tools is not None:
                tools.validate_agent(agent)
            if profiles is not None:
                for pid in filter(None, (agent.model_profile, agent.fallback_model_profile)):
                    check_profile_switch(profiles, agent.id, pid, agent.requirements)
            self._agents[agent.id] = agent

    def get(self, agent_id: str) -> AgentDefinition:
        try:
            return self._agents[agent_id]
        except KeyError:
            raise AgentDefinitionError(f"unknown agent '{agent_id}'") from None

    def __contains__(self, agent_id: object) -> bool:
        return agent_id in self._agents

    def all(self) -> list[AgentDefinition]:
        return list(self._agents.values())

    def switch_profile(self, agent_id: str, new_profile_id: str, *,
                       fallback: bool = False) -> AgentDefinition:
        """Смена model profile — настройка, но с проверкой capabilities (§6.3).

        Бросает ``ProfileSwitchRefusedError``; при отказе агент не меняется.
        """
        if self._profiles is None:
            raise AgentDefinitionError("profile registry is not configured")
        agent = self.get(agent_id)
        check_profile_switch(self._profiles, agent_id, new_profile_id, agent.requirements)
        field = "fallback_model_profile" if fallback else "model_profile"
        updated = agent.model_copy(update={field: new_profile_id})
        self._agents[agent_id] = updated
        return updated
