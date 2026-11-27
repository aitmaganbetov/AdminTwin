"""Модель агента (§5.2) и инварианты безопасности.

AI Agent — машинная идентичность: никогда не approver, никогда не получает
секрет, shell или break-glass (§2.1, §23 п.10). Это закреплено в модели:

* в схеме нет полей для секретов/учётных данных (``extra="forbid"``);
* ``allowed_tools`` не может содержать инструменты исполнения, shell,
  согласования или доступа к секретам — такие имена отклоняются;
* операции capability агента ограничены уровнями ≤ propose.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from admintwin_ai.classification import DataClass
from admintwin_ai.profiles import CapabilityRequirements
from admintwin_ai.providers.base import Capability


class AgentStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DRAFT = "draft"


class OperationLevel(StrEnum):
    OBSERVE = "observe"
    DIAGNOSE = "diagnose"
    RECOMMEND = "recommend"
    PROPOSE = "propose"
    EXECUTE = "execute"
    VERIFY = "verify"
    ROLLBACK = "rollback"


#: Уровни, доступные AI Agent (≤ propose, §3.2).
AGENT_OPERATION_LEVELS = frozenset({
    OperationLevel.OBSERVE, OperationLevel.DIAGNOSE, OperationLevel.RECOMMEND,
    OperationLevel.PROPOSE,
})

#: Имена инструментов, которые агенту не могут быть выданы ни при каких настройках.
_FORBIDDEN_TOOL = re.compile(
    r"(?i)(^|[._])(shell|exec|execute|execution|executions|ssh|run|command"
    r"|approve|approval|decision|decisions"
    r"|secret|secrets|vault|credential|credentials|break_glass|breakglass|kill_switch)([._]|$)"
)


class AgentBudget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tokens: int = Field(gt=0)
    tool_calls: int = Field(gt=0)
    wall_time_s: float = Field(gt=0)
    subtask_depth: int = Field(default=3, gt=0)


class AgentRouting(BaseModel):
    """Детерминированные правила выбора агента Commander-ом (§5.3)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_types: frozenset[str] = frozenset()
    service_kinds: frozenset[str] = frozenset()
    alert_types: frozenset[str] = frozenset()


class AgentDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str
    tenant_id: str | None = None  # None — платформенный шаблон, доступный всем tenants
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    prompt_version: str
    allowed_capabilities: frozenset[str] = frozenset()
    capability_levels: frozenset[OperationLevel] = AGENT_OPERATION_LEVELS
    allowed_tools: frozenset[str]
    # runbooks, которые агент может предложить через change.propose
    allowed_runbooks: frozenset[str] = frozenset()
    model_profile: str
    fallback_model_profile: str | None = None
    required_model_capabilities: frozenset[Capability] = frozenset({Capability.TOOL_CALLING})
    min_context: int = Field(default=32_768, ge=0)
    policy_id: str
    budget: AgentBudget
    data_sensitivity_max: DataClass = DataClass.CONFIDENTIAL
    status: AgentStatus = AgentStatus.ACTIVE
    routing: AgentRouting = Field(default_factory=AgentRouting)

    @field_validator("allowed_tools")
    @classmethod
    def _no_forbidden_tools(cls, tools: frozenset[str]) -> frozenset[str]:
        bad = sorted(t for t in tools if _FORBIDDEN_TOOL.search(t))
        if bad:
            raise ValueError(f"agents may never hold execute/shell/approval/secret tools: {bad}")
        return tools

    @field_validator("capability_levels")
    @classmethod
    def _levels_le_propose(cls, levels: frozenset[OperationLevel]) -> frozenset[OperationLevel]:
        bad = sorted(lv.value for lv in levels - AGENT_OPERATION_LEVELS)
        if bad:
            raise ValueError(f"AI agents own operations only up to 'propose'; got {bad}")
        return levels

    @field_validator("data_sensitivity_max")
    @classmethod
    def _no_secret_access(cls, value: DataClass) -> DataClass:
        if value in (DataClass.SECRET, DataClass.UNKNOWN):
            raise ValueError("agents never receive secrets: data_sensitivity_max must be <= pii")
        return value

    @property
    def requirements(self) -> CapabilityRequirements:
        return CapabilityRequirements(capabilities=self.required_model_capabilities,
                                      min_context=self.min_context)

    @property
    def is_active(self) -> bool:
        return self.status is AgentStatus.ACTIVE
