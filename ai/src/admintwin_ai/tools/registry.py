"""Реестр инструментов Tool Layer (§3.3).

Инструменты бывают только двух видов: ``read`` и ``propose``. Вида
``execute`` не существует на уровне типов: регистрация инструмента с иным
kind невозможна, а запись в инфраструктуру выполняется только Execution
Gateway из согласованного ChangeRequest (§11).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jsonschema
from pydantic import BaseModel, ConfigDict, Field

from admintwin_ai.classification import DataClass
from admintwin_ai.errors import AgentDefinitionError, ToolRegistrationError
from admintwin_ai.providers.base import ToolSpec
from admintwin_ai.resources import data_path, load_json

if TYPE_CHECKING:
    from admintwin_ai.agents.model import AgentDefinition
    from admintwin_ai.tools.invoker import ToolContext


class ToolKind(StrEnum):
    READ = "read"
    PROPOSE = "propose"


class ToolOutput(BaseModel):
    """Ответ обработчика: данные + класс данных источника (None — класс контракта)."""

    data: dict[str, Any]
    data_class: DataClass | None = None


class ToolRefusal(Exception):  # noqa: N818 - это отказ, а не ошибка
    """Обработчик отказывает в вызове (policy-denied, runbook не разрешён и т.п.)."""

    def __init__(self, reason: str, detail: str = "", problem: dict[str, Any] | None = None):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
        self.problem = problem


class ToolBackendError(Exception):
    """Сбой источника данных или ядра (не отказ политики)."""


ToolHandler = Callable[["ToolContext", dict[str, Any]], ToolOutput]


class ToolContract(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_ref: str | None = Field(default=None, alias="$schema")
    name: str
    kind: ToolKind
    version: str
    description: str
    data_class: DataClass
    max_response_bytes: int
    rate_limit_per_minute: int
    capabilities: tuple[str, ...] = ()
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]


class ToolDefinition:
    def __init__(self, contract: ToolContract, handler: ToolHandler) -> None:
        self.contract = contract
        self.handler = handler
        fc = jsonschema.Draft202012Validator.FORMAT_CHECKER
        self.input_validator = jsonschema.Draft202012Validator(contract.input_schema,
                                                               format_checker=fc)
        self.output_validator = jsonschema.Draft202012Validator(contract.output_schema,
                                                                format_checker=fc)

    @property
    def name(self) -> str:
        return self.contract.name

    @property
    def kind(self) -> ToolKind:
        return self.contract.kind

    def spec(self) -> ToolSpec:
        return ToolSpec(name=self.name, description=self.contract.description,
                        input_schema=self.contract.input_schema)


@lru_cache(maxsize=1)
def _contract_meta_validator() -> jsonschema.Draft202012Validator:
    meta = load_json("tools", "tool-contract.schema.json")
    return jsonschema.Draft202012Validator(meta)


def load_contract(path: Path) -> ToolContract:
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    errors = list(_contract_meta_validator().iter_errors(raw))
    if errors:
        raise ToolRegistrationError(f"{path.name}: {errors[0].message}")
    for key in ("input_schema", "output_schema"):
        jsonschema.Draft202012Validator.check_schema(raw[key])
    contract = ToolContract.model_validate(raw)
    expected_dir = contract.kind.value
    if path.parent.name != expected_dir:
        raise ToolRegistrationError(f"{path.name}: kind '{contract.kind}' must live in "
                                    f"tools/{expected_dir}/")
    return contract


def load_contracts(root: Path | None = None) -> dict[str, ToolContract]:
    root = root or data_path("tools")
    contracts: dict[str, ToolContract] = {}
    for sub in ("read", "propose"):
        for path in sorted((root / sub).glob("*.json")):
            c = load_contract(path)
            contracts[c.name] = c
    return contracts


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, contract: ToolContract, handler: ToolHandler) -> None:
        # ToolKind содержит только read/propose; проверка — защита от обхода типов.
        if not isinstance(contract.kind, ToolKind):
            raise ToolRegistrationError(f"tool kind '{contract.kind}' is not allowed")
        if contract.name in self._tools:
            raise ToolRegistrationError(f"duplicate tool '{contract.name}'")
        props = contract.input_schema.get("properties", {})
        if "tenant_id" in props:
            raise ToolRegistrationError(
                f"{contract.name}: tenant_id must come from context, never from parameters"
            )
        self._tools[contract.name] = ToolDefinition(contract, handler)

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[ToolDefinition]:
        return [self._tools[n] for n in self.names()]

    def specs_for(self, agent: AgentDefinition) -> list[ToolSpec]:
        """Модель видит только разрешённые агенту инструменты."""
        return [t.spec() for t in self.all() if t.name in agent.allowed_tools]

    def validate_agent(self, agent: AgentDefinition) -> None:
        unknown = sorted(t for t in agent.allowed_tools if t not in self._tools)
        if unknown:
            raise AgentDefinitionError(
                f"agent '{agent.id}' references tools without a confirmed tool scope: {unknown}"
            )


def register_all(registry: ToolRegistry, handlers: dict[str, ToolHandler],
                 contracts: Iterable[ToolContract] | None = None) -> ToolRegistry:
    for contract in contracts if contracts is not None else load_contracts().values():
        handler = handlers.get(contract.name)
        if handler is None:
            raise ToolRegistrationError(f"no handler for tool '{contract.name}'")
        registry.register(contract, handler)
    return registry
