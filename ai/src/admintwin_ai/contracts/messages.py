"""Контракт межагентного сообщения (§7): Pydantic-модель + JSON Schema.

Источник истины — ``ai/contracts/agent-message.schema.json`` (contract-first,
§23 п.1). Pydantic-модель повторяет схему для удобной работы в Python;
``AgentMessage.to_wire()`` всегда валидирует результат по JSON Schema.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from enum import StrEnum
from functools import lru_cache
from typing import Any, Literal

import jsonschema
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from admintwin_ai.errors import ContractValidationError
from admintwin_ai.resources import load_json

SCHEMA_VERSION: Literal["1.3"] = "1.3"


class MessageType(StrEnum):
    TASK_REQUEST = "task.request"
    TASK_ACCEPTED = "task.accepted"
    TASK_PROGRESS = "task.progress"
    TASK_RESULT = "task.result"
    TASK_FAILED = "task.failed"
    TASK_BLOCKED = "task.blocked"
    TASK_INPUT_REQUIRED = "task.input_required"
    TASK_CANCELLED = "task.cancelled"
    EVIDENCE_ADDED = "evidence.added"
    CHANGE_PROPOSED = "change.proposed"
    APPROVAL_REQUESTED = "approval.requested"
    EXECUTION_STARTED = "execution.started"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_CANCELLATION_PENDING = "execution.cancellation_pending"
    BUDGET_WARNING = "budget.warning"
    BUDGET_EXHAUSTED = "budget.exhausted"


Priority = Literal["low", "normal", "high", "critical"]
Environment = Literal["production", "staging", "dev", "test"]  # ТЗ §8.3
Sensitivity = Literal["public", "internal", "confidential", "pii", "secret"]

_AGENT_ID = r"^[a-z][a-z0-9-]{1,62}$"


class MessageScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    environment: Environment
    data_sensitivity_max: Sensitivity


class MessageBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_tokens: int = Field(ge=0)
    max_tool_calls: int = Field(ge=0)
    deadline_at: AwareDatetime


class AgentMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.3"] = SCHEMA_VERSION
    message_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID
    task_id: uuid.UUID
    parent_task_id: uuid.UUID | None = None
    correlation_id: uuid.UUID
    causation_id: uuid.UUID
    from_agent: str = Field(pattern=_AGENT_ID)
    to_agent: str = Field(pattern=_AGENT_ID)
    type: MessageType
    priority: Priority = "normal"
    timestamp: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    scope: MessageScope
    budget: MessageBudget
    payload: dict[str, Any] = Field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        """JSON-представление для NATS; гарантированно валидно по JSON Schema."""
        data = self.model_dump(mode="json")
        validate_message(data)
        return data

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> AgentMessage:
        validate_message(data)
        return cls.model_validate(data)


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    schema = load_json("contracts", "agent-message.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )


def validate_message(data: dict[str, Any]) -> None:
    errors = sorted(_validator().iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "<root>"
        raise ContractValidationError(f"agent message invalid at {where}: {first.message}")


class MessageDeduplicator:
    """Идемпотентная обработка при at-least-once доставке: повтор message_id
    пропускается. Ограниченный LRU, чтобы память не росла бесконечно."""

    def __init__(self, capacity: int = 10_000) -> None:
        self._seen: OrderedDict[uuid.UUID, None] = OrderedDict()
        self._capacity = capacity

    def seen(self, message: AgentMessage) -> bool:
        """Сообщение уже успешно обработано (без отметки)."""
        return message.message_id in self._seen

    def mark(self, message: AgentMessage) -> None:
        """Отметить обработанным (после успешной обработки — at-least-once)."""
        self._seen[message.message_id] = None
        self._seen.move_to_end(message.message_id)
        if len(self._seen) > self._capacity:
            self._seen.popitem(last=False)

    def first_delivery(self, message: AgentMessage) -> bool:
        if message.message_id in self._seen:
            self._seen.move_to_end(message.message_id)
            return False
        self._seen[message.message_id] = None
        if len(self._seen) > self._capacity:
            self._seen.popitem(last=False)
        return True
