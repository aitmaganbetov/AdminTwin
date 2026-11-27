"""Записи аудита AI-слоя.

``LLMCallRecord`` (§6.3): провайдер, модель, режим, prompt_version, SHA-256
входа, токены, стоимость, latency. **Сырой промпт в запись не попадает
никогда** (§23 п.5); полные маскированные промпты хранятся отдельно по
ретенции tenant (не в этом пакете).

``ToolCallRecord``: каждый вызов Tool Layer, включая отказы (T-CAP-001,
T-CAP-003 требуют запись в аудит).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from admintwin_ai.classification import DataClass


def sha256_of(obj: Any) -> str:
    """Канонический SHA-256 (отсортированные ключи, UTF-8)."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    data = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


class LLMCallRecord(BaseModel):
    record_type: Literal["llm_call"] = "llm_call"
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    at: datetime = Field(default_factory=_now)
    tenant_id: str
    task_id: str | None = None
    agent_id: str | None = None
    provider: str
    model: str  # фактически обслужившая модель
    requested_model: str
    mode: str
    profile_id: str
    prompt_version: str
    input_sha256: str  # хэш входа в том виде, в каком он отправлен провайдеру
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    status: Literal["ok", "error", "refused"]
    error_type: str | None = None
    finish_reason: str | None = None
    data_class: DataClass
    masked: bool = False
    external: bool
    attempt: int = 0  # 0 — primary, далее fallback-кандидаты
    routing_reasons: list[str] = Field(default_factory=list)


class ToolCallRecord(BaseModel):
    record_type: Literal["tool_call"] = "tool_call"
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    at: datetime = Field(default_factory=_now)
    tenant_id: str
    agent_id: str
    task_id: str | None = None
    tool: str
    kind: str | None = None  # read | propose | None (инструмент не существует)
    status: Literal["ok", "refused", "error"]
    reason: str | None = None
    params_sha256: str
    data_class: DataClass | None = None
    response_bytes: int = 0
    truncated: bool = False
    suspected_injection: bool = False
    latency_ms: float = 0.0


class RoutingRecord(BaseModel):
    record_type: Literal["routing"] = "routing"
    at: datetime = Field(default_factory=_now)
    tenant_id: str
    task_id: str | None = None
    agent_id: str | None = None
    status: str
    block_reason: str | None = None
    data_class: DataClass
    task_class: str
    reasons: list[str]


AuditRecord = LLMCallRecord | ToolCallRecord | RoutingRecord


class AuditSink(Protocol):
    def emit(self, record: AuditRecord) -> None: ...


class InMemoryAuditSink:
    """Для тестов и dev; в production — audit service ядра (append-only, hash chain)."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def emit(self, record: AuditRecord) -> None:
        self.records.append(record)

    def of_type(self, record_type: str) -> list[AuditRecord]:
        return [r for r in self.records if r.record_type == record_type]
