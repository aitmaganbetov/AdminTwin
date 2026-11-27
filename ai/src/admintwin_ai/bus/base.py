"""Межагентная шина (§7): абстракция и общая логика доставки.

Конверт — ``AgentMessage`` (``ai/contracts/agent-message.schema.json``),
валидируется при публикации и при получении. Требования §7, которые
реализует каждая шина:

* **at-least-once** — сообщение подтверждается только после успешной
  обработки; ошибка обработчика → повтор с backoff;
* **идемпотентность** — повтор ``message_id`` (дубль публикации или
  redelivery после сбоя подтверждения) обработчик не видит;
* **DLQ** — после ``max_deliver`` попыток, при невалидном конверте или
  просроченном дедлайне сообщение уходит в ``admintwin.dlq.<tenant>.<agent>``;
* **дедлайны** — ``budget.deadline_at``: просроченное сообщение не
  обрабатывается, обработка прерывается по дедлайну;
* **отмена** — ``cancel_task(task_id)``: новые сообщения задачи и её
  подзадач (``parent_task_id``) отбрасываются, обработчики в полёте
  отменяются (kill switch §11.7);
* **bounded concurrency** — не более ``concurrency`` обработчиков на подписку.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from admintwin_ai.contracts.messages import AgentMessage, MessageDeduplicator

log = logging.getLogger("admintwin.bus")

Handler = Callable[[AgentMessage], Awaitable[None]]

SUBJECT_PREFIX = "admintwin.agents"
DLQ_PREFIX = "admintwin.dlq"
CONTROL_CANCEL = "admintwin.control.cancel"


def subject_for(tenant_id: str | uuid.UUID, agent_id: str) -> str:
    return f"{SUBJECT_PREFIX}.{tenant_id}.{agent_id}"


def dlq_subject_for(tenant_id: str | uuid.UUID, agent_id: str) -> str:
    return f"{DLQ_PREFIX}.{tenant_id}.{agent_id}"


class DeliveryPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_deliver: int = Field(default=3, ge=1)
    backoff_s: tuple[float, ...] = (0.05, 0.25, 1.0)
    concurrency: int = Field(default=16, ge=1)
    ack_wait_s: float = Field(default=30.0, gt=0)

    def delay(self, attempt: int) -> float:
        if not self.backoff_s:
            return 0.0
        return self.backoff_s[min(attempt - 1, len(self.backoff_s) - 1)]


class DeadLetter(BaseModel):
    subject: str
    reason: str  # max_deliver_exceeded | invalid_envelope | deadline_exceeded
    attempts: int
    error: str | None = None
    message: dict[str, Any] | None = None
    raw: str | None = None
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HandlerOutcome(BaseModel):
    """Результат одной попытки доставки."""

    action: str  # ack | retry | dead
    reason: str | None = None
    error: str | None = None


class _CancelRegistry:
    """Отменённые задачи и обработчики в полёте (общая часть шин)."""

    def __init__(self) -> None:
        self.cancelled: set[uuid.UUID] = set()
        self._inflight: dict[uuid.UUID, set[asyncio.Task[Any]]] = {}

    def is_cancelled(self, msg: AgentMessage) -> bool:
        return msg.task_id in self.cancelled or (
            msg.parent_task_id is not None and msg.parent_task_id in self.cancelled)

    def track(self, msg: AgentMessage, task: asyncio.Task[Any]) -> None:
        for key in filter(None, (msg.task_id, msg.parent_task_id)):
            self._inflight.setdefault(key, set()).add(task)

    def untrack(self, msg: AgentMessage, task: asyncio.Task[Any]) -> None:
        for key in filter(None, (msg.task_id, msg.parent_task_id)):
            tasks = self._inflight.get(key)
            if tasks is not None:
                tasks.discard(task)
                if not tasks:
                    self._inflight.pop(key, None)

    def cancel(self, task_id: uuid.UUID) -> int:
        self.cancelled.add(task_id)
        tasks = self._inflight.pop(task_id, set())
        for t in tasks:
            t.cancel()
        return len(tasks)


class AgentBus(ABC):
    """Шина сообщений агентов. Реализации: in-process (по умолчанию), NATS JetStream."""

    def __init__(self, policy: DeliveryPolicy | None = None) -> None:
        self.policy = policy or DeliveryPolicy()
        self._cancel = _CancelRegistry()
        self._dedup: dict[str, MessageDeduplicator] = {}
        self._dlq_handlers: list[Callable[[DeadLetter], Awaitable[None]]] = []

    @property
    @abstractmethod
    def kind(self) -> str: ...

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...

    @abstractmethod
    async def publish(self, message: AgentMessage) -> None:
        """Публикация; конверт валидируется по JSON Schema (``to_wire``)."""

    @abstractmethod
    async def subscribe(self, agent_id: str, handler: Handler) -> None:
        """Подписка агента на сообщения всех tenant (tenant — в конверте)."""

    async def cancel_task(self, task_id: uuid.UUID) -> int:
        """Отменить задачу: сообщения отбрасываются, обработчики в полёте отменяются."""
        return self._cancel.cancel(task_id)

    def on_dead_letter(self, handler: Callable[[DeadLetter], Awaitable[None]]) -> None:
        self._dlq_handlers.append(handler)

    async def healthy(self) -> bool:
        return True

    # --- общая логика одной попытки --------------------------------------------

    def _dedup_for(self, agent_id: str) -> MessageDeduplicator:
        return self._dedup.setdefault(agent_id, MessageDeduplicator())

    async def _attempt(self, agent_id: str, msg: AgentMessage, handler: Handler,
                       attempt: int) -> HandlerOutcome:
        """Одна попытка обработки с учётом идемпотентности, дедлайна и отмены."""
        dedup = self._dedup_for(agent_id)
        if dedup.seen(msg):
            return HandlerOutcome(action="ack", reason="duplicate")
        if self._cancel.is_cancelled(msg):
            dedup.mark(msg)
            return HandlerOutcome(action="ack", reason="cancelled")
        remaining = (msg.budget.deadline_at - datetime.now(UTC)).total_seconds()
        if remaining <= 0:
            dedup.mark(msg)
            return HandlerOutcome(action="dead", reason="deadline_exceeded")
        task = asyncio.current_task()
        if task is not None:
            self._cancel.track(msg, task)
        try:
            async with asyncio.timeout(remaining):
                await handler(msg)
        except TimeoutError:
            dedup.mark(msg)
            return HandlerOutcome(action="dead", reason="deadline_exceeded")
        except asyncio.CancelledError:
            if self._cancel.is_cancelled(msg):
                dedup.mark(msg)
                # отмена задачи — штатное завершение доставки, а не сбой шины
                return HandlerOutcome(action="ack", reason="cancelled")
            raise
        except Exception as exc:
            log.warning("bus handler failed", extra={"agent": agent_id, "attempt": attempt,
                                                     "message_id": str(msg.message_id)})
            if attempt >= self.policy.max_deliver:
                dedup.mark(msg)
                return HandlerOutcome(action="dead", reason="max_deliver_exceeded",
                                      error=f"{type(exc).__name__}: {exc}"[:500])
            return HandlerOutcome(action="retry", error=f"{type(exc).__name__}: {exc}"[:500])
        finally:
            if task is not None:
                self._cancel.untrack(msg, task)
        dedup.mark(msg)
        return HandlerOutcome(action="ack")

    async def _emit_dead(self, letter: DeadLetter) -> None:
        for h in self._dlq_handlers:
            with contextlib.suppress(Exception):
                await h(letter)
