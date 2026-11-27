"""Шина на NATS JetStream (§7). Включается ``ADMINTWIN_NATS_URL``.

* Stream ``ADMINTWIN_AGENTS``: субъекты ``admintwin.agents.<tenant>.<agent>``
  и ``admintwin.dlq.<tenant>.<agent>``; дедупликация публикаций по
  заголовку ``Nats-Msg-Id`` = ``message_id`` (окно ``duplicate_window_s``).
* На агента — durable push consumer с deliver group (горизонтальное
  масштабирование), ``AckExplicit``, ``max_deliver``, ``ack_wait``.
  Подтверждение — только после успешной обработки (at-least-once);
  ошибка → ``nak(delay)``; исчерпание попыток, невалидный конверт или
  просроченный дедлайн → публикация в DLQ и ``term``.
* Идемпотентность на стороне получателя — ``MessageDeduplicator`` по
  ``message_id`` (redelivery после потери ack).
* Отмена — core NATS ``admintwin.control.cancel`` (payload — task_id): все
  экземпляры оркестратора отбрасывают сообщения задачи и отменяют
  обработчики в полёте.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import nats
from nats.aio.client import Client as NATSClient
from nats.aio.msg import Msg
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy, StreamConfig
from nats.js.client import JetStreamContext
from nats.js.errors import NotFoundError

from admintwin_ai.bus.base import (
    CONTROL_CANCEL,
    DLQ_PREFIX,
    SUBJECT_PREFIX,
    AgentBus,
    DeadLetter,
    DeliveryPolicy,
    Handler,
    dlq_subject_for,
    subject_for,
)
from admintwin_ai.contracts.messages import AgentMessage
from admintwin_ai.errors import ContractValidationError

log = logging.getLogger("admintwin.bus.nats")

STREAM = "ADMINTWIN_AGENTS"


class NatsBus(AgentBus):
    def __init__(self, url: str, *, policy: DeliveryPolicy | None = None,
                 stream: str = STREAM, consumer_prefix: str = "agent",
                 duplicate_window_s: float = 120.0, connect_timeout_s: float = 5.0) -> None:
        super().__init__(policy)
        self._url = url
        self._stream = stream
        self._prefix = consumer_prefix
        self._dup_window = duplicate_window_s
        self._connect_timeout = connect_timeout_s
        self._nc: NATSClient | None = None
        self._js: JetStreamContext | None = None
        self._subs: list[Any] = []
        self._sem: dict[str, asyncio.Semaphore] = {}
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def kind(self) -> str:
        return "nats"

    @property
    def js(self) -> JetStreamContext:
        if self._js is None:
            raise RuntimeError("NatsBus is not started")
        return self._js

    async def start(self) -> None:
        self._nc = await nats.connect(self._url, connect_timeout=self._connect_timeout,
                                      name="admintwin-orchestrator", max_reconnect_attempts=-1)
        self._js = self._nc.jetstream()
        config = StreamConfig(name=self._stream,
                              subjects=[f"{SUBJECT_PREFIX}.>", f"{DLQ_PREFIX}.>"],
                              duplicate_window=self._dup_window)
        try:
            await self._js.stream_info(self._stream)
            await self._js.update_stream(config)
        except NotFoundError:
            await self._js.add_stream(config)
        await self._nc.subscribe(CONTROL_CANCEL, cb=self._on_cancel)

    async def close(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        for sub in self._subs:
            with contextlib.suppress(Exception):  # закрытие best-effort
                await sub.unsubscribe()
        self._subs.clear()
        if self._nc is not None and not self._nc.is_closed:
            await self._nc.drain()
        self._nc = None
        self._js = None

    async def healthy(self) -> bool:
        return self._nc is not None and self._nc.is_connected

    async def publish(self, message: AgentMessage) -> None:
        wire = message.to_wire()
        await self.js.publish(subject_for(message.tenant_id, message.to_agent),
                              json.dumps(wire, ensure_ascii=False).encode("utf-8"),
                              headers={"Nats-Msg-Id": str(message.message_id)})

    async def publish_raw(self, tenant: str, agent_id: str, raw: bytes,
                          msg_id: str | None = None) -> None:
        headers = {"Nats-Msg-Id": msg_id} if msg_id else None
        await self.js.publish(subject_for(tenant, agent_id), raw, headers=headers)

    async def subscribe(self, agent_id: str, handler: Handler) -> None:
        durable = f"{self._prefix}-{agent_id}"
        config = ConsumerConfig(
            durable_name=durable, deliver_group=durable, ack_policy=AckPolicy.EXPLICIT,
            max_deliver=self.policy.max_deliver, ack_wait=self.policy.ack_wait_s,
            max_ack_pending=self.policy.concurrency * 4, deliver_policy=DeliverPolicy.ALL,
            filter_subject=f"{SUBJECT_PREFIX}.*.{agent_id}",
        )
        self._sem[agent_id] = asyncio.Semaphore(self.policy.concurrency)

        async def on_msg(msg: Msg) -> None:
            t = asyncio.create_task(self._handle(agent_id, handler, msg))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)

        sub = await self.js.subscribe(f"{SUBJECT_PREFIX}.*.{agent_id}", queue=durable,
                                      durable=durable, cb=on_msg, manual_ack=True,
                                      config=config, stream=self._stream)
        self._subs.append(sub)

    async def subscribe_dlq(self, handler: Callable[[DeadLetter], Awaitable[None]], *,
                            durable: str = "dlq-reader") -> None:
        """Чтение DLQ (для эксплуатации и тестов): handler(DeadLetter)."""
        async def on_msg(msg: Msg) -> None:
            try:
                letter = DeadLetter.model_validate_json(msg.data)
            finally:
                await msg.ack()
            await handler(letter)

        sub = await self.js.subscribe(f"{DLQ_PREFIX}.>", durable=durable, cb=on_msg,
                                      manual_ack=True, stream=self._stream)
        self._subs.append(sub)

    async def cancel_task(self, task_id: uuid.UUID) -> int:
        n = await super().cancel_task(task_id)
        if self._nc is not None and self._nc.is_connected:
            await self._nc.publish(CONTROL_CANCEL, str(task_id).encode())
        return n

    async def _on_cancel(self, msg: Msg) -> None:
        try:
            task_id = uuid.UUID(msg.data.decode())
        except ValueError:
            return
        self._cancel.cancel(task_id)

    async def _handle(self, agent_id: str, handler: Handler, msg: Msg) -> None:
        attempt = msg.metadata.num_delivered or 1
        try:
            message = AgentMessage.from_wire(json.loads(msg.data))
        except (ValueError, ContractValidationError) as exc:
            await self._dead_letter(DeadLetter(
                subject=msg.subject, reason="invalid_envelope", attempts=attempt,
                error=str(exc)[:500], raw=msg.data[:4000].decode("utf-8", "replace")),
                tenant="invalid", agent_id=agent_id)
            await msg.term()
            return
        async with self._sem[agent_id]:
            outcome = await self._attempt(agent_id, message, handler, attempt)
        if outcome.action == "ack":
            await msg.ack()
        elif outcome.action == "retry":
            await msg.nak(delay=self.policy.delay(attempt))
        else:
            await self._dead_letter(DeadLetter(
                subject=msg.subject, reason=outcome.reason or "unknown", attempts=attempt,
                error=outcome.error, message=message.model_dump(mode="json")),
                tenant=str(message.tenant_id), agent_id=agent_id)
            await msg.term()

    async def _dead_letter(self, letter: DeadLetter, *, tenant: str, agent_id: str) -> None:
        await self.js.publish(dlq_subject_for(tenant, agent_id),
                              letter.model_dump_json().encode("utf-8"))
        await self._emit_dead(letter)
