"""In-process шина (по умолчанию, без NATS): asyncio-очереди с семантикой §7.

Сообщение сериализуется в JSON-конверт и десериализуется на стороне
получателя — как при сетевом транспорте, поэтому контракт проверяется
одинаково. Повторы — с backoff ``DeliveryPolicy``; после ``max_deliver`` —
DLQ (``dead_letters`` + обработчики ``on_dead_letter``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass, field

from admintwin_ai.bus.base import (
    AgentBus,
    DeadLetter,
    DeliveryPolicy,
    Handler,
    dlq_subject_for,
    subject_for,
)
from admintwin_ai.contracts.messages import AgentMessage
from admintwin_ai.errors import ContractValidationError


@dataclass
class _Subscription:
    agent_id: str
    handler: Handler
    queue: asyncio.Queue[tuple[str, int]] = field(default_factory=asyncio.Queue)
    workers: list[asyncio.Task[None]] = field(default_factory=list)


class InProcessBus(AgentBus):
    def __init__(self, policy: DeliveryPolicy | None = None) -> None:
        super().__init__(policy)
        self._subs: dict[str, _Subscription] = {}
        self._pending: dict[str, list[str]] = {}  # сообщения до подписки агента
        self._retry_tasks: set[asyncio.Task[None]] = set()
        self.dead_letters: list[DeadLetter] = []
        self.published: list[dict[str, object]] = []
        self._started = False

    @property
    def kind(self) -> str:
        return "inprocess"

    async def start(self) -> None:
        self._started = True

    async def close(self) -> None:
        for sub in self._subs.values():
            for w in sub.workers:
                w.cancel()
        for t in list(self._retry_tasks):
            t.cancel()
        tasks = [w for s in self._subs.values() for w in s.workers] + list(self._retry_tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._subs.clear()
        self._started = False

    async def publish(self, message: AgentMessage) -> None:
        wire = message.to_wire()
        self.published.append(wire)
        raw = json.dumps(wire, ensure_ascii=False)
        await self.publish_raw(message.to_agent, raw)

    async def publish_raw(self, agent_id: str, raw: str) -> None:
        """Сырой конверт (в т.ч. невалидный — для проверки DLQ)."""
        sub = self._subs.get(agent_id)
        if sub is None:
            self._pending.setdefault(agent_id, []).append(raw)
            return
        sub.queue.put_nowait((raw, 1))

    async def subscribe(self, agent_id: str, handler: Handler) -> None:
        if agent_id in self._subs:
            raise ValueError(f"agent '{agent_id}' is already subscribed")
        sub = _Subscription(agent_id=agent_id, handler=handler)
        self._subs[agent_id] = sub
        for _ in range(self.policy.concurrency):
            sub.workers.append(asyncio.create_task(self._worker(sub),
                                                   name=f"bus-worker-{agent_id}"))
        for raw in self._pending.pop(agent_id, []):
            sub.queue.put_nowait((raw, 1))

    async def _worker(self, sub: _Subscription) -> None:
        while True:
            raw, attempt = await sub.queue.get()
            try:
                await self._deliver(sub, raw, attempt)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: S110 - доставка не должна ронять воркер
                pass
            finally:
                sub.queue.task_done()

    async def _deliver(self, sub: _Subscription, raw: str, attempt: int) -> None:
        try:
            msg = AgentMessage.from_wire(json.loads(raw))
        except (ValueError, ContractValidationError) as exc:
            await self._dead(DeadLetter(subject=f"{sub.agent_id}", reason="invalid_envelope",
                                        attempts=attempt, error=str(exc)[:500], raw=raw[:4000]))
            return
        # каждая попытка — отдельная asyncio-задача: её можно отменить по task_id
        runner = asyncio.create_task(self._attempt(sub.agent_id, msg, sub.handler, attempt))
        try:
            outcome = await runner
        except asyncio.CancelledError:
            if runner.cancelled() and not self._cancel.is_cancelled(msg):
                raise
            return
        if outcome.action == "retry":
            self._schedule_retry(sub, raw, attempt + 1, self.policy.delay(attempt))
        elif outcome.action == "dead":
            await self._dead(DeadLetter(
                subject=dlq_subject_for(msg.tenant_id, msg.to_agent),
                reason=outcome.reason or "unknown", attempts=attempt, error=outcome.error,
                message=msg.model_dump(mode="json")))

    def _schedule_retry(self, sub: _Subscription, raw: str, attempt: int, delay: float) -> None:
        async def later() -> None:
            await asyncio.sleep(delay)
            if self._subs.get(sub.agent_id) is sub:
                sub.queue.put_nowait((raw, attempt))

        t = asyncio.create_task(later())
        self._retry_tasks.add(t)
        t.add_done_callback(self._retry_tasks.discard)

    async def _dead(self, letter: DeadLetter) -> None:
        self.dead_letters.append(letter)
        await self._emit_dead(letter)

    async def drain(self, timeout_s: float = 5.0) -> None:
        """Дождаться опустошения очередей (для тестов)."""
        async def wait_all() -> None:
            while True:
                await asyncio.gather(*(s.queue.join() for s in self._subs.values()))
                if not self._retry_tasks:
                    return
                await asyncio.sleep(0.01)

        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(timeout_s):
                await wait_all()


__all__ = ["InProcessBus", "subject_for"]
