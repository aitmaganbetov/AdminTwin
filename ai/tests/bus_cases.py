"""Общие сценарии шины (§7) для in-process и NATS JetStream реализаций."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from admintwin_ai.bus.base import AgentBus, DeadLetter
from admintwin_ai.contracts.messages import AgentMessage, MessageBudget, MessageScope, MessageType

from support import TENANT_A

BusFactory = Callable[[], Awaitable[AgentBus]]


def message(*, to: str = "devops-engineer", task: uuid.UUID | None = None,
            parent: uuid.UUID | None = None, deadline_s: float = 30.0,
            message_id: uuid.UUID | None = None) -> AgentMessage:
    now = datetime.now(UTC)
    root = parent or uuid.uuid4()
    kw: dict[str, Any] = {}
    if message_id is not None:
        kw["message_id"] = message_id
    return AgentMessage(
        tenant_id=uuid.UUID(TENANT_A), task_id=task or uuid.uuid4(), parent_task_id=root,
        correlation_id=root, causation_id=root, from_agent="ai-commander", to_agent=to,
        type=MessageType.TASK_REQUEST, priority="high", timestamp=now,
        scope=MessageScope(asset_ids=[], environment="production",
                           data_sensitivity_max="confidential"),
        budget=MessageBudget(max_tokens=1000, max_tool_calls=5,
                             deadline_at=now + timedelta(seconds=deadline_s)),
        payload={"objective": "Diagnose HTTP 502", "constraints": ["read_only"]}, **kw)


async def eventually(pred: Callable[[], bool], timeout_s: float = 5.0) -> None:
    async with asyncio.timeout(timeout_s):
        while not pred():
            await asyncio.sleep(0.01)


async def scenario_delivery_and_idempotency(bus: AgentBus) -> None:
    got: list[AgentMessage] = []

    async def handler(m: AgentMessage) -> None:
        got.append(m)

    await bus.subscribe("devops-engineer", handler)
    m = message()
    await bus.publish(m)
    await bus.publish(m)  # дубль публикации (at-least-once у отправителя)
    await eventually(lambda: len(got) >= 1)
    await asyncio.sleep(0.3)
    assert [x.message_id for x in got] == [m.message_id]
    assert got[0].payload["constraints"] == ["read_only"]


async def scenario_retry_then_success(bus: AgentBus) -> None:
    attempts: list[int] = []

    async def flaky(m: AgentMessage) -> None:
        attempts.append(1)
        if len(attempts) < 2:
            raise RuntimeError("transient")

    await bus.subscribe("dba-engineer", flaky)
    await bus.publish(message(to="dba-engineer"))
    await eventually(lambda: len(attempts) == 2)
    await asyncio.sleep(0.3)
    assert len(attempts) == 2  # подтверждено после успеха, повторов больше нет


async def scenario_dead_letter_after_max_deliver(bus: AgentBus,
                                                 dead: list[DeadLetter]) -> None:
    attempts: list[int] = []

    async def broken(m: AgentMessage) -> None:
        attempts.append(1)
        raise RuntimeError("permanent failure")

    await bus.subscribe("network-engineer", broken)
    m = message(to="network-engineer")
    await bus.publish(m)
    await eventually(lambda: any(d.reason == "max_deliver_exceeded" for d in dead), 10)
    assert len(attempts) == bus.policy.max_deliver
    letter = next(d for d in dead if d.reason == "max_deliver_exceeded")
    assert letter.message is not None and letter.message["message_id"] == str(m.message_id)
    assert "permanent failure" in (letter.error or "")
    assert letter.subject.endswith(f"{TENANT_A}.network-engineer")


async def scenario_deadline(bus: AgentBus, dead: list[DeadLetter]) -> None:
    started: list[int] = []

    async def slow(m: AgentMessage) -> None:
        started.append(1)
        await asyncio.sleep(10)

    await bus.subscribe("linux-admin", slow)
    await bus.publish(message(to="linux-admin", deadline_s=0.3))
    await eventually(lambda: any(d.reason == "deadline_exceeded" for d in dead), 5)
    assert started == [1]  # прервано по дедлайну, не повторялось


async def scenario_cancel_in_flight(bus: AgentBus) -> None:
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    handled: list[uuid.UUID] = []

    async def long(m: AgentMessage) -> None:
        handled.append(m.task_id)
        entered.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    await bus.subscribe("devops-engineer", long)
    root = uuid.uuid4()
    await bus.publish(message(parent=root))
    await asyncio.wait_for(entered.wait(), 5)
    await bus.cancel_task(root)
    await asyncio.wait_for(cancelled.wait(), 5)
    # новые сообщения отменённой задачи не обрабатываются
    await bus.publish(message(parent=root))
    await asyncio.sleep(0.3)
    assert len(handled) == 1
