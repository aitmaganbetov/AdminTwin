"""Межагентная шина in-process (§7): at-least-once, идемпотентность, DLQ, дедлайны, отмена."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import pytest

from admintwin_ai.bus import DeliveryPolicy, InProcessBus, build_bus
from admintwin_ai.bus.base import DeadLetter
from admintwin_ai.contracts.messages import AgentMessage
from admintwin_ai.errors import ContractValidationError

from bus_cases import (
    eventually,
    message,
    scenario_cancel_in_flight,
    scenario_dead_letter_after_max_deliver,
    scenario_deadline,
    scenario_delivery_and_idempotency,
    scenario_retry_then_success,
)


@pytest.fixture
async def bus() -> AsyncIterator[InProcessBus]:
    b = InProcessBus(DeliveryPolicy(max_deliver=3, backoff_s=(0.01, 0.02), concurrency=4))
    await b.start()
    yield b
    await b.close()


@pytest.fixture
def dead(bus: InProcessBus) -> list[DeadLetter]:
    letters: list[DeadLetter] = []

    async def collect(d: DeadLetter) -> None:
        letters.append(d)

    bus.on_dead_letter(collect)
    return letters


def test_build_bus_selects_by_nats_url() -> None:
    assert build_bus(None).kind == "inprocess"
    assert build_bus("nats://127.0.0.1:4222").kind == "nats"


async def test_delivery_and_idempotency(bus: InProcessBus) -> None:
    await scenario_delivery_and_idempotency(bus)


async def test_retry_then_success(bus: InProcessBus) -> None:
    await scenario_retry_then_success(bus)


async def test_dead_letter_after_max_deliver(bus: InProcessBus, dead: list[DeadLetter]) -> None:
    await scenario_dead_letter_after_max_deliver(bus, dead)
    assert bus.dead_letters


async def test_deadline_exceeded_goes_to_dlq(bus: InProcessBus, dead: list[DeadLetter]) -> None:
    await scenario_deadline(bus, dead)


async def test_expired_message_is_not_delivered(bus: InProcessBus,
                                                dead: list[DeadLetter]) -> None:
    got: list[AgentMessage] = []

    async def h(m: AgentMessage) -> None:
        got.append(m)

    await bus.subscribe("devops-engineer", h)
    await bus.publish(message(deadline_s=-1))
    await eventually(lambda: bool(dead))
    assert got == [] and dead[0].reason == "deadline_exceeded"


async def test_cancel_in_flight(bus: InProcessBus) -> None:
    await scenario_cancel_in_flight(bus)


async def test_invalid_envelope_goes_to_dlq(bus: InProcessBus, dead: list[DeadLetter]) -> None:
    got: list[AgentMessage] = []

    async def h(m: AgentMessage) -> None:
        got.append(m)

    await bus.subscribe("devops-engineer", h)
    wire = message().to_wire()
    wire["scope"]["environment"] = "development"  # вне перечисления §8.3
    await bus.publish_raw("devops-engineer", json.dumps(wire))
    await bus.publish_raw("devops-engineer", "{not json")
    await eventually(lambda: len(dead) == 2)
    assert got == [] and {d.reason for d in dead} == {"invalid_envelope"}


async def test_publish_validates_contract(bus: InProcessBus) -> None:
    m = message()
    bad = m.model_copy(update={"payload": {"objective": "x"}})  # task.request без constraints
    with pytest.raises(ContractValidationError):
        await bus.publish(bad)


async def test_messages_before_subscription_are_kept(bus: InProcessBus) -> None:
    got: list[AgentMessage] = []
    await bus.publish(message(to="linux-admin"))

    async def h(m: AgentMessage) -> None:
        got.append(m)

    await bus.subscribe("linux-admin", h)
    await eventually(lambda: len(got) == 1)


async def test_bounded_concurrency(bus: InProcessBus) -> None:
    running = 0
    peak = 0
    done = 0

    async def h(m: AgentMessage) -> None:
        nonlocal running, peak, done
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.05)
        running -= 1
        done += 1

    await bus.subscribe("devops-engineer", h)
    for _ in range(12):
        await bus.publish(message())
    await eventually(lambda: done == 12)
    assert peak <= bus.policy.concurrency


async def test_duplicate_subscription_rejected(bus: InProcessBus) -> None:
    async def h(m: AgentMessage) -> None:
        return None

    await bus.subscribe("devops-engineer", h)
    with pytest.raises(ValueError, match="already subscribed"):
        await bus.subscribe("devops-engineer", h)
