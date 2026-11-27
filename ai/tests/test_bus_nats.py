"""Шина NATS JetStream (§7) против настоящего nats-server.

Запускается, если доступен бинарник ``nats-server`` (``PATH`` или
``ADMINTWIN_TEST_NATS_SERVER``), например::

    GOBIN=$PWD/.bin go install github.com/nats-io/nats-server/v2@v2.10.22
    ADMINTWIN_TEST_NATS_SERVER=$PWD/.bin/nats-server pytest tests/test_bus_nats.py

Иначе тесты пропускаются (skip), остальной набор остаётся офлайн.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from admintwin_ai.bus.base import DeadLetter, DeliveryPolicy
from admintwin_ai.contracts.messages import AgentMessage

from bus_cases import (
    eventually,
    message,
    scenario_cancel_in_flight,
    scenario_dead_letter_after_max_deliver,
    scenario_deadline,
    scenario_delivery_and_idempotency,
    scenario_retry_then_success,
)

NATS_BIN = os.environ.get("ADMINTWIN_TEST_NATS_SERVER") or shutil.which("nats-server")
pytestmark = pytest.mark.skipif(not NATS_BIN or not Path(NATS_BIN).exists(),
                                reason="nats-server binary not available")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def nats_url(tmp_path: Path) -> Iterator[str]:
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603 - тестовый nats-server на loopback
        [str(NATS_BIN), "-js", "-a", "127.0.0.1", "-p", str(port), "-sd", str(tmp_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(200):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            import time
            time.sleep(0.02)
        yield f"nats://127.0.0.1:{port}"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
async def bus(nats_url: str) -> AsyncIterator[object]:
    from admintwin_ai.bus.nats_bus import NatsBus

    b = NatsBus(nats_url, policy=DeliveryPolicy(max_deliver=3, backoff_s=(0.05, 0.1),
                                                concurrency=4, ack_wait_s=2.0))
    await b.start()
    yield b
    await b.close()


@pytest.fixture
def dead(bus: object) -> list[DeadLetter]:
    letters: list[DeadLetter] = []

    async def collect(d: DeadLetter) -> None:
        letters.append(d)

    bus.on_dead_letter(collect)  # type: ignore[attr-defined]
    return letters


async def test_nats_delivery_and_idempotency(bus: object) -> None:
    await scenario_delivery_and_idempotency(bus)  # type: ignore[arg-type]


async def test_nats_retry_then_success(bus: object) -> None:
    await scenario_retry_then_success(bus)  # type: ignore[arg-type]


async def test_nats_dead_letter_subject(bus: object, dead: list[DeadLetter]) -> None:
    from_dlq: list[DeadLetter] = []

    async def reader(d: DeadLetter) -> None:
        from_dlq.append(d)

    await bus.subscribe_dlq(reader)  # type: ignore[attr-defined]
    await scenario_dead_letter_after_max_deliver(bus, dead)  # type: ignore[arg-type]
    # письмо реально лежит в JetStream в субъекте admintwin.dlq.<tenant>.<agent>
    await eventually(lambda: bool(from_dlq), 5)
    assert from_dlq[0].reason == "max_deliver_exceeded"


async def test_nats_deadline(bus: object, dead: list[DeadLetter]) -> None:
    await scenario_deadline(bus, dead)  # type: ignore[arg-type]


async def test_nats_cancel_in_flight(bus: object) -> None:
    await scenario_cancel_in_flight(bus)  # type: ignore[arg-type]


async def test_nats_redelivery_survives_consumer_restart(nats_url: str) -> None:
    """At-least-once: сообщение без ack доставляется заново новому экземпляру."""
    from admintwin_ai.bus.nats_bus import NatsBus

    policy = DeliveryPolicy(max_deliver=5, backoff_s=(0.05,), concurrency=2, ack_wait_s=1.0)
    first = NatsBus(nats_url, policy=policy)
    await first.start()
    entered = asyncio.Event()

    async def crash(m: AgentMessage) -> None:
        entered.set()
        await asyncio.sleep(30)  # «падение» без подтверждения

    await first.subscribe("devops-engineer", crash)
    msg = message()
    await first.publish(msg)
    await asyncio.wait_for(entered.wait(), 5)
    await first.close()

    second = NatsBus(nats_url, policy=policy)
    await second.start()
    got: list[uuid.UUID] = []

    async def ok(m: AgentMessage) -> None:
        got.append(m.message_id)

    await second.subscribe("devops-engineer", ok)
    try:
        await eventually(lambda: bool(got), 10)
        assert got[0] == msg.message_id
    finally:
        await second.close()


async def test_orchestrator_rca_over_nats(nats_url: str) -> None:
    from admintwin_ai.bus.nats_bus import NatsBus
    from admintwin_ai.contracts.task_state import TaskState

    from support import TENANT_A
    from svc import golden, make_runtime, scope_of, wait_for

    case = golden("http502-upstream-oom-002")
    rt, _core = make_runtime(case=case, bus=NatsBus(nats_url))
    orch = rt.orchestrator
    await orch.start()
    try:
        task = orch.manager.create(tenant_id=TENANT_A, kind="rca", incident_id="INC-NATS",
                                   objective="HTTP 502", asset_ids=scope_of(case))
        orch.manager.start(task)
        await wait_for(task, [TaskState.COMPLETED, TaskState.FAILED, TaskState.BLOCKED], 30)
        assert task.state is TaskState.COMPLETED, task.reason
        assert task.result is not None
        assert task.result["hypotheses"][0]["cause"] == "upstream_container_oom"
        assert sorted(task.agents) == ["dba-engineer", "devops-engineer", "network-engineer"]
    finally:
        await orch.close()
