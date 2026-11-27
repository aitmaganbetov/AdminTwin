"""TaskManager: state machine, журнал событий (SSE), ретенция, отмена без корутины."""

from __future__ import annotations

import asyncio

import pytest

from admintwin_ai.contracts.task_state import TaskState
from admintwin_ai.errors import InvalidTransitionError
from admintwin_ai.orchestrator.tasks import EventLog, Task, TaskManager

from support import TENANT_A


async def test_event_log_follow_replays_and_waits() -> None:
    log = EventLog()
    for i in range(3):
        log.append("task.progress", {"i": i})
    got: list[int] = []

    async def reader() -> None:
        async for ev in log.follow(1, heartbeat_s=0.05):
            if ev is not None:
                got.append(ev.id)

    t = asyncio.create_task(reader())
    await asyncio.sleep(0.02)
    log.append("task.result", {"done": True})
    log.close()
    await asyncio.wait_for(t, 2)
    assert got == [2, 3, 4]
    assert "id: 4\nevent: task.result\ndata: " in log.since(3)[0].sse()


async def test_flow_completion_and_invalid_transition() -> None:
    async def flow(m: TaskManager, t: Task) -> None:
        t.result = {"ok": True}

    m = TaskManager(flows={"diagnose": flow})
    t = m.create(tenant_id=TENANT_A, kind="diagnose")
    m.start(t)
    await asyncio.wait_for(t.finished.wait(), 2)
    assert t.state is TaskState.COMPLETED
    with pytest.raises(InvalidTransitionError):
        m.transition(t, TaskState.RUNNING, reason="again", actor="x")
    assert [r.to_state for r in m.transitions][-1] is TaskState.COMPLETED


async def test_flow_exception_fails_task_without_crashing() -> None:
    async def boom(m: TaskManager, t: Task) -> None:
        raise RuntimeError("bug")

    m = TaskManager(flows={"rca": boom})
    t = m.create(tenant_id=TENANT_A, kind="rca")
    m.start(t)
    await asyncio.wait_for(t.finished.wait(), 2)
    assert t.state is TaskState.FAILED and t.reason == "internal error: RuntimeError"


async def test_cancel_blocked_task_without_running_coroutine() -> None:
    async def blocks(m: TaskManager, t: Task) -> None:
        m.block(t, "budget.exhausted: tenant:x/tokens")

    m = TaskManager(flows={"rca": blocks})
    t = m.create(tenant_id=TENANT_A, kind="rca")
    m.start(t)
    await asyncio.sleep(0.05)
    assert t.state is TaskState.BLOCKED
    assert await m.cancel(t, reason="operator", actor="user:1")
    assert t.state is TaskState.CANCELLED


async def test_retention_evicts_oldest_terminal_roots() -> None:
    async def flow(m: TaskManager, t: Task) -> None:
        return None

    m = TaskManager(flows={"diagnose": flow}, max_tasks=2)
    first = m.create(tenant_id=TENANT_A, kind="diagnose")
    m.start(first)
    await asyncio.wait_for(first.finished.wait(), 2)
    second = m.create(tenant_id=TENANT_A, kind="diagnose")
    m.create(tenant_id=TENANT_A, kind="diagnose")
    ids = {t.id for t in m.list_tasks(TENANT_A)}
    assert first.id not in ids and second.id in ids
