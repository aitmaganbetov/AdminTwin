"""Бюджеты (§6.6): уровни, пороги, blocked при исчерпании."""

from __future__ import annotations

import pytest

from admintwin_ai.budgets import (
    BudgetDimension,
    BudgetLedger,
    BudgetLevel,
    BudgetLimits,
    BudgetScope,
    BudgetState,
    block_task_on_exhaustion,
)
from admintwin_ai.contracts import TaskState, TaskStateMachine


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _scopes() -> list[BudgetScope]:
    return [
        BudgetScope(level=BudgetLevel.TASK, key="task-1",
                    limits=BudgetLimits(tokens=1000, tool_calls=10, wall_time_s=60,
                                        subtask_depth=2)),
        BudgetScope(level=BudgetLevel.INCIDENT, key="inc-1", limits=BudgetLimits(tokens=5000)),
        BudgetScope(level=BudgetLevel.AGENT, key="linux-admin",
                    limits=BudgetLimits(tokens=2000, window_s=3600)),
        BudgetScope(level=BudgetLevel.TENANT, key="t1",
                    limits=BudgetLimits(tokens=100_000, cost_usd=10.0, window_s=86400)),
    ]


def test_ok_soft_hard_by_tokens() -> None:
    ledger = BudgetLedger(clock=Clock())
    scopes = _scopes()
    assert ledger.check(scopes).state is BudgetState.OK
    ledger.consume(scopes, tokens=800)
    soft = ledger.check(scopes)
    assert soft.state is BudgetState.SOFT
    assert [e.type for e in soft.events] == ["budget.warning"]
    assert soft.utilization["task:task-1/tokens"] == 0.8
    # предупреждение не повторяется
    assert ledger.check(scopes).events == []
    ledger.consume(scopes, tokens=200)
    hard = ledger.check(scopes)
    assert hard.state is BudgetState.HARD and hard.exhausted
    exhausted = [e for e in hard.events if e.type == "budget.exhausted"]
    assert exhausted[0].scope == "task:task-1" and exhausted[0].notify == "tenant_admin"


@pytest.mark.parametrize(
    ("kwargs", "dimension"),
    [
        ({"tool_calls": 10}, BudgetDimension.TOOL_CALLS),
        ({"cost_usd": 10.0}, BudgetDimension.COST_USD),
    ],
)
def test_other_dimensions_exhaust(kwargs: dict[str, float], dimension: BudgetDimension) -> None:
    ledger = BudgetLedger(clock=Clock())
    scopes = _scopes()
    ledger.consume(scopes, **kwargs)  # type: ignore[arg-type]
    check = ledger.check(scopes)
    assert check.exhausted
    assert any(e.dimension is dimension for e in check.events)


def test_wall_time_and_subtask_depth() -> None:
    clock = Clock()
    ledger = BudgetLedger(clock=clock)
    scopes = _scopes()
    ledger.check(scopes)  # старт задачи
    clock.t = 50
    assert ledger.check(scopes).state is BudgetState.SOFT
    clock.t = 61
    assert ledger.check(scopes).exhausted
    fresh = BudgetLedger(clock=Clock())
    assert fresh.check(scopes, subtask_depth=2).exhausted
    assert fresh.check(scopes, subtask_depth=1).state is BudgetState.OK


def test_agent_window_resets() -> None:
    clock = Clock()
    ledger = BudgetLedger(clock=clock)
    agent = [BudgetScope(level=BudgetLevel.AGENT, key="a",
                         limits=BudgetLimits(tokens=100, window_s=3600))]
    ledger.consume(agent, tokens=100)
    assert ledger.check(agent).exhausted
    clock.t = 3600
    assert ledger.check(agent).state is BudgetState.OK


def test_exhaustion_blocks_running_task_with_reason() -> None:
    ledger = BudgetLedger(clock=Clock())
    scopes = _scopes()
    task = TaskStateMachine("task-1")
    task.transition(TaskState.QUEUED, reason="accepted", actor="ai-commander")
    task.transition(TaskState.RUNNING, reason="started", actor="linux-admin")
    ledger.consume(scopes, tokens=1000)
    assert block_task_on_exhaustion(task, ledger.check(scopes))
    assert task.state is TaskState.BLOCKED
    assert task.journal[-1].reason.startswith("budget.exhausted: task:task-1/tokens")
    # повторно — без перехода
    assert not block_task_on_exhaustion(task, ledger.check(scopes))


def test_invalid_thresholds() -> None:
    with pytest.raises(ValueError, match="soft_threshold"):
        BudgetLedger(soft_threshold=1.0, hard_threshold=1.0)
