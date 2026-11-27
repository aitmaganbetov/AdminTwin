"""Бюджеты AI (§6.6): задача, инцидент, агент, tenant.

Измерения: токены, tool calls, wall time, глубина подзадач, стоимость.
Мягкий порог (по умолчанию 80%) — предупреждение ``budget.warning`` и
downgrade профиля; жёсткий (100%) — ``budget.exhausted``, задача переходит
в ``blocked``, уведомляется Tenant Admin. Мониторинг при этом не
останавливается: бюджеты действуют только на AI-функции.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from admintwin_ai.contracts.task_state import TaskState, TaskStateMachine


class BudgetLevel(StrEnum):
    TASK = "task"
    INCIDENT = "incident"
    AGENT = "agent"
    TENANT = "tenant"


class BudgetDimension(StrEnum):
    TOKENS = "tokens"
    TOOL_CALLS = "tool_calls"
    WALL_TIME_S = "wall_time_s"
    SUBTASK_DEPTH = "subtask_depth"
    COST_USD = "cost_usd"


class BudgetState(StrEnum):
    OK = "ok"
    SOFT = "soft"  # предупреждение + downgrade
    HARD = "hard"  # blocked

    @property
    def rank(self) -> int:
        return {"ok": 0, "soft": 1, "hard": 2}[self.value]


class BudgetLimits(BaseModel):
    """None — измерение не ограничено. ``window_s`` — окно для агент/tenant
    (например токены/час агента: tokens + window_s=3600)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tokens: int | None = Field(default=None, gt=0)
    tool_calls: int | None = Field(default=None, gt=0)
    wall_time_s: float | None = Field(default=None, gt=0)
    subtask_depth: int | None = Field(default=None, gt=0)
    cost_usd: float | None = Field(default=None, gt=0)
    window_s: float | None = Field(default=None, gt=0)


class BudgetScope(BaseModel):
    model_config = ConfigDict(frozen=True)

    level: BudgetLevel
    key: str  # task_id / incident_id / agent_id / tenant_id
    limits: BudgetLimits

    @property
    def ref(self) -> str:
        return f"{self.level.value}:{self.key}"


class BudgetEvent(BaseModel):
    type: str  # "budget.warning" | "budget.exhausted" — типы сообщений §7
    scope: str
    dimension: BudgetDimension
    utilization: float
    notify: str | None = None  # "tenant_admin" для exhausted


class BudgetCheck(BaseModel):
    state: BudgetState
    utilization: dict[str, float] = Field(default_factory=dict)  # "task:x/tokens" -> 0.83
    events: list[BudgetEvent] = Field(default_factory=list)

    @property
    def exhausted(self) -> bool:
        return self.state is BudgetState.HARD


@dataclass
class _Counters:
    started_at: float
    window_start: float
    tokens: int = 0
    tool_calls: int = 0
    cost_usd: float = 0.0
    warned: set[str] = field(default_factory=set)


class BudgetLedger:
    def __init__(self, *, soft_threshold: float = 0.8, hard_threshold: float = 1.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if not 0 < soft_threshold < hard_threshold:
            raise ValueError("expected 0 < soft_threshold < hard_threshold")
        self.soft_threshold = soft_threshold
        self.hard_threshold = hard_threshold
        self._clock = clock
        self._counters: dict[str, _Counters] = {}

    def _get(self, scope: BudgetScope) -> _Counters:
        now = self._clock()
        c = self._counters.get(scope.ref)
        if c is None:
            c = _Counters(started_at=now, window_start=now)
            self._counters[scope.ref] = c
        window = scope.limits.window_s
        if window is not None and now - c.window_start >= window:
            c.window_start = now
            c.tokens = 0
            c.tool_calls = 0
            c.cost_usd = 0.0
            c.warned.clear()
        return c

    def consume(self, scopes: Iterable[BudgetScope], *, tokens: int = 0, tool_calls: int = 0,
                cost_usd: float = 0.0) -> None:
        for scope in scopes:
            c = self._get(scope)
            c.tokens += tokens
            c.tool_calls += tool_calls
            c.cost_usd += cost_usd

    def check(self, scopes: Iterable[BudgetScope], *, subtask_depth: int = 0) -> BudgetCheck:
        state = BudgetState.OK
        utilization: dict[str, float] = {}
        events: list[BudgetEvent] = []
        now = self._clock()
        for scope in scopes:
            c = self._get(scope)
            lim = scope.limits
            measures: list[tuple[BudgetDimension, float | None, float]] = [
                (BudgetDimension.TOKENS, lim.tokens, c.tokens),
                (BudgetDimension.TOOL_CALLS, lim.tool_calls, c.tool_calls),
                (BudgetDimension.COST_USD, lim.cost_usd, c.cost_usd),
                (BudgetDimension.WALL_TIME_S, lim.wall_time_s, now - c.started_at),
                (BudgetDimension.SUBTASK_DEPTH, lim.subtask_depth, subtask_depth),
            ]
            for dim, limit, used in measures:
                if limit is None:
                    continue
                ratio = used / limit
                key = f"{scope.ref}/{dim.value}"
                utilization[key] = round(ratio, 4)
                if ratio >= self.hard_threshold:
                    state = BudgetState.HARD
                    events.append(BudgetEvent(type="budget.exhausted", scope=scope.ref,
                                              dimension=dim, utilization=ratio,
                                              notify="tenant_admin"))
                elif ratio >= self.soft_threshold:
                    if state.rank < BudgetState.SOFT.rank:
                        state = BudgetState.SOFT
                    if dim.value not in c.warned:  # предупреждение — однократно
                        c.warned.add(dim.value)
                        events.append(BudgetEvent(type="budget.warning", scope=scope.ref,
                                                  dimension=dim, utilization=ratio))
        return BudgetCheck(state=state, utilization=utilization, events=events)


def block_task_on_exhaustion(task: TaskStateMachine, check: BudgetCheck, *,
                             actor: str = "ai-provider-gateway") -> bool:
    """Переводит выполняющуюся задачу в ``blocked`` при исчерпании бюджета."""
    if not check.exhausted or task.state is not TaskState.RUNNING:
        return False
    worst = next(e for e in check.events if e.type == "budget.exhausted")
    task.transition(TaskState.BLOCKED, reason=f"budget.exhausted: {worst.scope}/{worst.dimension}",
                    actor=actor)
    return True
