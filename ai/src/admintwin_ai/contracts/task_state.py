"""State machine задачи агента (§7).

Таблица переходов загружается из ``ai/contracts/task-state-machine.json``
(state machine как данные, C.10). Каждый переход журналируется с причиной,
актором, временем, correlation_id и ссылкой на evidence; недопустимый
переход бросает ``InvalidTransitionError``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from functools import lru_cache

from pydantic import BaseModel

from admintwin_ai.errors import InvalidTransitionError
from admintwin_ai.resources import load_json


class TaskState(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    WAITING_APPROVAL = "waiting_approval"
    WAITING_INPUT = "waiting_input"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class _Spec(BaseModel):
    initial: TaskState
    terminal: frozenset[TaskState]
    transitions: dict[TaskState, frozenset[TaskState]]
    notify: dict[tuple[TaskState, TaskState], str]


@lru_cache(maxsize=1)
def _spec() -> _Spec:
    raw = load_json("contracts", "task-state-machine.json")
    transitions = {TaskState(k): frozenset(TaskState(v) for v in vs)
                   for k, vs in raw["transitions"].items()}
    missing = set(TaskState) - set(transitions)
    if missing:
        raise InvalidTransitionError(f"state machine data lacks states: {sorted(missing)}")
    notify = {(TaskState(n["from"]), TaskState(n["to"])): str(n["notify"])
              for n in raw.get("notify_on", [])}
    return _Spec(initial=TaskState(raw["initial"]),
                 terminal=frozenset(TaskState(s) for s in raw["terminal"]),
                 transitions=transitions, notify=notify)


def allowed_transitions(state: TaskState) -> frozenset[TaskState]:
    return _spec().transitions[state]


def is_terminal(state: TaskState) -> bool:
    return state in _spec().terminal


class TransitionRecord(BaseModel):
    task_id: str
    from_state: TaskState
    to_state: TaskState
    reason: str
    actor: str
    at: datetime
    correlation_id: str | None = None
    evidence_ref: str | None = None
    notify: str | None = None


class TaskStateMachine:
    def __init__(self, task_id: str, *, correlation_id: str | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.task_id = task_id
        self.correlation_id = correlation_id
        self._clock = clock or (lambda: datetime.now(UTC))
        self._state = _spec().initial
        self.journal: list[TransitionRecord] = []

    @property
    def state(self) -> TaskState:
        return self._state

    @property
    def terminal(self) -> bool:
        return is_terminal(self._state)

    def can(self, target: TaskState) -> bool:
        return target in allowed_transitions(self._state)

    def transition(self, target: TaskState, *, reason: str, actor: str,
                   evidence_ref: str | None = None) -> TransitionRecord:
        if not reason or not reason.strip():
            raise InvalidTransitionError("every transition requires a non-empty reason")
        if not actor:
            raise InvalidTransitionError("every transition requires an actor")
        if not self.can(target):
            raise InvalidTransitionError(
                f"task {self.task_id}: {self._state.value} -> {target.value} is not allowed"
            )
        record = TransitionRecord(
            task_id=self.task_id, from_state=self._state, to_state=target, reason=reason.strip(),
            actor=actor, at=self._clock(), correlation_id=self.correlation_id,
            evidence_ref=evidence_ref, notify=_spec().notify.get((self._state, target)),
        )
        self._state = target
        self.journal.append(record)
        return record
