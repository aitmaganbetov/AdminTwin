"""Задачи оркестратора: дерево задач, state machine, журнал событий (SSE), отмена.

* Состояния и переходы — ``TaskStateMachine`` (``contracts/task-state-machine.json``);
  каждый переход журналируется с причиной и актором и публикуется событием.
* Журнал событий корневой задачи — источник SSE (``/v1/tasks/{id}/events``):
  монотонные id, повтор с ``Last-Event-ID``, ограниченный объём.
* Отмена/kill switch: флаг ``CancelToken`` (виден рабочим потокам) +
  ``asyncio.Task.cancel()`` корневой корутины + отмена сообщений задачи в шине;
  ``kill()`` ждёт подтверждения завершения и измеряет время (§11.7: < 5 с).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from admintwin_ai.contracts.task_state import TaskState, TaskStateMachine, TransitionRecord
from admintwin_ai.orchestrator.runner import CancelToken, TaskCancelledError

log = logging.getLogger("admintwin.tasks")

TaskKind = Literal["rca", "chat", "diagnose", "subtask", "check"]

# состояние → тип события §7 для SSE
_STATE_EVENT: dict[TaskState, str] = {
    TaskState.RUNNING: "task.progress",
    TaskState.COMPLETED: "task.result",
    TaskState.FAILED: "task.failed",
    TaskState.BLOCKED: "task.blocked",
    TaskState.WAITING_INPUT: "task.input_required",
    TaskState.WAITING_APPROVAL: "approval.requested",
    TaskState.CANCELLED: "task.cancelled",
    TaskState.TIMED_OUT: "task.failed",
    TaskState.QUEUED: "task.progress",
}


@dataclass
class Event:
    id: int
    type: str
    data: dict[str, Any]
    at: str

    def sse(self) -> str:
        import json

        payload = json.dumps(self.data, ensure_ascii=False, default=str)
        lines = "".join(f"data: {line}\n" for line in payload.split("\n"))
        return f"id: {self.id}\nevent: {self.type}\n{lines}\n"


class EventLog:
    """Журнал событий с повтором по Last-Event-ID и ожиданием новых событий."""

    def __init__(self, capacity: int = 20_000) -> None:
        self._events: deque[Event] = deque(maxlen=capacity)
        self._next = 1
        self._changed = asyncio.Event()
        self.closed = False

    def append(self, type_: str, data: dict[str, Any]) -> Event:
        ev = Event(id=self._next, type=type_, data=data, at=datetime.now(UTC).isoformat())
        self._next += 1
        self._events.append(ev)
        self._wake()
        return ev

    def close(self) -> None:
        self.closed = True
        self._wake()

    def _wake(self) -> None:
        changed, self._changed = self._changed, asyncio.Event()
        changed.set()

    @property
    def last_id(self) -> int:
        return self._next - 1

    def since(self, last_id: int) -> list[Event]:
        return [e for e in self._events if e.id > last_id]

    async def follow(self, last_id: int = 0, *, heartbeat_s: float = 15.0
                     ) -> AsyncIterator[Event | None]:
        """События после ``last_id``; ``None`` — heartbeat. Завершается после закрытия."""
        cursor = last_id
        while True:
            waiter = self._changed
            batch = self.since(cursor)
            for ev in batch:
                cursor = ev.id
                yield ev
            if batch:
                continue
            if self.closed:
                return
            try:
                await asyncio.wait_for(waiter.wait(), timeout=heartbeat_s)
            except TimeoutError:
                yield None


class TaskView(BaseModel):
    task_id: str
    kind: str
    tenant_id: str
    status: str
    parent_task_id: str | None = None
    agent_id: str | None = None
    incident_id: str | None = None
    session_id: str | None = None
    objective: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)
    requested_by: str | None = None
    created_at: str
    updated_at: str
    reason: str | None = None
    question: str | None = None
    agents: list[str] = Field(default_factory=list)
    facts: list[dict[str, Any]] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    cost_usd: float = 0.0
    cost_by_provider: dict[str, float] = Field(default_factory=dict)
    tokens: int = 0
    result: dict[str, Any] | None = None
    transitions: list[dict[str, Any]] = Field(default_factory=list)
    children: list[TaskView] = Field(default_factory=list)


@dataclass
class Task:
    id: str
    tenant_id: str
    kind: TaskKind
    objective: str = ""
    incident_id: str | None = None
    asset_ids: list[str] = field(default_factory=list)
    requested_by: str | None = None
    parent_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    sm: TaskStateMachine = field(init=False)
    events: EventLog | None = None  # только у корневых задач
    children: list[str] = field(default_factory=list)
    facts: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    cost_usd: float = 0.0
    cost_by_provider: dict[str, float] = field(default_factory=dict)
    tokens: int = 0
    result: dict[str, Any] | None = None
    reason: str | None = None
    question: str | None = None
    cancel: CancelToken = field(default_factory=CancelToken)
    runner: asyncio.Task[None] | None = None
    inputs: asyncio.Queue[str] = field(default_factory=asyncio.Queue)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.sm = TaskStateMachine(self.id, correlation_id=self.incident_id or self.id)

    @property
    def state(self) -> TaskState:
        return self.sm.state

    @property
    def terminal(self) -> bool:
        return self.sm.terminal


Flow = Callable[["TaskManager", Task], Awaitable[None]]


class TaskNotFoundError(KeyError):
    pass


class TaskRejectedError(Exception):
    """Новая задача отклонена (kill switch)."""


class KillReport(BaseModel):
    scope: str
    cancelled: list[str]
    confirmed: list[str]
    cancellation_pending: list[str]
    elapsed_ms: float


class TaskManager:
    def __init__(self, *, flows: dict[str, Flow] | None = None,
                 on_cancel: Callable[[Task], Awaitable[None]] | None = None,
                 blocked_timeout_s: float = 3600.0,
                 terminal_hook: Callable[[Task], Awaitable[None]] | None = None) -> None:
        self.flows: dict[str, Flow] = dict(flows or {})
        self._tasks: dict[str, Task] = {}
        self._on_cancel = on_cancel
        self._terminal_hook = terminal_hook
        self.blocked_timeout_s = blocked_timeout_s
        self._timers: dict[str, asyncio.Task[None]] = {}
        self._killed_tenants: set[str] = set()
        self._platform_killed = False
        self.transitions: list[TransitionRecord] = []
        #: журналы чат-сессий: события задач сессии дублируются в журнал сессии
        self.session_logs: dict[str, EventLog] = {}

    # --- реестр ------------------------------------------------------------------

    def get(self, task_id: str, tenant_id: str | None = None) -> Task:
        task = self._tasks.get(task_id)
        if task is None or (tenant_id is not None and task.tenant_id != tenant_id):
            raise TaskNotFoundError(task_id)  # чужой tenant неотличим от отсутствующей задачи
        return task

    def list_tasks(self, tenant_id: str | None = None, *,
                   roots_only: bool = True) -> list[Task]:
        return [t for t in self._tasks.values()
                if (tenant_id is None or t.tenant_id == tenant_id)
                and (not roots_only or t.parent_id is None)]

    def root_of(self, task: Task) -> Task:
        while task.parent_id is not None:
            task = self._tasks[task.parent_id]
        return task

    def kill_active(self, tenant_id: str) -> bool:
        return self._platform_killed or tenant_id in self._killed_tenants

    # --- создание и запуск ----------------------------------------------------------

    def create(self, *, tenant_id: str, kind: TaskKind, objective: str = "",
               incident_id: str | None = None, asset_ids: list[str] | None = None,
               requested_by: str | None = None, parent: Task | None = None,
               agent_id: str | None = None, session_id: str | None = None,
               context: dict[str, Any] | None = None, task_id: str | None = None) -> Task:
        if self.kill_active(tenant_id):
            raise TaskRejectedError("kill switch active: new AI tasks are rejected")
        task = Task(id=task_id or str(uuid.uuid4()), tenant_id=tenant_id, kind=kind,
                    objective=objective, incident_id=incident_id,
                    asset_ids=list(asset_ids or []), requested_by=requested_by,
                    parent_id=parent.id if parent else None, agent_id=agent_id,
                    session_id=session_id, context=dict(context or {}))
        if parent is None:
            task.events = EventLog()
        else:
            parent.children.append(task.id)
        self._tasks[task.id] = task
        self.emit(task, "task.progress", {"state": TaskState.CREATED.value, "kind": kind,
                                          "agent": agent_id})
        return task

    def start(self, task: Task, *, reason: str = "accepted by orchestrator") -> None:
        flow = self.flows.get(task.kind)
        if flow is None:
            raise ValueError(f"no flow for task kind '{task.kind}'")
        self.transition(task, TaskState.QUEUED, reason=reason, actor="orchestrator")
        task.runner = asyncio.create_task(self._run(flow, task), name=f"task-{task.id}")

    async def _run(self, flow: Flow, task: Task) -> None:
        try:
            self.transition(task, TaskState.RUNNING, reason="worker picked up the task",
                            actor="orchestrator")
            await flow(self, task)
            if not task.terminal and task.state is TaskState.RUNNING:
                self.transition(task, TaskState.COMPLETED, reason="flow finished",
                                actor="orchestrator")
        except (asyncio.CancelledError, TaskCancelledError):
            self._finish_cancelled(task)
        except Exception as exc:  # задача не должна ронять сервис
            log.exception("task flow failed", extra={"task_id": task.id})
            if not task.terminal:
                self.fail(task, f"internal error: {type(exc).__name__}")
        finally:
            if task.terminal:
                await self._after_terminal(task)

    def _finish_cancelled(self, task: Task) -> None:
        reason = task.cancel.reason or "cancelled"
        for cid in list(task.children):
            child = self._tasks.get(cid)
            if child is not None and not child.terminal:
                child.cancel.cancel(reason)
                self.transition(child, TaskState.CANCELLED, reason=reason, actor="orchestrator")
        if not task.terminal:
            self.transition(task, TaskState.CANCELLED, reason=reason, actor="orchestrator")

    async def _after_terminal(self, task: Task) -> None:
        timer = self._timers.pop(task.id, None)
        if timer is not None:
            timer.cancel()
        task.finished.set()
        if task.events is not None:
            task.events.close()
        if self._terminal_hook is not None:
            try:
                await self._terminal_hook(task)
            except Exception:
                log.exception("terminal hook failed", extra={"task_id": task.id})

    # --- переходы и события ---------------------------------------------------------

    def emit(self, task: Task, type_: str, data: dict[str, Any]) -> None:
        root = self.root_of(task)
        if root.events is None:
            return
        payload = {"task_id": task.id, **data}
        if task.agent_id and "agent" not in payload:
            payload["agent"] = task.agent_id
        root.events.append(type_, payload)
        if root.session_id is not None and root.session_id in self.session_logs:
            self.session_logs[root.session_id].append(type_, payload)

    def transition(self, task: Task, target: TaskState, *, reason: str, actor: str,
                   evidence_ref: str | None = None) -> TransitionRecord:
        rec = task.sm.transition(target, reason=reason, actor=actor, evidence_ref=evidence_ref)
        self.transitions.append(rec)
        task.updated_at = rec.at.isoformat()
        task.reason = reason
        log.info("task transition", extra={"task_id": task.id, "from": rec.from_state.value,
                                           "to": rec.to_state.value, "reason": reason,
                                           "actor": actor})
        data: dict[str, Any] = {"state": target.value, "from": rec.from_state.value,
                                "reason": reason, "actor": actor}
        if rec.notify:
            data["notify"] = rec.notify
        if target is TaskState.COMPLETED and task.result is not None:
            data["result"] = task.result
        if target is TaskState.WAITING_INPUT and task.question:
            data["question"] = task.question
        self.emit(task, _STATE_EVENT.get(target, "task.progress"), data)
        if target is TaskState.BLOCKED and task.parent_id is None:
            self._arm_blocked_timer(task)
        return rec

    def fail(self, task: Task, reason: str) -> None:
        if not task.terminal:
            self.transition(task, TaskState.FAILED, reason=reason, actor="orchestrator")

    def block(self, task: Task, reason: str) -> None:
        if task.state is TaskState.RUNNING:
            self.transition(task, TaskState.BLOCKED, reason=reason, actor="orchestrator")

    def _arm_blocked_timer(self, task: Task) -> None:
        async def expire() -> None:
            await asyncio.sleep(self.blocked_timeout_s)
            if task.state is TaskState.BLOCKED:
                self.transition(task, TaskState.TIMED_OUT,
                                reason=f"blocked longer than {self.blocked_timeout_s:.0f}s "
                                       f"({task.reason})", actor="orchestrator")
                await self._after_terminal(task)

        old = self._timers.pop(task.id, None)
        if old is not None:
            old.cancel()
        self._timers[task.id] = asyncio.create_task(expire())

    # --- waiting_input ------------------------------------------------------------------

    async def ask(self, task: Task, question: str) -> str:
        """running → waiting_input; ждёт ``provide_input``; → running."""
        task.question = question
        self.transition(task, TaskState.WAITING_INPUT, reason="input required from requester",
                        actor="orchestrator")
        text = await task.inputs.get()
        task.question = None
        self.transition(task, TaskState.RUNNING, reason="input received", actor="requester")
        return text

    def provide_input(self, task: Task, text: str) -> None:
        if task.state is not TaskState.WAITING_INPUT:
            raise ValueError(f"task is '{task.state.value}', not waiting_input")
        self.emit(task, "task.progress", {"event": "input", "text_len": len(text)})
        task.inputs.put_nowait(text)

    # --- стоимость ----------------------------------------------------------------------

    def add_cost(self, task: Task, provider: str, cost_usd: float, tokens: int) -> None:
        for t in (task, self.root_of(task)) if task.parent_id else (task,):
            t.cost_usd = round(t.cost_usd + cost_usd, 8)
            t.cost_by_provider[provider] = round(t.cost_by_provider.get(provider, 0.0)
                                                 + cost_usd, 8)
            t.tokens += tokens
        root = self.root_of(task)
        self.emit(task, "cost", {"provider": provider, "cost_usd": round(cost_usd, 8),
                                 "tokens": tokens, "total_usd": root.cost_usd,
                                 "by_provider": dict(root.cost_by_provider)})

    # --- отмена и kill switch -----------------------------------------------------------

    async def cancel(self, task: Task, *, reason: str, actor: str,
                     wait_s: float = 4.5) -> bool:
        """Отмена задачи и её подзадач; True — завершение подтверждено."""
        root = task
        if root.terminal:
            return True
        root.cancel.cancel(f"{reason} (by {actor})")
        for cid in root.children:
            child = self._tasks.get(cid)
            if child is not None:
                child.cancel.cancel(reason)
        if self._on_cancel is not None:
            with contextlib.suppress(Exception):
                await self._on_cancel(root)
        if root.runner is not None and not root.runner.done():
            root.runner.cancel()
        elif not root.terminal:
            # задача без корутины (blocked после завершения flow, waiting) — отменяем сами
            self._finish_cancelled(root)
            await self._after_terminal(root)
        try:
            async with asyncio.timeout(wait_s):
                await root.finished.wait()
        except TimeoutError:
            return False
        return True

    async def kill(self, tenant_id: str | None, *, platform: bool, actor: str = "kill-switch",
                   reason: str = "kill switch", wait_s: float = 4.5) -> KillReport:
        started = time.monotonic()
        if platform:
            self._platform_killed = True
            scope = "platform"
        elif tenant_id is not None:
            self._killed_tenants.add(tenant_id)
            scope = f"tenant:{tenant_id}"
        else:
            raise ValueError("tenant_id or platform=true is required")
        targets = [t for t in self._tasks.values()
                   if t.parent_id is None and not t.terminal
                   and (platform or t.tenant_id == tenant_id)]
        results = await asyncio.gather(*(self.cancel(t, reason=reason, actor=actor,
                                                     wait_s=wait_s) for t in targets))
        confirmed = [t.id for t, ok in zip(targets, results, strict=True) if ok]
        pending = [t.id for t, ok in zip(targets, results, strict=True) if not ok]
        return KillReport(scope=scope, cancelled=[t.id for t in targets], confirmed=confirmed,
                          cancellation_pending=pending,
                          elapsed_ms=round((time.monotonic() - started) * 1000, 3))

    def release_kill(self, tenant_id: str | None, *, platform: bool) -> None:
        if platform:
            self._platform_killed = False
        elif tenant_id is not None:
            self._killed_tenants.discard(tenant_id)

    # --- представление ----------------------------------------------------------------

    def view(self, task: Task, *, tree: bool = True) -> TaskView:
        return TaskView(
            task_id=task.id, kind=task.kind, tenant_id=task.tenant_id, status=task.state.value,
            parent_task_id=task.parent_id, agent_id=task.agent_id, incident_id=task.incident_id,
            session_id=task.session_id, objective=task.objective,
            scope={"asset_ids": task.asset_ids}, requested_by=task.requested_by,
            created_at=task.created_at, updated_at=task.updated_at, reason=task.reason,
            question=task.question, agents=list(task.agents), facts=list(task.facts),
            hypotheses=list(task.hypotheses), cost_usd=task.cost_usd,
            cost_by_provider=dict(task.cost_by_provider), tokens=task.tokens,
            result=task.result,
            transitions=[{"from": r.from_state.value, "to": r.to_state.value, "reason": r.reason,
                          "actor": r.actor, "at": r.at.isoformat()} for r in task.sm.journal],
            children=[self.view(self._tasks[c]) for c in task.children if c in self._tasks]
            if tree else [],
        )

    async def shutdown(self) -> None:
        for t in list(self._timers.values()):
            t.cancel()
        runners = [t.runner for t in self._tasks.values() if t.runner and not t.runner.done()]
        for r in runners:
            r.cancel()
        if runners:
            await asyncio.gather(*runners, return_exceptions=True)
