"""Оркестратор MVP: Commander RCA (§5.3, §21), диагностика, чат, исполнители агентов.

Поток RCA (``kind: rca``):

1. Commander от своего имени (read tools ``asset.get``, ``topology.blast_radius``,
   ``events.list``) собирает контекст; тип алерта — детерминированно
   (``orchestrator.context``); top-k похожих подтверждённых кейсов tenant.
2. ``Commander.select_agents`` — правила по ``asset.type``/``service.kind``/
   алерту (HTTP 502 → Network, DevOps, DBA); пусто → ``waiting_input``.
3. Параллельные read-only подзадачи — сообщения ``task.request`` через шину
   (§7); исполнитель агента проводит цикл через ``AIGateway`` (профиль агента,
   его ``allowed_tools``), публикует события и итог ``task.result`` со
   структурированными findings (факты, evidence IDs, исключённые причины).
4. Таблица гипотез; предложение LLM о доп. агенте подтверждается правилами
   (одна дополнительная волна).
5. При разрыве confidence лидеров < 0.2 — ОДНА разделяющая безопасная
   проверка (read tool) и пересчёт Commander-ом; если разрыв остаётся —
   «неопределённость, нужна проверка X».
6. Результат — в ядро ``POST /api/v1/incidents/{id}/rca`` (contracts §3) от
   имени сервиса ``orchestrator``; кейс — в память кейсов tenant.

Деградация (§17.2): все LLM недоступны → задача ``blocked`` с причиной;
бюджет исчерпан → ``blocked`` (``budget.exhausted``); мониторинг и другие
tenant не затрагиваются.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Callable
from concurrent.futures import Executor, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from admintwin_ai.agents.model import AgentDefinition
from admintwin_ai.agents.registry import AgentRegistry
from admintwin_ai.budgets import BudgetLedger, BudgetLevel, BudgetLimits, BudgetScope
from admintwin_ai.bus.base import AgentBus, DeadLetter
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.contracts.messages import AgentMessage, MessageType
from admintwin_ai.contracts.task_state import TaskState
from admintwin_ai.gateway import AIGateway, CallContext
from admintwin_ai.orchestrator.cases import CaseStore, RcaCase, SimilarCase
from admintwin_ai.orchestrator.commander import (
    COMMANDER_ID,
    Check,
    Commander,
    Hypothesis,
    HypothesisTable,
    IncidentContext,
    Resolution,
    Selection,
)
from admintwin_ai.orchestrator.context import alert_from_text, infer_alert_type
from admintwin_ai.orchestrator.core_client import CoreClient
from admintwin_ai.orchestrator.costs import CostTrackingSink
from admintwin_ai.orchestrator.findings import (
    Findings,
    parse_findings,
    sanitize,
)
from admintwin_ai.orchestrator.runner import (
    AgentRun,
    AgentRunner,
    CancelToken,
    Evidence,
    evidence_trailer,
    system_prompt,
)
from admintwin_ai.orchestrator.tasks import EventLog, Task, TaskManager
from admintwin_ai.providers.base import ChatMessage
from admintwin_ai.routing.router import TenantAIPolicy
from admintwin_ai.tools.invoker import ToolContext, ToolInvoker
from admintwin_ai.tools.registry import ToolKind, ToolRegistry
from admintwin_ai.tools.wrapping import wrap_untrusted

log = logging.getLogger("admintwin.orchestrator")

_NS = uuid.UUID("6b1f3b5e-7a8d-4c2e-9f10-ad0000000001")


class BudgetSettings(BaseModel):
    """Лимиты бюджетов §6.6 (переопределяются переменными окружения)."""

    task_tokens: int = 400_000
    task_cost_usd: float = 5.0
    task_wall_time_s: float = 1800.0
    incident_cost_usd: float = 20.0
    agent_tokens_per_hour: int = 2_000_000
    tenant_tokens_per_day: int = 20_000_000
    tenant_cost_per_day_usd: float = 200.0


class EngineSettings(BaseModel):
    post_rca: bool = True
    agent_max_steps: int = 8
    result_grace_s: float = 30.0
    similar_k: int = 3
    max_context_assets: int = 5
    max_parallel_agents: int = 4
    blocked_timeout_s: float = 3600.0
    worker_threads: int = 64


class Session(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    id: str
    tenant_id: str
    incident_id: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    history: list[ChatMessage] = Field(default_factory=list)
    active_task: str | None = None
    events: EventLog = Field(default_factory=EventLog, exclude=True)


class ChildResult(BaseModel):
    agent_id: str
    task_id: str
    outcome: Literal["result", "failed", "blocked", "timeout", "dead_letter"]
    findings: Findings | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    stopped: str | None = None
    reason: str | None = None
    block_kind: str | None = None  # budget | llm | human_review
    budget_scope: str | None = None
    data_class: str = "internal"
    proposed_changes: list[str] = Field(default_factory=list)
    tool_calls: int = 0


def _as_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        return uuid.uuid5(_NS, value)


def _data_class(value: str | None) -> DataClass:
    try:
        return DataClass(value or "internal")
    except ValueError:
        return DataClass.UNKNOWN


def _block_kind(stopped: str) -> str | None:
    return {"budget_exhausted": "budget", "model_unavailable": "llm",
            "human_review": "human_review"}.get(stopped)


class Orchestrator:
    def __init__(self, *, agents: AgentRegistry, tools: ToolRegistry, invoker: ToolInvoker,
                 gateway: AIGateway, ledger: BudgetLedger, costs: CostTrackingSink,
                 bus: AgentBus, cases: CaseStore | None = None, core: CoreClient | None = None,
                 tenant_policy: Callable[[str], TenantAIPolicy] | None = None,
                 settings: EngineSettings | None = None,
                 budgets: BudgetSettings | None = None,
                 executor: Executor | None = None, llm_configured: bool = True) -> None:
        self.settings = settings or EngineSettings()
        self.budgets = budgets or BudgetSettings()
        self.agents = agents
        self.tools = tools
        self.invoker = invoker
        self.gateway = gateway
        self.ledger = ledger
        self.costs = costs
        self.bus = bus
        self.cases = cases or CaseStore()
        self.core = core
        self._tenant_policy = tenant_policy or (lambda t: TenantAIPolicy(tenant_id=t))
        self._own_executor = executor is None
        self.executor = executor or ThreadPoolExecutor(
            max_workers=self.settings.worker_threads, thread_name_prefix="admintwin-ai")
        self.runner = AgentRunner(gateway, tools, invoker, ledger, self.executor)
        self.commander = Commander(agents, max_parallel_agents=self.settings.max_parallel_agents)
        self.manager = TaskManager(
            flows={"rca": self._rca_flow, "diagnose": self._diagnose_flow,
                   "chat": self._chat_flow},
            on_cancel=self._on_cancel, terminal_hook=self._on_terminal,
            blocked_timeout_s=self.settings.blocked_timeout_s)
        self.sessions: dict[str, Session] = {}
        self._inboxes: dict[str, asyncio.Queue[AgentMessage | DeadLetter]] = {}
        self._worker_tokens: dict[str, CancelToken] = {}
        self._background: set[asyncio.Task[Any]] = set()
        self.posted_rca: list[dict[str, Any]] = []
        self.llm_configured = llm_configured
        self._started = False

    # --- жизненный цикл -----------------------------------------------------------

    async def start(self) -> None:
        if self._started:
            return
        await self.bus.start()
        self.bus.on_dead_letter(self._on_dead_letter)
        for agent in self.agents.all():
            if agent.id == COMMANDER_ID or not agent.is_active:
                continue
            await self.bus.subscribe(agent.id, self._make_worker(agent.id))
        await self.bus.subscribe(COMMANDER_ID, self._commander_inbox)
        self._started = True

    async def close(self) -> None:
        await self.manager.shutdown()
        for t in list(self._background):
            t.cancel()
        if self._background:
            await asyncio.gather(*self._background, return_exceptions=True)
        await self.bus.close()
        if self.core is not None:
            await self.core.close()
        if self._own_executor and isinstance(self.executor, ThreadPoolExecutor):
            self.executor.shutdown(wait=False, cancel_futures=True)
        self._started = False

    def _spawn(self, coro: Any) -> None:
        t = asyncio.create_task(coro)
        self._background.add(t)
        t.add_done_callback(self._background.discard)

    # --- бюджеты ----------------------------------------------------------------------

    def scopes(self, root: Task, agent: AgentDefinition,
               subtask_id: str | None = None) -> list[BudgetScope]:
        b = self.budgets
        scopes = [BudgetScope(level=BudgetLevel.TASK, key=root.id, limits=BudgetLimits(
            tokens=b.task_tokens, cost_usd=b.task_cost_usd, wall_time_s=b.task_wall_time_s))]
        if subtask_id is not None:
            scopes.append(BudgetScope(level=BudgetLevel.TASK, key=subtask_id,
                                      limits=BudgetLimits(tokens=agent.budget.tokens,
                                                          tool_calls=agent.budget.tool_calls,
                                                          wall_time_s=agent.budget.wall_time_s)))
        if root.incident_id:
            scopes.append(BudgetScope(level=BudgetLevel.INCIDENT,
                                      key=f"{root.tenant_id}:{root.incident_id}",
                                      limits=BudgetLimits(cost_usd=b.incident_cost_usd)))
        scopes.append(BudgetScope(level=BudgetLevel.AGENT, key=f"{root.tenant_id}:{agent.id}",
                                  limits=BudgetLimits(tokens=b.agent_tokens_per_hour,
                                                      window_s=3600)))
        scopes.append(BudgetScope(level=BudgetLevel.TENANT, key=root.tenant_id,
                                  limits=BudgetLimits(tokens=b.tenant_tokens_per_day,
                                                      cost_usd=b.tenant_cost_per_day_usd,
                                                      window_s=86400)))
        return scopes

    def call_context(self, tenant_id: str, agent: AgentDefinition, task_id: str,
                     scopes: list[BudgetScope], depth: int = 0) -> CallContext:
        return CallContext(tenant=self._tenant_policy(tenant_id), agent_id=agent.id,
                           task_id=task_id, primary_profile=agent.model_profile,
                           secondary_profile=agent.fallback_model_profile,
                           requirements=agent.requirements, budget_scopes=scopes,
                           subtask_depth=depth)

    def _drain_costs(self, task: Task, ledger_task_id: str) -> None:
        for d in self.costs.drain(ledger_task_id):
            self.manager.add_cost(task, d.provider, d.cost_usd, d.tokens)

    # --- отмена ---------------------------------------------------------------------------

    async def _on_cancel(self, root: Task) -> None:
        await self.bus.cancel_task(_as_uuid(root.id))
        for cid in root.children:
            token = self._worker_tokens.get(cid)
            if token is not None:
                token.cancel(root.cancel.reason)

    async def _on_terminal(self, task: Task) -> None:
        if task.parent_id is not None:
            return
        if task.session_id and task.session_id in self.sessions:
            session = self.sessions[task.session_id]
            if session.active_task == task.id:
                session.active_task = None
        if task.kind == "rca" and task.incident_id:
            payload = task.result
            if payload is None or "status" not in payload:
                payload = {"task_id": task.id, "status": "failed", "hypotheses": [],
                           "conclusion": f"RCA не завершён: {task.state.value} ({task.reason})",
                           "uncertainty_check": None, "agents": list(task.agents),
                           "cost_usd": round(task.cost_usd, 6), "proposed_changes": []}
            self._spawn(self._post_rca(task, payload))
        if task.kind in ("rca", "diagnose") and task.result and task.incident_id:
            leader = (task.result.get("hypotheses") or [{}])[0]
            if task.result.get("status") == "completed" and leader.get("cause"):
                self.cases.upsert(RcaCase(
                    tenant_id=task.tenant_id, incident_id=task.incident_id,
                    cause=str(leader["cause"]), summary=str(task.result.get("conclusion", "")),
                    confirmed=False, alert_type=task.context.get("alert_type"),
                    asset_type=task.context.get("asset_type")))

    async def _post_rca(self, task: Task, payload: dict[str, Any]) -> None:
        self.posted_rca.append({"tenant_id": task.tenant_id, "incident_id": task.incident_id,
                                "payload": payload})
        if not self.settings.post_rca or self.core is None or task.incident_id is None:
            return
        res = await self.core.post_rca(task.tenant_id, task.incident_id, payload)
        log.info("rca posted", extra={"task_id": task.id, "ok": res.ok,
                                      "status_code": res.status_code})

    # --- исполнитель агента (подписчик шины) ------------------------------------------------

    def _make_worker(self, agent_id: str) -> Callable[[AgentMessage], Any]:
        async def handle(msg: AgentMessage) -> None:
            if msg.type is MessageType.TASK_REQUEST:
                await self._work(agent_id, msg)
        return handle

    def _reply(self, request: AgentMessage, type_: MessageType,
               payload: dict[str, Any]) -> AgentMessage:
        return AgentMessage(
            tenant_id=request.tenant_id, task_id=request.task_id,
            parent_task_id=request.parent_task_id, correlation_id=request.correlation_id,
            causation_id=request.message_id, from_agent=request.to_agent,
            to_agent=request.from_agent, type=type_, priority=request.priority,
            scope=request.scope, budget=request.budget, payload=payload)

    async def _work(self, agent_id: str, msg: AgentMessage) -> None:
        agent = self.agents.get(agent_id)
        x: dict[str, Any] = dict(msg.payload.get("x_admintwin") or {})
        child_id = str(msg.task_id)
        token = CancelToken()
        self._worker_tokens[child_id] = token
        outbox: asyncio.Queue[AgentMessage | None] = asyncio.Queue()

        async def pump() -> None:
            while True:
                item = await outbox.get()
                if item is None:
                    return
                await self.bus.publish(item)

        pump_task = asyncio.create_task(pump())

        def send(type_: MessageType, payload: dict[str, Any]) -> None:
            outbox.put_nowait(self._reply(msg, type_, payload))

        def emit(event: str, data: dict[str, Any]) -> None:
            mtype = {"evidence.added": MessageType.EVIDENCE_ADDED,
                     "change.proposed": MessageType.CHANGE_PROPOSED,
                     "budget.warning": MessageType.BUDGET_WARNING,
                     "budget.exhausted": MessageType.BUDGET_EXHAUSTED}.get(
                         event, MessageType.TASK_PROGRESS)
            send(mtype, {"event": event, "data": data})
            if event == "task.progress":
                for d in self.costs.drain(child_id):
                    send(MessageType.TASK_PROGRESS, {"event": "cost", "data": d.model_dump()})

        try:
            send(MessageType.TASK_ACCEPTED, {"event": "task.progress",
                                             "data": {"state": "accepted"}})
            scopes = [BudgetScope.model_validate(s) for s in x.get("budget_scopes", [])]
            tenant_id = str(msg.tenant_id)
            ctx = self.call_context(tenant_id, agent, child_id, scopes, depth=1)
            tool_ctx = ToolContext(tenant_id=tenant_id, agent=agent, task_id=child_id,
                                   incident_id=x.get("incident_id"),
                                   correlation_id=str(msg.correlation_id),
                                   data_sensitivity_max=DataClass(msg.scope.data_sensitivity_max))
            mode = str(x.get("mode", "rca"))
            run = await self.runner.run(
                agent, ctx=ctx, tool_ctx=tool_ctx, system=system_prompt(agent, mode=mode),
                user_message=str(x.get("context_text") or msg.payload.get("objective", "")),
                task_class=TaskClass.RCA, cancel=token, emit=emit,
                initial_data_class=DataClass(x.get("data_class", "internal")),
                max_steps=int(x.get("max_steps", self.settings.agent_max_steps)),
                max_tool_calls=min(agent.budget.tool_calls, msg.budget.max_tool_calls))
            for d in self.costs.drain(child_id):
                send(MessageType.TASK_PROGRESS, {"event": "cost", "data": d.model_dump()})
            send(*self._run_outcome(agent, run))
        except asyncio.CancelledError:
            token.cancel("cancelled")
            pump_task.cancel()
            raise
        except Exception as exc:
            log.exception("agent worker failed", extra={"agent": agent_id, "task_id": child_id})
            send(MessageType.TASK_FAILED, {"event": "agent.failed",
                                           "data": {"reason": f"{type(exc).__name__}"}})
        finally:
            self._worker_tokens.pop(child_id, None)
        outbox.put_nowait(None)
        await pump_task

    @staticmethod
    def _run_outcome(agent: AgentDefinition, run: AgentRun) -> tuple[MessageType, dict[str, Any]]:
        evidence = [{"evidence_id": e.evidence_id, "tool": e.tool, "summary": e.summary,
                     "call_index": i + 1, "data_class": e.data_class.value if e.data_class
                     else None} for i, e in enumerate(run.evidence)]
        base = {"stopped": run.stopped, "evidence": evidence, "tool_calls": run.tool_calls,
                "data_class": run.data_class.value, "proposed_changes": run.proposed_changes}
        kind = _block_kind(run.stopped)
        if kind is not None:
            return MessageType.TASK_BLOCKED, {"event": "agent.blocked", "data": {
                **base, "reason": run.error or run.stopped, "block_kind": kind,
                "budget_scope": run.budget_scope}}
        if run.stopped == "model_error":
            return MessageType.TASK_FAILED, {"event": "agent.failed",
                                             "data": {**base, "reason": run.error}}
        findings = parse_findings(run.final_text, agent_id=agent.id) \
            if run.stopped == "final" else None
        return MessageType.TASK_RESULT, {"event": "agent.result", "data": {
            **base, "findings": findings.model_dump(mode="json") if findings else None,
            "reason": None if findings else f"no valid findings ({run.stopped})"}}

    # --- входящие Commander -------------------------------------------------------------------

    async def _commander_inbox(self, msg: AgentMessage) -> None:
        key = str(msg.parent_task_id) if msg.parent_task_id else str(msg.task_id)
        q = self._inboxes.get(key)
        if q is not None:
            q.put_nowait(msg)

    async def _on_dead_letter(self, letter: DeadLetter) -> None:
        if not letter.message:
            return
        parent = letter.message.get("parent_task_id")
        q = self._inboxes.get(str(parent)) if parent else None
        if q is not None:
            q.put_nowait(letter)

    # --- поток RCA / диагностики ------------------------------------------------------------------

    async def _diagnose_flow(self, manager: TaskManager, task: Task) -> None:
        await self._investigate(task, post=False)

    async def _rca_flow(self, manager: TaskManager, task: Task) -> None:
        await self._investigate(task, post=True)

    async def _collect_context(self, task: Task, commander: AgentDefinition,
                               evidence: dict[str, Evidence]) -> dict[str, Any]:
        tool_ctx = ToolContext(tenant_id=task.tenant_id, agent=commander, task_id=task.id,
                               incident_id=task.incident_id, correlation_id=task.id)
        scope = task.asset_ids[: self.settings.max_context_assets]
        plan: list[tuple[str, dict[str, Any]]] = [("asset.get", {"asset_id": a}) for a in scope]
        if scope:
            plan.append(("topology.blast_radius", {"asset_id": scope[0], "depth": 2}))
            plan.extend(("events.list", {"asset_id": a, "window": "30m", "limit": 50})
                        for a in scope)
        plan = [(n, p) for n, p in plan if n in commander.allowed_tools]
        # id evidence назначаются до вызовов — детерминированно при параллельном исполнении
        eids = [f"ev-{commander.id}-{i}" for i in range(1, len(plan) + 1)]

        async def call(name: str, params: dict[str, Any], eid: str) -> Evidence | None:
            _, ev = await self.runner.single_tool(
                tool_ctx, name, params, task.cancel, evidence_id=eid,
                emit=lambda e, d: self.manager.emit(task, e, d))
            self.ledger.consume(self.scopes(task, commander), tool_calls=1)
            return ev

        found = await asyncio.gather(*(call(n, p, e) for (n, p), e in zip(plan, eids,
                                                                          strict=True)))
        assets: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        blast: list[dict[str, Any]] = []
        for (name, _), ev in zip(plan, found, strict=True):
            if ev is None or ev.data is None:
                continue
            evidence[ev.evidence_id] = ev
            if name == "asset.get":
                assets.append(ev.data)
            elif name == "topology.blast_radius":
                blast = list(ev.data.get("nodes", []))
            else:
                events.extend(ev.data.get("events", []))
        return {"assets": assets, "events": events, "blast_radius": blast,
                "context_calls": len(plan)}

    def _llm_missing(self, task: Task) -> bool:
        if self.llm_configured:
            return False
        self.manager.block(task, "llm.unavailable: LLM-провайдеры не настроены "
                                 "(ADMINTWIN_AI_CONFIG); мониторинг работает")
        return True

    async def _investigate(self, task: Task, *, post: bool) -> None:
        if self._llm_missing(task):
            return
        commander = self.agents.get(COMMANDER_ID)
        evidence: dict[str, Evidence] = {}
        ctx_data = await self._collect_context(task, commander, evidence)
        assets = ctx_data["assets"]
        first = assets[0] if assets else {}
        hint: dict[str, Any] = dict(task.context.get("hints") or {})
        alert_type, rule = infer_alert_type(hint.get("alert_type"), ctx_data["events"],
                                            task.objective)
        asset_type = hint.get("asset_type") or first.get("type")
        service_kind = hint.get("service_kind") or (first.get("tags") or {}).get("service_kind")
        task.context.update({"alert_type": alert_type, "alert_rule": rule,
                             "asset_type": asset_type, "service_kind": service_kind,
                             "context_calls": ctx_data["context_calls"]})
        similar = self.cases.similar(task.tenant_id, " ".join(filter(None, [
            alert_type, asset_type, task.objective])), k=self.settings.similar_k,
            exclude_incident=task.incident_id)
        for ev in evidence.values():
            self.manager.emit(task, "fact", {"evidence_id": ev.evidence_id, "tool": ev.tool,
                                             "statement": f"{ev.tool}: {ev.summary}"})

        def incident_ctx() -> IncidentContext:
            env = first.get("environment")
            return IncidentContext(
                tenant_id=_as_uuid(task.tenant_id),
                incident_id=_as_uuid(task.incident_id or task.id),
                alert_type=task.context.get("alert_type"), asset_type=asset_type,
                service_kind=service_kind,
                asset_ids=[_as_uuid(a) for a in task.asset_ids],
                related_asset_types=frozenset(str(n.get("type")) for n in
                                              ctx_data["blast_radius"] if n.get("type")),
                environment=env if env in ("production", "staging", "dev", "test")
                else "production",
                objective=task.objective or "Diagnose incident")

        selection = self.commander.select_agents(incident_ctx())
        while not selection.agents:
            answer = await self.manager.ask(
                task, "Не удалось детерминированно выбрать профильных агентов: уточните тип "
                      "проблемы (например http_502, disk_usage_high, container_stopped).")
            alert = alert_from_text(answer)
            if alert is None:
                self.manager.fail(task, "agent selection impossible: alert type unknown")
                return
            task.context.update({"alert_type": alert, "alert_rule": "requester.input"})
            selection = self.commander.select_agents(incident_ctx())
        self.manager.emit(task, "task.progress", {
            "event": "agents.selected", "agents": selection.agents,
            "rules": [r.model_dump() for r in selection.reasons],
            "alert_type": task.context.get("alert_type"), "alert_rule": task.context["alert_rule"]})

        context_text = self._context_text(task, evidence, ctx_data, similar)
        results = await self._dispatch_wave(task, incident_ctx(), selection, context_text,
                                            post=post)
        known: set[str] = set(evidence)
        table = HypothesisTable()
        self._merge(task, table, results, known, evidence)

        # предложение LLM о дополнительном агенте — только по правилам (одна волна)
        suggested = sorted({a for r in results if r.findings for a in r.findings.suggested_agents})
        extra: list[str] = []
        for agent_id in suggested:
            verdict = self.commander.confirm_suggestion(incident_ctx(), Selection(
                agents=[*selection.agents, *extra], reasons=[]), agent_id)
            self.manager.emit(task, "task.progress", {"event": "agent.suggestion",
                                                      **verdict.model_dump()})
            if verdict.accepted:
                extra.append(agent_id)
        if extra:
            more = await self._dispatch_wave(task, incident_ctx(),
                                             Selection(agents=extra, reasons=[]), context_text,
                                             post=post)
            self._merge(task, table, more, known, evidence)
            results.extend(more)

        usable = [r for r in results if r.outcome == "result" and r.findings is not None]
        if not usable:
            blocked = [r for r in results if r.outcome == "blocked"]
            if blocked and len(blocked) == len(results):
                kinds = {r.block_kind for r in blocked}
                if kinds == {"llm"}:
                    reason = ("llm.unavailable: все LLM-провайдеры недоступны (§17.2); "
                              "задачи агентов приостановлены, мониторинг работает")
                elif "budget" in kinds:
                    scope = next((r.budget_scope for r in blocked if r.budget_scope), "")
                    reason = f"budget.exhausted: {scope}".strip()
                else:
                    reason = "human_review: нет разрешённого провайдера для класса данных"
                self.manager.block(task, reason)
                return
            if any(r.outcome == "blocked" and r.block_kind == "budget" for r in results):
                scope = next((r.budget_scope for r in results if r.budget_scope), "")
                self.manager.block(task, f"budget.exhausted: {scope}")
                return

        resolution = table.resolve()
        adjudication: Findings | None = None
        check_used: Check | None = None
        if resolution.status == "uncertain" and resolution.next_check is not None:
            check_used = resolution.next_check
            adjudication = await self._separating_check(task, table, resolution, results,
                                                        evidence, known)
            resolution = table.resolve()
        payload = self._payload(task, table, resolution, results, evidence, adjudication,
                                check_used)
        task.result = payload
        task.hypotheses = payload["hypotheses"]
        if payload["status"] == "failed":
            self.manager.fail(task, "RCA: нет действующих гипотез с evidence")

    def _context_text(self, task: Task, evidence: dict[str, Evidence],
                      ctx_data: dict[str, Any], similar: list[SimilarCase]) -> str:
        assets = [{k: a.get(k) for k in ("asset_id", "name", "type", "environment",
                                         "criticality", "tags") if k in a}
                  for a in ctx_data["assets"]]
        body = json.dumps({
            "alert_type": task.context.get("alert_type"),
            "assets": assets, "blast_radius": ctx_data["blast_radius"][:50],
            "events": ctx_data["events"][:30],
            "similar_confirmed_cases": [s.model_dump() for s in similar],
        }, ensure_ascii=False, sort_keys=True, default=str)
        dc = DataClass.max_of(DataClass.INTERNAL, *[e.data_class for e in evidence.values()
                                                    if e.data_class is not None])
        wrapped = wrap_untrusted("incident.context", dc, body)
        refs = ", ".join(f"{e.evidence_id} ({e.tool})" for e in evidence.values()) or "нет"
        return (f"Задача: {task.objective or 'диагностика инцидента'}\n"
                f"Инцидент: {task.incident_id or '-'}; тип алерта: "
                f"{task.context.get('alert_type') or 'не определён'}; ограничения: read_only.\n"
                f"Контекст, собранный Commander (данные CMDB/телеметрии, недоверенные):\n"
                f"{wrapped}\n"
                f"Evidence контекста: {refs}.\n"
                f"Проведи диагностику своими инструментами и верни JSON findings.")

    async def _dispatch_wave(self, task: Task, ictx: IncidentContext, selection: Selection,
                             context_text: str, *, post: bool) -> list[ChildResult]:
        commander = self.agents.get(COMMANDER_ID)
        root_uuid = _as_uuid(task.id)
        messages = self.commander.dispatch(
            ictx, selection, parent_task_id=root_uuid, correlation_id=root_uuid,
            causation_id=root_uuid, context_summary_ref=f"evidence://task/{task.id}/context")
        inbox: asyncio.Queue[AgentMessage | DeadLetter] = asyncio.Queue()
        self._inboxes[task.id] = inbox
        children: dict[str, Task] = {}
        try:
            for m in messages:
                agent = self.agents.get(m.to_agent)
                child = self.manager.create(tenant_id=task.tenant_id, kind="subtask",
                                            objective=task.objective, parent=task,
                                            agent_id=agent.id, incident_id=task.incident_id,
                                            asset_ids=task.asset_ids, task_id=str(m.task_id))
                if agent.id not in task.agents:
                    task.agents.append(agent.id)
                children[child.id] = child
                self.manager.transition(child, TaskState.QUEUED, reason="dispatched via bus",
                                        actor=commander.id)
                payload = dict(m.payload)
                payload["x_admintwin"] = {
                    "root_task_id": task.id, "incident_id": task.incident_id,
                    "context_text": context_text, "mode": "rca" if post else "diagnose",
                    "budget_scopes": [s.model_dump(mode="json")
                                      for s in self.scopes(task, agent, child.id)],
                    "max_steps": self.settings.agent_max_steps,
                }
                await self.bus.publish(m.model_copy(update={"payload": payload}))
            deadline = max((self.agents.get(c.agent_id or "").budget.wall_time_s
                            for c in children.values()), default=60.0) \
                + self.settings.result_grace_s
            results: dict[str, ChildResult] = {}
            try:
                async with asyncio.timeout(deadline):
                    while len(results) < len(children):
                        item = await inbox.get()
                        self._handle_reply(task, children, results, item)
            except TimeoutError:
                for cid, child in children.items():
                    if cid in results:
                        continue
                    await self.bus.cancel_task(_as_uuid(cid))
                    if child.state is TaskState.RUNNING:
                        self.manager.transition(child, TaskState.TIMED_OUT,
                                                reason="agent deadline exceeded",
                                                actor=commander.id)
                    elif not child.terminal:
                        self.manager.transition(child, TaskState.CANCELLED,
                                                reason="agent did not start before deadline",
                                                actor=commander.id)
                    results[cid] = ChildResult(agent_id=child.agent_id or "", task_id=cid,
                                               outcome="timeout", reason="deadline exceeded")
            return [results[cid] for cid in children]
        finally:
            self._inboxes.pop(task.id, None)

    def _handle_reply(self, task: Task, children: dict[str, Task],
                      results: dict[str, ChildResult], item: AgentMessage | DeadLetter) -> None:
        if isinstance(item, DeadLetter):
            msg_task = str((item.message or {}).get("task_id", ""))
            child = children.get(msg_task)
            if child is None or msg_task in results:
                return
            self.manager.emit(child, "task.failed", {"reason": f"dead letter: {item.reason}"})
            if not child.terminal:
                if child.state is TaskState.QUEUED:
                    self.manager.transition(child, TaskState.RUNNING, reason="delivery attempted",
                                            actor="bus")
                self.manager.transition(child, TaskState.FAILED, reason=f"DLQ: {item.reason}",
                                        actor="bus")
            results[msg_task] = ChildResult(agent_id=child.agent_id or "", task_id=msg_task,
                                            outcome="dead_letter", reason=item.reason)
            return
        child = children.get(str(item.task_id))
        if child is None:
            return
        event = str(item.payload.get("event", ""))
        data = dict(item.payload.get("data") or {})
        agent_id = child.agent_id or item.from_agent
        if item.type is MessageType.TASK_ACCEPTED:
            if child.state is TaskState.QUEUED:
                self.manager.transition(child, TaskState.RUNNING, reason="task.accepted",
                                        actor=agent_id)
            return
        if event == "cost":
            self.manager.add_cost(child, str(data.get("provider")),
                                  float(data.get("cost_usd", 0.0)), int(data.get("tokens", 0)))
            return
        if item.type in (MessageType.TASK_RESULT, MessageType.TASK_FAILED,
                         MessageType.TASK_BLOCKED):
            if str(item.task_id) in results:
                return  # повторная доставка
            if child.state is TaskState.QUEUED:
                self.manager.transition(child, TaskState.RUNNING, reason="result received",
                                        actor=agent_id)
            findings = Findings.model_validate(data["findings"]) if data.get("findings") \
                else None
            common: dict[str, Any] = {"agent_id": agent_id, "task_id": child.id,
                      "evidence": list(data.get("evidence", [])),
                      "stopped": data.get("stopped"), "reason": data.get("reason"),
                      "data_class": str(data.get("data_class", "internal")),
                      "proposed_changes": list(data.get("proposed_changes", [])),
                      "tool_calls": int(data.get("tool_calls", 0))}
            if item.type is MessageType.TASK_RESULT:
                results[child.id] = ChildResult.model_validate(
                    {**common, "outcome": "result", "findings": findings})
                self.manager.transition(child, TaskState.COMPLETED,
                                        reason="findings received" if findings else
                                        str(data.get("reason") or "no findings"),
                                        actor=agent_id)
            elif item.type is MessageType.TASK_BLOCKED:
                results[child.id] = ChildResult.model_validate(
                    {**common, "outcome": "blocked", "block_kind": data.get("block_kind"),
                     "budget_scope": data.get("budget_scope")})
                self.manager.transition(child, TaskState.BLOCKED,
                                        reason=str(data.get("reason") or "blocked"),
                                        actor=agent_id)
            else:
                results[child.id] = ChildResult.model_validate({**common, "outcome": "failed"})
                self.manager.transition(child, TaskState.FAILED,
                                        reason=str(data.get("reason") or "agent failed"),
                                        actor=agent_id)
            return
        self.manager.emit(child, event or "task.progress", {**data, "agent": agent_id})

    def _merge(self, task: Task, table: HypothesisTable, results: list[ChildResult],
               known: set[str], evidence: dict[str, Evidence]) -> None:
        read_tools = {t.name for t in self.tools.all() if t.kind is ToolKind.READ}
        index: dict[str, Any] = task.context.setdefault("evidence_index", {})
        for eid, ev in evidence.items():
            index.setdefault(eid, {"agent": ev.agent_id, "tool": ev.tool,
                                   "call_index": int(eid.rsplit("-", 1)[-1])
                                   if eid.rsplit("-", 1)[-1].isdigit() else 1})
        for r in results:
            for e in r.evidence:
                eid = str(e.get("evidence_id"))
                known.add(eid)
                index[eid] = {"agent": r.agent_id, "tool": e.get("tool"),
                              "call_index": e.get("call_index")}
                if eid not in evidence:
                    evidence[eid] = Evidence(evidence_id=eid, agent_id=r.agent_id,
                                             tool=str(e.get("tool")),
                                             summary=str(e.get("summary", "")),
                                             params={"call_index": e.get("call_index")})
        for r in results:
            if r.findings is None:
                continue
            clean = sanitize(r.findings, known_evidence=known, read_tools=read_tools)
            r.findings = clean
            for f in clean.facts:
                table.add_fact(f.evidence_id, f.statement)
                fact = {"agent": r.agent_id, "evidence_id": f.evidence_id,
                        "statement": f.statement}
                task.facts.append(fact)
                self.manager.emit(task, "fact", fact)
            for h in clean.hypotheses:
                merged = table.add(h)
                self.manager.emit(task, "hypothesis", {
                    "agent": r.agent_id, "cause": merged.cause, "confidence": merged.confidence,
                    "supporting": merged.supporting, "refuting": merged.refuting})
            for cause in clean.excluded_causes:
                if table.get(cause) is None:
                    table.add(Hypothesis(cause=cause, confidence=0.0, proposed_by=[r.agent_id]))

    async def _separating_check(self, task: Task, table: HypothesisTable,
                                resolution: Resolution, results: list[ChildResult],
                                evidence: dict[str, Evidence], known: set[str]
                                ) -> Findings | None:
        check = resolution.next_check
        assert check is not None
        leader, runner = resolution.leader, resolution.runner_up
        owners = [*(leader.proposed_by if leader else []), *(runner.proposed_by if runner else []),
                  *[r.agent_id for r in results], COMMANDER_ID]
        executor_agent: AgentDefinition | None = None
        for aid in owners:
            if aid in self.agents and check.tool in self.agents.get(aid).allowed_tools:
                executor_agent = self.agents.get(aid)
                break
        self.manager.emit(task, "task.progress", {
            "event": "separating_check", "tool": check.tool, "description": check.description,
            "gap": resolution.gap, "executor": executor_agent.id if executor_agent else None})
        if executor_agent is None:
            return None
        tool_ctx = ToolContext(tenant_id=task.tenant_id, agent=executor_agent, task_id=task.id,
                               incident_id=task.incident_id, correlation_id=task.id)
        eid = "ev-check-1"
        result, ev = await self.runner.single_tool(
            tool_ctx, check.tool, dict(check.params), task.cancel, evidence_id=eid,
            emit=lambda e, d: self.manager.emit(task, e, d))
        self.ledger.consume(self.scopes(task, executor_agent), tool_calls=1)
        if ev is None:
            self.manager.emit(task, "fact", {"evidence_id": None, "statement":
                                             f"разделяющая проверка не выполнена: {result.reason}"})
            return None
        evidence[eid] = ev
        known.add(eid)
        task.context["check_evidence"] = eid
        max_calls = max((r.tool_calls for r in results), default=0)
        task.context.setdefault("evidence_index", {})[eid] = {
            "agent": executor_agent.id, "tool": check.tool, "call_index": max_calls + 1}
        self.manager.emit(task, "fact", {"evidence_id": eid, "tool": check.tool,
                                         "statement": f"{check.tool}: {ev.summary}"})
        commander = self.agents.get(COMMANDER_ID)
        dc = DataClass.max_of(ev.data_class or DataClass.INTERNAL,
                              *[_data_class(r.data_class) for r in results])
        summary = wrap_untrusted("agents.summary", dc,
                                 json.dumps(table.summary(), ensure_ascii=False, sort_keys=True))
        message = (f"mode: adjudicate\n"
                   f"Структурированный summary агентов (JSON):\n{summary}\n"
                   f"Разделяющая проверка: {check.tool} "
                   f"{json.dumps(check.params, ensure_ascii=False, sort_keys=True)} — "
                   f"{check.description}\n"
                   f"Результат проверки:\n{result.content}\n{evidence_trailer(eid)}\n"
                   f"Пересчитай confidence гипотез "
                   f"'{leader.cause if leader else ''}' и '{runner.cause if runner else ''}' "
                   f"и верни JSON findings.")
        scopes = self.scopes(task, commander)
        run = await self.runner.run(
            commander, ctx=self.call_context(task.tenant_id, commander, task.id, scopes),
            tool_ctx=ToolContext(tenant_id=task.tenant_id, agent=commander, task_id=task.id),
            system=system_prompt(commander, mode="adjudicate"), user_message=message,
            task_class=TaskClass.RCA, cancel=task.cancel,
            emit=lambda e, d: self.manager.emit(task, e, d), initial_data_class=dc,
            # JSON findings проверяется схемой при разборе (parse_findings), а не
            # response_format провайдера: strict-режимы провайдеров несовместимы между собой
            max_steps=1, use_tools=False)
        self._drain_costs(task, task.id)
        if run.stopped != "final":
            self.manager.emit(task, "task.progress", {"event": "adjudication.skipped",
                                                      "reason": run.error or run.stopped})
            return None
        parsed = parse_findings(run.final_text, agent_id=commander.id)
        if parsed is None:
            return None
        read_tools = {t.name for t in self.tools.all() if t.kind is ToolKind.READ}
        clean = sanitize(parsed, known_evidence=known, read_tools=read_tools)
        for h in clean.hypotheses:
            updated = table.update(h.cause, confidence=h.confidence, supporting=h.supporting,
                                   refuting=h.refuting)
            if updated is not None:
                self.manager.emit(task, "hypothesis", {
                    "agent": commander.id, "cause": updated.cause,
                    "confidence": updated.confidence, "supporting": updated.supporting,
                    "refuting": updated.refuting, "after_check": eid})
        for f in clean.facts:
            table.add_fact(f.evidence_id, f.statement)
        return clean

    def _payload(self, task: Task, table: HypothesisTable, resolution: Resolution,
                 results: list[ChildResult], evidence: dict[str, Evidence],
                 adjudication: Findings | None, check_used: Check | None) -> dict[str, Any]:
        facts = {eid: s for eid, s in table.facts}

        def ref(eid: str) -> dict[str, str]:
            ev = evidence.get(eid)
            fact = facts.get(eid) or (f"{ev.tool}: {ev.summary}" if ev else eid)
            return {"fact": fact[:1000], "evidence_id": eid}

        excluded = {h.cause for h in table.excluded()}
        ordered = [h for h in table.ranked() if h.cause not in excluded] + \
            [h for h in table.ranked() if h.cause in excluded]
        hypotheses = [{
            "cause": h.cause, "confidence": round(h.confidence, 4),
            "supporting": [ref(e) for e in h.supporting],
            "refuting": [ref(e) for e in h.refuting],
            "next_checks": [f"{c.tool}: {c.description}" for c in h.checks],
        } for h in ordered]
        status = {"confident": "completed", "uncertain": "uncertain",
                  "insufficient_evidence": "uncertain",
                  # Ни одна гипотеза не подтверждена — это результат анализа («нужен дополнительный
                  # сбор»), а не сбой процесса: failed остаётся для таймаутов и ошибок.
                  "no_hypotheses": "uncertain"}[resolution.status]
        conclusion = resolution.message
        if adjudication is not None and adjudication.conclusion:
            conclusion = f"{conclusion}. Commander: {adjudication.conclusion}"
        if check_used is not None:
            conclusion += (f" (разделяющая проверка выполнена: {check_used.tool})"
                           if "check_evidence" in task.context else
                           f" (разделяющая проверка {check_used.tool} не выполнена)")
        missing = [r.agent_id for r in results if r.outcome != "result"]
        if missing:
            conclusion += f"; без итогов агентов: {', '.join(sorted(set(missing)))}"
        uncertainty = None
        if status == "uncertain" and resolution.next_check is not None:
            uncertainty = f"{resolution.next_check.tool}: {resolution.next_check.description}"
        proposed = sorted({c for r in results for c in r.proposed_changes})
        return {
            "task_id": task.id, "status": status, "hypotheses": hypotheses,
            "conclusion": conclusion[:4000], "uncertainty_check": uncertainty,
            "agents": list(task.agents), "cost_usd": round(task.cost_usd, 6),
            "proposed_changes": proposed,
        }

    # --- чат ------------------------------------------------------------------------------------

    def create_session(self, tenant_id: str, incident_id: str | None) -> Session:
        session = Session(id=str(uuid.uuid4()), tenant_id=tenant_id, incident_id=incident_id)
        self.sessions[session.id] = session
        self.manager.session_logs[session.id] = session.events
        return session

    def session_message(self, session: Session, text: str, *,
                        requested_by: str | None) -> Task:
        session.events.append("task.progress", {"event": "user.message", "text": text})
        if session.active_task is not None:
            active = self.manager.get(session.active_task)
            if active.state is TaskState.WAITING_INPUT:
                self.manager.provide_input(active, text)
                return active
            if not active.terminal and active.state is not TaskState.BLOCKED:
                raise ValueError("session has a running task; wait for it or cancel it")
        task = self.manager.create(tenant_id=session.tenant_id, kind="chat", objective=text,
                                   incident_id=session.incident_id, requested_by=requested_by,
                                   session_id=session.id)
        session.active_task = task.id
        self.manager.start(task)
        return task

    async def _chat_flow(self, manager: TaskManager, task: Task) -> None:
        if self._llm_missing(task):
            return
        commander = self.agents.get(COMMANDER_ID)
        session = self.sessions.get(task.session_id or "")
        history = list(session.history) if session else []
        text = task.objective
        for _ in range(3):
            scopes = self.scopes(task, commander)
            run = await self.runner.run(
                commander, ctx=self.call_context(task.tenant_id, commander, task.id, scopes),
                tool_ctx=ToolContext(tenant_id=task.tenant_id, agent=commander,
                                     task_id=task.id, incident_id=task.incident_id),
                system=system_prompt(commander, mode="chat"), user_message=text,
                history=history, task_class=TaskClass.MULTI_STEP, cancel=task.cancel,
                emit=lambda e, d: manager.emit(task, e, d),
                max_steps=self.settings.agent_max_steps)
            self._drain_costs(task, task.id)
            kind = _block_kind(run.stopped)
            if kind == "llm":
                manager.block(task, "llm.unavailable: все LLM-провайдеры недоступны (§17.2)")
                return
            if kind == "budget":
                manager.block(task, f"budget.exhausted: {run.budget_scope or ''}".strip())
                return
            if kind == "human_review":
                manager.block(task, "human_review: нет разрешённого провайдера для класса данных")
                return
            if run.stopped not in ("final", "refusal"):
                manager.fail(task, f"chat agent stopped: {run.stopped} {run.error or ''}".strip())
                return
            final = run.final_text.strip()
            history = [*history, ChatMessage(role="user", content=text)]
            if final.startswith("NEED_INPUT:"):
                question = final.removeprefix("NEED_INPUT:").strip() or "Уточните запрос"
                history.append(ChatMessage(role="assistant", content=final))
                text = await manager.ask(task, question)
                continue
            history.append(ChatMessage(role="assistant", content=final))
            if session is not None:
                session.history = history[-40:]
            task.result = {"text": final,
                           "evidence": [e.evidence_id for e in run.evidence],
                           "tool_calls": run.tool_calls}
            return
        manager.fail(task, "too many clarification rounds")
