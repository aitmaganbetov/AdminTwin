"""Асинхронный цикл агента для сервиса оркестратора.

То же, что ``run_agent``, но:

* каждый блокирующий шаг (вызов LLM через ``AIGateway``, вызов инструмента
  через ``ToolInvoker``) выполняется в пуле потоков, а цикл ждёт его через
  ``await`` — отмена asyncio-задачи (kill switch, cancel) прерывает ожидание
  немедленно, не дожидаясь ответа провайдера/ядра (§11.7: < 5 с);
* кооперативная отмена: ``CancelToken`` проверяется перед каждым шагом и
  в рабочем потоке непосредственно перед вызовом инструмента — отменённая
  задача не начнёт новый вызов (в т.ч. ``change.propose``);
* у каждого успешного вызова инструмента — ``evidence_id``; строка с ним
  добавляется ПОСЛЕ обёртки недоверенных данных (её пишет оркестратор);
* причина остановки различает исчерпание бюджета, недоступность LLM и
  human review (§17.2), а события (tool_call, cost, budget.*) уходят в
  ``emit``.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Callable
from concurrent.futures import Executor
from functools import lru_cache
from typing import Any, Literal

from pydantic import BaseModel, Field

from admintwin_ai.agents.model import AgentDefinition
from admintwin_ai.budgets import BudgetCheck, BudgetLedger
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.gateway import AIGateway, CallContext, GatewayResponse, GatewayStatus
from admintwin_ai.providers.base import ChatMessage, CompletionRequest, ToolCall
from admintwin_ai.resources import data_path
from admintwin_ai.tools.invoker import ToolContext, ToolInvoker, ToolResult
from admintwin_ai.tools.registry import ToolKind, ToolRegistry

Emit = Callable[[str, dict[str, Any]], None]

AgentStop = Literal["final", "max_steps", "tool_call_budget", "model_unavailable",
                    "budget_exhausted", "human_review", "model_error", "refusal"]

EVIDENCE_TRAILER = "[AdminTwin evidence_id={eid}]"


class TaskCancelledError(Exception):
    """Кооперативная отмена (kill switch / cancel)."""


class CancelToken:
    """Флаг отмены, видимый и из asyncio, и из рабочих потоков."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self.reason = ""

    def cancel(self, reason: str) -> None:
        if not self._event.is_set():
            self.reason = reason
            self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise TaskCancelledError(self.reason or "cancelled")


class Evidence(BaseModel):
    evidence_id: str
    agent_id: str
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    data_class: DataClass | None = None
    summary: str = ""
    data: dict[str, Any] | None = None  # маскированные данные (секреты удалены Tool Layer)
    suspected_injection: bool = False


class AgentRun(BaseModel):
    agent_id: str
    stopped: AgentStop
    final_text: str = ""
    steps: int = 0
    data_class: DataClass = DataClass.INTERNAL
    evidence: list[Evidence] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    messages: list[ChatMessage] = Field(default_factory=list)
    proposed_changes: list[str] = Field(default_factory=list)
    tool_calls: int = 0
    error: str | None = None
    budget_scope: str | None = None  # область исчерпанного бюджета


@lru_cache(maxsize=32)
def _prompt_file(name: str) -> str:
    path = data_path("agents", "prompts", f"{name}.md")
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def system_prompt(agent: AgentDefinition, *, mode: str, extra: str = "") -> str:
    """Версионированный промпт агента (``agents/prompts/<prompt_version>.md``) + общие правила."""
    header = (f"AdminTwin agent_id: {agent.id}; mode: {mode}; "
              f"prompt_version: {agent.prompt_version}")
    body = _prompt_file(agent.prompt_version) or f"# {agent.name}"
    parts = [header, body, _prompt_file("_common")]
    if extra:
        parts.append(extra)
    return "\n\n".join(p for p in parts if p)


def evidence_trailer(evidence_id: str) -> str:
    return EVIDENCE_TRAILER.format(eid=evidence_id)


def strip_trailer(content: str) -> str:
    """Содержимое tool-сообщения без строки evidence (для проверки обёртки)."""
    head, sep, tail = content.rpartition("\n")
    if sep and tail.startswith("[AdminTwin evidence_id="):
        return head
    return content


def _summary(data: dict[str, Any] | None, limit: int = 240) -> str:
    if data is None:
        return ""
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    return text if len(text) <= limit else text[:limit] + "…"


class AgentRunner:
    def __init__(self, gateway: AIGateway, tools: ToolRegistry, invoker: ToolInvoker,
                 ledger: BudgetLedger, executor: Executor) -> None:
        self.gateway = gateway
        self.tools = tools
        self.invoker = invoker
        self.ledger = ledger
        self.executor = executor

    async def _in_thread(self, fn: Callable[[], Any]) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, fn)

    # --- один вызов модели ---------------------------------------------------------

    async def call_model(self, ctx: CallContext, request: CompletionRequest, *,
                         data_class: DataClass, task_class: TaskClass,
                         cancel: CancelToken) -> GatewayResponse:
        cancel.check()

        def work() -> GatewayResponse:
            return self.gateway.complete(ctx, request, data_class=data_class,
                                         task_class=task_class)

        resp: GatewayResponse = await self._in_thread(work)
        cancel.check()
        return resp

    # --- один вызов инструмента ----------------------------------------------------

    async def call_tool(self, tool_ctx: ToolContext, call: ToolCall,
                        cancel: CancelToken) -> ToolResult:
        cancel.check()

        def work() -> ToolResult:
            # последняя кооперативная проверка в рабочем потоке: отменённая задача
            # не начинает новый вызов (в т.ч. change.propose)
            cancel.check()
            return self.invoker.invoke_call(tool_ctx, call)

        result: ToolResult = await self._in_thread(work)
        return result

    # --- цикл агента ---------------------------------------------------------------------

    async def run(self, agent: AgentDefinition, *, ctx: CallContext, tool_ctx: ToolContext,
                  system: str, user_message: str, task_class: TaskClass,
                  cancel: CancelToken, emit: Emit, evidence_prefix: str | None = None,
                  history: list[ChatMessage] | None = None,
                  initial_data_class: DataClass = DataClass.INTERNAL, max_steps: int = 8,
                  max_tool_calls: int | None = None, use_tools: bool = True,
                  response_schema: dict[str, Any] | None = None,
                  max_tokens: int = 4096) -> AgentRun:
        specs = self.tools.specs_for(agent) if use_tools else []
        messages = [*(history or []), ChatMessage(role="user", content=user_message)]
        run = AgentRun(agent_id=agent.id, stopped="max_steps", data_class=initial_data_class,
                       messages=messages)
        budget_calls = max_tool_calls if max_tool_calls is not None else agent.budget.tool_calls
        prefix = evidence_prefix or f"ev-{agent.id}"
        for step in range(1, max_steps + 1):
            run.steps = step
            request = CompletionRequest(system=system, messages=list(messages), tools=specs,
                                        max_tokens=max_tokens, prompt_version=agent.prompt_version,
                                        response_schema=response_schema if not specs else None)
            resp = await self.call_model(ctx, request, data_class=run.data_class,
                                         task_class=task_class, cancel=cancel)
            self._emit_budget(resp.budget, emit, agent.id)
            if resp.status is not GatewayStatus.OK or resp.result is None:
                run.stopped, run.error = _stop_reason(resp)
                run.budget_scope = _exhausted_scope(resp.budget)
                return run
            completion = resp.result
            emit("task.progress", {"agent": agent.id, "step": step,
                                   "provider": resp.served_by.provider_id if resp.served_by
                                   else None,
                                   "profile": resp.served_by.profile_id if resp.served_by
                                   else None,
                                   "tool_calls_requested": len(completion.tool_calls)})
            messages.append(ChatMessage(role="assistant", content=completion.text,
                                        tool_calls=completion.tool_calls))
            if completion.finish_reason == "refusal":
                run.stopped, run.final_text = "refusal", completion.text
                return run
            if not completion.tool_calls:
                run.stopped, run.final_text = "final", completion.text
                return run
            for call in completion.tool_calls:
                if run.tool_calls >= budget_calls:
                    run.stopped = "tool_call_budget"
                    return run
                result = await self.call_tool(tool_ctx, call, cancel)
                run.tool_calls += 1
                self.ledger.consume(ctx.budget_scopes, tool_calls=1)
                run.tool_results.append(result)
                content = result.content
                evidence_id: str | None = None
                if result.status == "ok":
                    evidence_id = f"{prefix}-{len(run.evidence) + 1}"
                    run.evidence.append(Evidence(
                        evidence_id=evidence_id, agent_id=agent.id, tool=result.tool,
                        params=dict(call.arguments), data_class=result.data_class,
                        summary=_summary(result.data), data=result.data,
                        suspected_injection=result.suspected_injection))
                    content = f"{content}\n{evidence_trailer(evidence_id)}"
                    if result.data_class is not None:
                        run.data_class = DataClass.max_of(run.data_class, result.data_class)
                    if result.kind == ToolKind.PROPOSE.value and result.data:
                        change_id = str(result.data.get("change_id", ""))
                        if change_id:
                            run.proposed_changes.append(change_id)
                            emit("change.proposed", {"agent": agent.id, "change_id": change_id,
                                                     "status": result.data.get("status"),
                                                     "runbook_id": result.data.get("runbook_id")})
                emit("tool_call", {"agent": agent.id, "tool": result.tool, "status": result.status,
                                   "reason": result.reason, "evidence_id": evidence_id,
                                   "data_class": result.data_class.value if result.data_class
                                   else None, "suspected_injection": result.suspected_injection})
                if evidence_id is not None:
                    emit("evidence.added", {"agent": agent.id, "evidence_id": evidence_id,
                                            "tool": result.tool,
                                            "summary": run.evidence[-1].summary})
                messages.append(ChatMessage(role="tool", content=content, tool_call_id=call.id,
                                            is_error=result.status != "ok"))
                check = self.ledger.check(ctx.budget_scopes, subtask_depth=ctx.subtask_depth)
                if check.exhausted:
                    self._emit_budget(check, emit, agent.id)
                    run.stopped, run.error = "budget_exhausted", "budget.exhausted"
                    run.budget_scope = _exhausted_scope(check)
                    return run
        return run

    @staticmethod
    def _emit_budget(check: BudgetCheck, emit: Emit, agent_id: str) -> None:
        for ev in check.events:
            emit(ev.type, {"agent": agent_id, "scope": ev.scope, "dimension": ev.dimension.value,
                           "utilization": round(ev.utilization, 4), "notify": ev.notify})

    async def single_tool(self, tool_ctx: ToolContext, name: str, params: dict[str, Any],
                          cancel: CancelToken, *, evidence_id: str,
                          emit: Emit) -> tuple[ToolResult, Evidence | None]:
        """Детерминированный вызов инструмента оркестратором (контекст, разделяющая проверка)."""
        result = await self.call_tool(tool_ctx, ToolCall(id=evidence_id, name=name,
                                                         arguments=params), cancel)
        ev: Evidence | None = None
        if result.status == "ok":
            ev = Evidence(evidence_id=evidence_id, agent_id=tool_ctx.agent.id, tool=name,
                          params=params, data_class=result.data_class,
                          summary=_summary(result.data), data=result.data,
                          suspected_injection=result.suspected_injection)
        emit("tool_call", {"agent": tool_ctx.agent.id, "tool": name, "status": result.status,
                           "reason": result.reason,
                           "evidence_id": evidence_id if ev else None,
                           "data_class": result.data_class.value if result.data_class else None,
                           "suspected_injection": result.suspected_injection})
        if ev is not None:
            emit("evidence.added", {"agent": tool_ctx.agent.id, "evidence_id": evidence_id,
                                    "tool": name, "summary": ev.summary})
        return result, ev


def _exhausted_scope(check: BudgetCheck) -> str | None:
    for ev in check.events:
        if ev.type == "budget.exhausted":
            return f"{ev.scope}/{ev.dimension.value}"
    return None


def _stop_reason(resp: GatewayResponse) -> tuple[AgentStop, str]:
    error = resp.error or ""
    if resp.status is GatewayStatus.HUMAN_REVIEW:
        return "human_review", error or "no_permitted_provider"
    if resp.status is GatewayStatus.BLOCKED:
        if error == "budget.exhausted":
            return "budget_exhausted", error
        return "model_unavailable", error or "no_provider_available"
    if error.startswith("all candidates failed"):
        return "model_unavailable", error
    return "model_error", error or "provider request error"
