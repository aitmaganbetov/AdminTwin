"""Минимальный цикл агента: модель ↔ Tool Layer.

Модель видит только инструменты из ``allowed_tools`` агента; каждый
запрошенный ею вызов исполняется исключительно через ``ToolInvoker``
(никаких обходных путей), а результаты возвращаются обёрнутыми как
недоверенные данные. Класс данных диалога — максимум классов полученных
ответов инструментов; он передаётся в маршрутизатор при следующем вызове
модели, поэтому, например, ``pii`` из журналов уводит диалог на Local.
"""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, Field

from admintwin_ai.agents.model import AgentDefinition
from admintwin_ai.classification import DataClass, TaskClass
from admintwin_ai.gateway import AIGateway, CallContext, GatewayStatus
from admintwin_ai.providers.base import ChatMessage, CompletionRequest, CompletionResult, ToolSpec
from admintwin_ai.tools.invoker import ToolContext, ToolInvoker, ToolResult
from admintwin_ai.tools.registry import ToolRegistry


class ModelCaller(Protocol):
    def __call__(self, messages: list[ChatMessage], tools: list[ToolSpec],
                 data_class: DataClass) -> CompletionResult | None: ...


class AgentRunResult(BaseModel):
    final_text: str = ""
    steps: int = 0
    stopped: Literal["final", "max_steps", "tool_call_budget", "model_unavailable"]
    data_class: DataClass
    tool_results: list[ToolResult] = Field(default_factory=list)
    messages: list[ChatMessage] = Field(default_factory=list)


def gateway_caller(gateway: AIGateway, ctx: CallContext, *, system: str,
                   task_class: TaskClass, prompt_version: str,
                   max_tokens: int = 4096) -> ModelCaller:
    def call(messages: list[ChatMessage], tools: list[ToolSpec],
             data_class: DataClass) -> CompletionResult | None:
        resp = gateway.complete(ctx, CompletionRequest(
            system=system, messages=messages, tools=tools, max_tokens=max_tokens,
            prompt_version=prompt_version,
        ), data_class=data_class, task_class=task_class)
        return resp.result if resp.status is GatewayStatus.OK else None
    return call


def run_agent(agent: AgentDefinition, tools: ToolRegistry, invoker: ToolInvoker,
              tool_ctx: ToolContext, caller: ModelCaller, user_message: str, *,
              initial_data_class: DataClass = DataClass.INTERNAL, max_steps: int = 8,
              max_tool_calls: int | None = None) -> AgentRunResult:
    specs = tools.specs_for(agent)
    messages = [ChatMessage(role="user", content=user_message)]
    data_class = initial_data_class
    results: list[ToolResult] = []
    budget_calls = max_tool_calls if max_tool_calls is not None else agent.budget.tool_calls
    for step in range(1, max_steps + 1):
        completion = caller(messages, specs, data_class)
        if completion is None:
            return AgentRunResult(steps=step, stopped="model_unavailable", data_class=data_class,
                                  tool_results=results, messages=messages)
        messages.append(ChatMessage(role="assistant", content=completion.text,
                                    tool_calls=completion.tool_calls))
        if not completion.tool_calls:
            return AgentRunResult(final_text=completion.text, steps=step, stopped="final",
                                  data_class=data_class, tool_results=results,
                                  messages=messages)
        for call in completion.tool_calls:
            if len(results) >= budget_calls:
                return AgentRunResult(steps=step, stopped="tool_call_budget",
                                      data_class=data_class, tool_results=results,
                                      messages=messages)
            result = invoker.invoke_call(tool_ctx, call)
            results.append(result)
            if result.status == "ok" and result.data_class is not None:
                data_class = DataClass.max_of(data_class, result.data_class)
            messages.append(result.to_message(call.id))
    return AgentRunResult(steps=max_steps, stopped="max_steps", data_class=data_class,
                          tool_results=results, messages=messages)
