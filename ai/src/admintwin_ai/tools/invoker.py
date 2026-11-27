"""Исполнитель вызовов Tool Layer — единственная точка, через которую агент
получает данные или создаёт ChangeRequest.

Порядок проверок (каждый отказ записывается в аудит):

1. инструмент существует (инструментов execute нет — T-CAP-003);
2. агент активен и инструмент входит в его ``allowed_tools`` (T-CAP-001);
3. tenant-scope: tenant агента совпадает с tenant контекста;
4. параметры валидны по JSON Schema (вне allowlist — отказ);
5. ``asset_id`` существует в CMDB этого tenant (эскалация через параметры);
6. rate limit;
7. вызов обработчика;
8. валидация ответа по output-схеме;
9. класс данных ответа ≤ ``data_sensitivity_max`` контекста;
10. маскирование секретов в ответе;
11. лимит размера ответа;
12. обёртка «данные, не инструкции».
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from admintwin_ai.agents.model import AgentDefinition
from admintwin_ai.audit import AuditSink, ToolCallRecord, sha256_of
from admintwin_ai.classification import DataClass
from admintwin_ai.masking import Masker, MaskingSession
from admintwin_ai.providers.base import ChatMessage, ToolCall
from admintwin_ai.tools.ratelimit import RateLimiter
from admintwin_ai.tools.registry import ToolBackendError, ToolRefusal, ToolRegistry
from admintwin_ai.tools.wrapping import looks_like_injection, wrap_untrusted


class AssetDirectory(Protocol):
    """Проверка существования актива в CMDB tenant (§18.6)."""

    def asset_exists(self, tenant_id: str, asset_id: str) -> bool: ...


class ToolContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str
    agent: AgentDefinition
    task_id: str | None = None
    incident_id: str | None = None
    correlation_id: str | None = None
    data_sensitivity_max: DataClass | None = None  # None — как у агента

    @property
    def sensitivity_max(self) -> DataClass:
        limits = [self.agent.data_sensitivity_max]
        if self.data_sensitivity_max is not None:
            limits.append(self.data_sensitivity_max)
        return min(limits, key=lambda d: d.rank)


class ToolResult(BaseModel):
    status: Literal["ok", "refused", "error"]
    tool: str
    kind: str | None = None
    content: str  # то, что видит модель
    data: dict[str, Any] | None = None  # маскированные данные для оркестратора
    data_class: DataClass | None = None
    reason: str | None = None
    problem: dict[str, Any] | None = None
    truncated: bool = False
    suspected_injection: bool = False

    def to_message(self, tool_call_id: str) -> ChatMessage:
        return ChatMessage(role="tool", content=self.content, tool_call_id=tool_call_id,
                           is_error=self.status != "ok")


class ToolInvoker:
    def __init__(
        self,
        registry: ToolRegistry,
        audit: AuditSink,
        *,
        assets: AssetDirectory | None = None,
        rate_limiter: RateLimiter | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._assets = assets
        self._limiter = rate_limiter or RateLimiter()
        self._clock = clock
        self._secret_masker = Masker(secrets_only=True)
        self.calls = 0  # счётчик выполненных вызовов (для бюджета tool_calls)
        self._calls_lock = threading.Lock()

    def invoke_call(self, ctx: ToolContext, call: ToolCall) -> ToolResult:
        if call.malformed:
            return self._refuse(ctx, call.name, None, call.arguments, "malformed_arguments",
                                "tool arguments are not a valid JSON object")
        return self.invoke(ctx, call.name, call.arguments)

    def invoke(self, ctx: ToolContext, name: str, params: dict[str, Any]) -> ToolResult:
        started = self._clock()
        agent = ctx.agent
        tool = self._registry.get(name)
        if tool is None:
            return self._refuse(ctx, name, None, params, "tool_not_found",
                                "no such tool for this agent (only read/propose tools exist)")
        kind = tool.kind.value
        if not agent.is_active:
            return self._refuse(ctx, name, kind, params, "agent_not_active", agent.status.value)
        if name not in agent.allowed_tools:
            return self._refuse(ctx, name, kind, params, "tool_not_allowed",
                                f"'{name}' is outside the tool scope of agent '{agent.id}'")
        if agent.tenant_id is not None and agent.tenant_id != ctx.tenant_id:
            return self._refuse(ctx, name, kind, params, "tenant_scope_violation",
                                "agent is bound to another tenant")
        errors = sorted(tool.input_validator.iter_errors(params), key=lambda e: list(e.path))
        if errors:
            where = "/".join(str(p) for p in errors[0].path) or "<root>"
            return self._refuse(ctx, name, kind, params, "invalid_params",
                                f"{where}: {errors[0].message}")
        asset_id = params.get("asset_id")
        if (isinstance(asset_id, str) and self._assets is not None
                and not self._assets.asset_exists(ctx.tenant_id, asset_id)):
            return self._refuse(ctx, name, kind, params, "asset_not_in_tenant",
                                "asset does not exist in this tenant's CMDB")
        if not self._limiter.allow((ctx.tenant_id, agent.id, name),
                                   tool.contract.rate_limit_per_minute):
            return self._refuse(ctx, name, kind, params, "rate_limited",
                                f"limit {tool.contract.rate_limit_per_minute}/min")

        with self._calls_lock:
            self.calls += 1
        try:
            output = tool.handler(ctx, params)
        except ToolRefusal as exc:
            return self._refuse(ctx, name, kind, params, exc.reason, exc.detail, exc.problem)
        except ToolBackendError as exc:
            return self._error(ctx, name, kind, params, "backend_error", str(exc), started)

        out_errors = list(tool.output_validator.iter_errors(output.data))
        if out_errors:
            return self._error(ctx, name, kind, params, "invalid_tool_output",
                               out_errors[0].message, started)
        data_class = DataClass.max_of(tool.contract.data_class,
                                      output.data_class or tool.contract.data_class)
        if data_class.exceeds(ctx.sensitivity_max):
            return self._refuse(ctx, name, kind, params, "data_sensitivity_exceeded",
                                f"response class '{data_class}' exceeds scope "
                                f"'{ctx.sensitivity_max}'", data_class=data_class)

        masked = self._secret_masker.mask_obj(output.data, MaskingSession())
        body = json.dumps(masked, ensure_ascii=False, sort_keys=True, default=str)
        raw = body.encode("utf-8")
        limit = tool.contract.max_response_bytes
        truncated = len(raw) > limit
        if truncated:
            body = raw[:limit].decode("utf-8", errors="ignore") + " …[truncated by Tool Layer]"
        suspected = looks_like_injection(body)
        content = wrap_untrusted(name, data_class, body, suspected_injection=suspected)
        self._audit.emit(ToolCallRecord(
            tenant_id=ctx.tenant_id, agent_id=agent.id, task_id=ctx.task_id, tool=name,
            kind=kind, status="ok", params_sha256=sha256_of(params), data_class=data_class,
            response_bytes=min(len(raw), limit), truncated=truncated,
            suspected_injection=suspected, latency_ms=(self._clock() - started) * 1000,
        ))
        return ToolResult(status="ok", tool=name, kind=kind, content=content, data=masked,
                          data_class=data_class, truncated=truncated,
                          suspected_injection=suspected)

    # --- отказы и ошибки -------------------------------------------------------

    def _refuse(self, ctx: ToolContext, name: str, kind: str | None, params: dict[str, Any],
                reason: str, detail: str = "", problem: dict[str, Any] | None = None, *,
                data_class: DataClass | None = None) -> ToolResult:
        self._audit.emit(ToolCallRecord(
            tenant_id=ctx.tenant_id, agent_id=ctx.agent.id, task_id=ctx.task_id, tool=name,
            kind=kind, status="refused", reason=reason, params_sha256=sha256_of(params),
            data_class=data_class,
        ))
        content = f"TOOL CALL REFUSED by AdminTwin Tool Layer: tool={_safe(name)} reason={reason}"
        if detail:
            content += f" detail={_safe(detail)}"
        return ToolResult(status="refused", tool=name, kind=kind, content=content, reason=reason,
                          problem=problem, data_class=data_class)

    def _error(self, ctx: ToolContext, name: str, kind: str, params: dict[str, Any],
               reason: str, detail: str, started: float) -> ToolResult:
        self._audit.emit(ToolCallRecord(
            tenant_id=ctx.tenant_id, agent_id=ctx.agent.id, task_id=ctx.task_id, tool=name,
            kind=kind, status="error", reason=reason, params_sha256=sha256_of(params),
            latency_ms=(self._clock() - started) * 1000,
        ))
        return ToolResult(status="error", tool=name, kind=kind, reason=reason,
                          content=f"TOOL ERROR: tool={name} reason={reason}")


def _safe(text: str, limit: int = 200) -> str:
    """Эхо значений из запроса модели — коротко и без разделителей обёртки."""
    return text[:limit].replace("<<<", "‹‹‹").replace(">>>", "›››").replace("\n", " ")
