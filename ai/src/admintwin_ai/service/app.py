"""HTTP API оркестратора (contracts §4), сервис ``admintwin-orchestrator`` (:8090).

* Каждый запрос — только с валидным ``X-AdminTwin-Service-Token``
  (constant-time сравнение); иначе ``401`` RFC 9457.
* Tenant и пользователь — из заголовков ядра (``X-AdminTwin-Tenant``,
  ``X-AdminTwin-Actor``); tenant в теле/запросе обязан совпадать с заголовком;
  задача другого tenant неотличима от отсутствующей (``404``).
* Ошибки — ``application/problem+json`` с типами ``https://errors.admintwin.io/*``.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from admintwin_ai import __version__
from admintwin_ai.contracts.task_state import TaskState
from admintwin_ai.orchestrator.cases import RcaCase
from admintwin_ai.orchestrator.tasks import EventLog, TaskNotFoundError, TaskRejectedError
from admintwin_ai.service.runtime import Runtime
from admintwin_ai.tools.http_backend import SERVICE_TOKEN_HEADER

log = logging.getLogger("admintwin.api")

PROBLEM = "https://errors.admintwin.io/"
_UUID = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


class ProblemError(Exception):
    def __init__(self, status: int, code: str, detail: str = "", title: str | None = None):
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail
        self.title = title or code.replace("-", " ").capitalize()


def problem_response(status: int, code: str, detail: str = "", title: str | None = None,
                     **extra: Any) -> JSONResponse:
    body: dict[str, Any] = {"type": PROBLEM + code, "title": title or code.replace("-", " ")
                            .capitalize(), "status": status}
    if detail:
        body["detail"] = detail
    body.update(extra)
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


# --- модели запросов ---------------------------------------------------------------


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_ids: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("asset_ids")
    @classmethod
    def _uuids(cls, v: list[str]) -> list[str]:
        for a in v:
            uuid.UUID(a)
        return list(dict.fromkeys(v))


class EventHint(BaseModel):
    """Сводка события от ядра: шаблонный текст и ссылка, без сырых строк журналов (контракты §4)."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(max_length=128)
    evidence_ref: str = Field(max_length=200)
    kind: str = Field(max_length=64)
    severity: str = Field(max_length=16)
    asset_id: str | None = Field(default=None, max_length=64)
    at: str = Field(max_length=64)
    summary: str = Field(default="", max_length=500)
    fingerprint: str = Field(default="", max_length=200)


class Hints(BaseModel):
    """Контекст инцидента от ядра (контракты §4, поле ``context``). Все поля необязательны;
    строки — данные, не инструкции: в промпты попадают только через обёртку недоверенных данных."""

    model_config = ConfigDict(extra="forbid")

    alert_type: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    asset_type: str | None = Field(default=None, max_length=64)
    service_kind: str | None = Field(default=None, max_length=64)
    incident_title: str | None = Field(default=None, max_length=300)
    severity: str | None = Field(default=None, max_length=16)
    priority: str | None = Field(default=None, max_length=16)
    environment: str | None = Field(default=None, max_length=32)
    asset_ids: list[str] = Field(default_factory=list, max_length=500)
    events: list[EventHint] = Field(default_factory=list, max_length=100)
    constraints: list[str] = Field(default_factory=list, max_length=20)


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["rca", "chat", "diagnose"]
    tenant_id: str = Field(pattern=_UUID)
    incident_id: str | None = Field(default=None, min_length=1, max_length=128)
    objective: str = Field(default="", max_length=4000)
    scope: Scope = Field(default_factory=Scope)
    requested_by: str | None = Field(default=None, max_length=200)
    context: Hints | None = None


class TextInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=8000)


class SessionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=_UUID)
    incident_id: str | None = Field(default=None, max_length=128)


class KillRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str | None = Field(default=None, pattern=_UUID)
    platform: bool = False
    active: bool = True
    reason: str = Field(default="kill switch", max_length=500)


class CaseFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=_UUID)
    incident_id: str = Field(min_length=1, max_length=128)
    correct: bool
    actual_cause: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")
    cause: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")
    summary: str | None = Field(default=None, max_length=4000)


# --- приложение ---------------------------------------------------------------------------


def create_app(runtime: Runtime) -> FastAPI:
    settings = runtime.settings
    orch = runtime.orchestrator
    manager = orch.manager
    token = settings.service_token.encode() if settings.service_token else None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await orch.start()
        try:
            yield
        finally:
            await orch.close()

    app = FastAPI(title="admintwin-orchestrator", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runtime = runtime

    @app.middleware("http")
    async def auth(request: Request,
                   call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if token is not None:
            presented = request.headers.get(SERVICE_TOKEN_HEADER, "").encode()
            if not hmac.compare_digest(presented, token):
                return problem_response(401, "unauthenticated",
                                        "valid X-AdminTwin-Service-Token is required")
        return await call_next(request)

    @app.exception_handler(ProblemError)
    async def _problem(_: Request, exc: ProblemError) -> JSONResponse:
        return problem_response(exc.status, exc.code, exc.detail, exc.title)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"field": "/".join(str(p) for p in e.get("loc", [])[1:]) or "body",
                   "reason": str(e.get("msg", ""))[:300]} for e in exc.errors()[:20]]
        return problem_response(422, "invalid-params", "request does not match the contract",
                                errors=errors)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not-found", 405: "bad-request"}.get(exc.status_code, "bad-request")
        return problem_response(exc.status_code, code, str(exc.detail))

    # --- идентичность ------------------------------------------------------------------

    def header_tenant(request: Request) -> str | None:
        return request.headers.get("X-AdminTwin-Tenant") or None

    def actor(request: Request) -> str:
        kind = request.headers.get("X-AdminTwin-Actor-Kind", "service")
        return f"{kind}:{request.headers.get('X-AdminTwin-Actor', 'core')}"

    def tenant_for(request: Request, explicit: str | None) -> str:
        hdr = header_tenant(request)
        if hdr and explicit and hdr != explicit:
            raise ProblemError(403, "forbidden", "tenant_id does not match X-AdminTwin-Tenant")
        tenant = explicit or hdr
        if not tenant:
            raise ProblemError(400, "bad-request",
                               "tenant is required (X-AdminTwin-Tenant or tenant_id)")
        return tenant

    def task_or_404(request: Request, task_id: str) -> Any:
        tenant = tenant_for(request, request.query_params.get("tenant_id"))
        try:
            return manager.get(task_id, tenant)
        except TaskNotFoundError:
            raise ProblemError(404, "not-found", "task not found") from None

    # --- задачи -------------------------------------------------------------------------

    @app.post("/v1/tasks", status_code=202)
    async def create_task(body: TaskCreate, request: Request) -> dict[str, Any]:
        tenant = tenant_for(request, body.tenant_id)
        requested_by = body.requested_by or request.headers.get("X-AdminTwin-Actor")
        try:
            if body.kind == "chat":
                session = orch.create_session(tenant, body.incident_id)
                task = orch.session_message(session, body.objective or "Сводка по инциденту",
                                            requested_by=requested_by)
            else:
                task = manager.create(
                    tenant_id=tenant, kind=body.kind, objective=body.objective,
                    incident_id=body.incident_id, asset_ids=body.scope.asset_ids,
                    requested_by=requested_by,
                    context={"hints": body.context.model_dump(exclude_none=True)}
                    if body.context else None)
                manager.start(task)
        except TaskRejectedError as exc:
            raise ProblemError(409, "kill-switch-active", str(exc)) from None
        return {"task_id": task.id, "status": task.state.value,
                **({"session_id": task.session_id} if task.session_id else {})}

    @app.get("/v1/tasks")
    async def list_tasks(request: Request, tenant_id: str | None = None) -> dict[str, Any]:
        tenant = tenant_for(request, tenant_id)
        items = [manager.view(t).model_dump() for t in manager.list_tasks(tenant)]
        items.sort(key=lambda v: v["created_at"], reverse=True)
        return {"items": items}

    @app.get("/v1/tasks/{task_id}")
    async def get_task(task_id: str, request: Request) -> dict[str, Any]:
        return manager.view(task_or_404(request, task_id)).model_dump()

    @app.post("/v1/tasks/{task_id}/cancel")
    async def cancel_task(task_id: str, request: Request) -> dict[str, Any]:
        task = task_or_404(request, task_id)
        root = manager.root_of(task)
        confirmed = await manager.cancel(root, reason="cancelled by requester",
                                         actor=actor(request))
        return {"task_id": root.id, "status": root.state.value,
                "cancellation": "cancelled" if confirmed else "cancellation_pending"}

    @app.post("/v1/tasks/{task_id}/input", status_code=202)
    async def task_input(task_id: str, body: TextInput, request: Request) -> dict[str, Any]:
        task = task_or_404(request, task_id)
        if task.state is not TaskState.WAITING_INPUT:
            raise ProblemError(409, "invalid-transition",
                               f"task is '{task.state.value}', not waiting_input")
        manager.provide_input(task, body.text)
        return {"task_id": task.id, "status": task.state.value}

    @app.get("/v1/tasks/{task_id}/events")
    async def task_events(task_id: str, request: Request) -> StreamingResponse:
        task = task_or_404(request, task_id)
        root = manager.root_of(task)
        if root.events is None:
            raise ProblemError(404, "not-found", "no event stream")
        return sse(root.events, request)

    # --- чат ---------------------------------------------------------------------------------

    def session_or_404(request: Request, session_id: str) -> Any:
        tenant = tenant_for(request, request.query_params.get("tenant_id"))
        session = orch.sessions.get(session_id)
        if session is None or session.tenant_id != tenant:
            raise ProblemError(404, "not-found", "chat session not found")
        return session

    @app.post("/v1/chat/sessions", status_code=201)
    async def create_session(body: SessionCreate, request: Request) -> dict[str, Any]:
        tenant = tenant_for(request, body.tenant_id)
        if manager.kill_active(tenant):
            raise ProblemError(409, "kill-switch-active", "kill switch active")
        session = orch.create_session(tenant, body.incident_id)
        return {"session_id": session.id}

    @app.post("/v1/chat/sessions/{session_id}/messages", status_code=202)
    async def session_message(session_id: str, body: TextInput,
                              request: Request) -> dict[str, Any]:
        session = session_or_404(request, session_id)
        try:
            task = orch.session_message(session, body.text,
                                        requested_by=request.headers.get("X-AdminTwin-Actor"))
        except TaskRejectedError as exc:
            raise ProblemError(409, "kill-switch-active", str(exc)) from None
        except ValueError as exc:
            raise ProblemError(409, "conflict", str(exc)) from None
        return {"session_id": session.id, "task_id": task.id, "status": task.state.value}

    @app.get("/v1/chat/sessions/{session_id}/events")
    async def session_events(session_id: str, request: Request) -> StreamingResponse:
        session = session_or_404(request, session_id)
        return sse(session.events, request)

    # --- kill switch ----------------------------------------------------------------------------

    @app.post("/v1/kill")
    async def kill(body: KillRequest, request: Request) -> dict[str, Any]:
        hdr = header_tenant(request)
        if body.platform:
            if hdr and request.headers.get("X-AdminTwin-Actor-Kind") != "service":
                raise ProblemError(403, "forbidden",
                                   "platform kill is accepted only from the core service")
            tenant = None
        else:
            tenant = tenant_for(request, body.tenant_id)
        if not body.active:
            manager.release_kill(tenant, platform=body.platform)
            return {"scope": "platform" if body.platform else f"tenant:{tenant}",
                    "active": False}
        report = await manager.kill(tenant, platform=body.platform, actor=actor(request),
                                    reason=f"kill switch: {body.reason}")
        log.warning("kill switch", extra={"scope": report.scope,
                                          "cancelled": len(report.cancelled),
                                          "elapsed_ms": report.elapsed_ms})
        return {**report.model_dump(), "active": True}

    # --- кейсы (расширение: обратная связь оператора из ядра) ----------------------------------

    @app.post("/v1/cases", status_code=202)
    async def case_feedback(body: CaseFeedback, request: Request) -> dict[str, Any]:
        tenant = tenant_for(request, body.tenant_id)
        case = orch.cases.confirm(tenant, body.incident_id, correct=body.correct,
                                  actual_cause=body.actual_cause)
        if case is None and body.correct and (body.cause or body.actual_cause):
            case = orch.cases.upsert(RcaCase(
                tenant_id=tenant, incident_id=body.incident_id,
                cause=body.actual_cause or body.cause or "", summary=body.summary or "",
                confirmed=True))
        if case is None:
            raise ProblemError(404, "not-found", "no RCA case for this incident")
        return {"incident_id": case.incident_id, "cause": case.cause,
                "confirmed": case.confirmed}

    # --- здоровье ---------------------------------------------------------------------------------

    @app.get("/healthz")
    async def healthz(probe: bool = False) -> dict[str, Any]:
        if probe:
            providers = await asyncio.get_running_loop().run_in_executor(
                orch.executor, lambda: runtime.provider_states(probe=True))
        else:
            providers = runtime.provider_states()
        usable = [p for p in providers if p["enabled"] and p["circuit"] != "open"
                  and p.get("health", {}).get("ok", True)]
        tasks = manager.list_tasks(None)
        by_state: dict[str, int] = {}
        for t in tasks:
            by_state[t.state.value] = by_state.get(t.state.value, 0) + 1
        llm = "ok" if usable else "unavailable"
        return {
            "status": "ok" if usable else "degraded",
            "version": __version__,
            "llm": llm,
            "degradation": None if usable else
            "все LLM недоступны: задачи агентов → blocked; мониторинг, алерты, топология и "
            "ручные changes в ядре работают (§17.2)",
            "bus": {"kind": orch.bus.kind, "healthy": await orch.bus.healthy()},
            "providers": providers,
            "tasks": by_state,
            "auth": "service_token" if token else "disabled (ADMINTWIN_DEV_INSECURE)",
        }

    return app


def sse(log_: EventLog, request: Request) -> StreamingResponse:
    raw = request.headers.get("Last-Event-ID") or request.query_params.get("last_event_id") or "0"
    try:
        last = max(0, int(raw))
    except ValueError:
        last = 0

    async def gen() -> AsyncIterator[str]:
        yield "retry: 3000\n\n"
        async for ev in log_.follow(last):
            if await request.is_disconnected():
                return
            yield ": heartbeat\n\n" if ev is None else ev.sse()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
