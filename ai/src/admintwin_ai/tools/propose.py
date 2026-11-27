"""Propose tool ``change.propose`` — единственный способ для агента
инициировать запись в инфраструктуру (§3.3, §11).

Создаёт ChangeRequest в ядре: ``POST {core_url}/api/v1/changes``. Решение
принимают Policy Engine и человек в Approval Service; у агента нет
инструментов согласования или исполнения (T-CAP-002, T-CAP-003).

Dev-режим идентичности (до JWT/OIDC): заголовки ``X-AdminTwin-Tenant``,
``X-AdminTwin-Actor``, ``X-AdminTwin-Actor-Kind: ai_agent``. Повтор при
сетевой ошибке/5xx использует тот же ``Idempotency-Key`` (защита от
дублей, §18.6 Replay).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import httpx

from admintwin_ai.tools.invoker import ToolContext
from admintwin_ai.tools.registry import ToolBackendError, ToolOutput, ToolRefusal

CHANGES_PATH = "/api/v1/changes"
PROBLEM_PREFIX = "https://errors.admintwin.io/"


class ChangeProposeHandler:
    def __init__(
        self,
        core_url: str,
        *,
        client: httpx.Client | None = None,
        idempotency_key_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
        max_attempts: int = 2,
        timeout_s: float = 10.0,
    ) -> None:
        self._url = core_url.rstrip("/") + CHANGES_PATH
        self._client = client or httpx.Client(timeout=timeout_s)
        self._new_key = idempotency_key_factory
        self._max_attempts = max(1, max_attempts)

    def __call__(self, ctx: ToolContext, params: dict[str, Any]) -> ToolOutput:
        runbook_id = params["runbook_id"]
        if runbook_id not in ctx.agent.allowed_runbooks:
            raise ToolRefusal("runbook_not_allowed",
                              f"agent '{ctx.agent.id}' may not propose runbook '{runbook_id}'")
        body = {
            "runbook_id": runbook_id,
            "asset_id": params["asset_id"],
            "params": params.get("params", {}),
            "reason": params["reason"],
            "incident_id": params.get("incident_id") or ctx.incident_id,
        }
        headers = {
            "Idempotency-Key": self._new_key(),
            "X-AdminTwin-Tenant": ctx.tenant_id,
            "X-AdminTwin-Actor": ctx.agent.id,
            "X-AdminTwin-Actor-Kind": "ai_agent",
            "Accept": "application/json, application/problem+json",
        }
        if ctx.correlation_id:
            headers["X-Correlation-Id"] = ctx.correlation_id

        response: httpx.Response | None = None
        last_error = ""
        for _ in range(self._max_attempts):
            try:
                response = self._client.post(self._url, json=body, headers=headers)
            except httpx.TransportError as exc:
                last_error = type(exc).__name__
                response = None
                continue
            if response.status_code < 500:
                break
            last_error = f"HTTP {response.status_code}"
        if response is None:
            raise ToolBackendError(f"core API unreachable: {last_error}")
        return self._handle(response, runbook_id)

    @staticmethod
    def _handle(response: httpx.Response, runbook_id: str) -> ToolOutput:
        if response.status_code in (200, 201, 202):
            try:
                change = response.json()
            except ValueError as exc:
                raise ToolBackendError("core API returned non-JSON change object") from exc
            if not isinstance(change, dict) or "id" not in change or "status" not in change:
                raise ToolBackendError("core API change object lacks id/status")
            return ToolOutput(data={"change_id": str(change["id"]),
                                    "status": str(change["status"]),
                                    "runbook_id": str(change.get("runbook_id", runbook_id))})
        problem = _problem(response)
        if response.status_code >= 500:
            raise ToolBackendError(f"core API error {response.status_code}: "
                                   f"{problem.get('title', '')}")
        ptype = str(problem.get("type", ""))
        slug = ptype.removeprefix(PROBLEM_PREFIX) if ptype.startswith(PROBLEM_PREFIX) \
            else f"http_{response.status_code}"
        raise ToolRefusal(slug or f"http_{response.status_code}",
                          str(problem.get("detail") or problem.get("title") or ""), problem)


def _problem(response: httpx.Response) -> dict[str, Any]:
    """RFC 9457 problem+json; неизвестный формат — минимальный объект."""
    try:
        data = response.json()
    except ValueError:
        return {"status": response.status_code, "title": response.reason_phrase}
    if not isinstance(data, dict):
        return {"status": response.status_code}
    allowed = ("type", "title", "status", "detail", "instance", "policy_id", "change_id",
               "request_id")
    return {k: data[k] for k in allowed if k in data}
