"""HTTP ``ReadBackend``: read tools через Tool Service ядра (contracts §1).

``POST {core_url}/api/v1/tools/{name}`` с телом ``{"input": {...}}`` →
``200 {"tool","version","data_class","data"}``. Идентичность — сервисная
(contracts §0): ``X-AdminTwin-Service-Token`` + ``X-AdminTwin-Tenant``,
``X-AdminTwin-Actor: <agent id>``, ``X-AdminTwin-Actor-Kind: ai_agent``.

Ядро повторно проверяет tool scope, схему входа/выхода, принадлежность
актива tenant и лимит размера (defense in depth). Локальные проверки
``ToolInvoker`` (allowed_tools, JSON Schema, класс данных, маскирование
секретов, обёртка «данные, не инструкции») остаются в силе: этот backend
лишь заменяет источник данных.

Отображение ответов:

* ``200`` — ``ToolOutput(data, data_class=<класс ядра>)``; итоговый класс в
  ``ToolInvoker`` = max(класс контракта, класс ядра);
* RFC 9457 ``4xx`` — ``ToolRefusal`` с ``reason`` = slug типа проблемы
  (``not-found``, ``forbidden``, ``invalid-params``, ``conflict``,
  ``kill-switch-active`` ...); ``401`` — ошибка конфигурации сервиса
  (``ToolBackendError``), а не отказ агенту;
* ``5xx``/сетевая ошибка — повтор (read идемпотентен), затем ``ToolBackendError``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

from admintwin_ai.classification import DataClass
from admintwin_ai.tools.registry import ToolBackendError, ToolOutput, ToolRefusal

TOOLS_PATH = "/api/v1/tools/"
ASSETS_PATH = "/api/v1/assets/"
PROBLEM_PREFIX = "https://errors.admintwin.io/"
SERVICE_TOKEN_HEADER = "X-AdminTwin-Service-Token"  # noqa: S105 - имя заголовка, не секрет

_PROBLEM_FIELDS = ("type", "title", "status", "detail", "instance", "policy_id", "change_id",
                   "request_id", "errors")


def agent_headers(service_token: str | None, tenant_id: str, actor: str,
                  actor_kind: str = "ai_agent") -> dict[str, str]:
    """Заголовки сервисной идентичности ядра (contracts §0)."""
    headers = {
        "X-AdminTwin-Tenant": tenant_id,
        "X-AdminTwin-Actor": actor,
        "X-AdminTwin-Actor-Kind": actor_kind,
        "Accept": "application/json, application/problem+json",
    }
    if service_token:
        headers[SERVICE_TOKEN_HEADER] = service_token
    return headers


def problem_of(response: httpx.Response) -> dict[str, Any]:
    """RFC 9457 problem+json; неизвестный формат — минимальный объект."""
    try:
        data = response.json()
    except ValueError:
        return {"status": response.status_code, "title": response.reason_phrase}
    if not isinstance(data, dict):
        return {"status": response.status_code}
    return {k: data[k] for k in _PROBLEM_FIELDS if k in data}


def problem_slug(problem: dict[str, Any], status: int) -> str:
    ptype = str(problem.get("type", ""))
    if ptype.startswith(PROBLEM_PREFIX):
        slug = ptype.removeprefix(PROBLEM_PREFIX).strip("/")
        if slug:
            return slug
    return f"http_{status}"


class HttpReadBackend:
    """``ReadBackend`` + ``AssetDirectory`` поверх ядра.

    Вызов выполняется от имени агента (``ToolContext.agent.id``), поэтому
    ``fetch`` принимает id агента через ``fetch_as``; ``read_handlers``
    передаёт его автоматически (см. ``admintwin_ai.tools.read``).
    """

    def __init__(
        self,
        core_url: str,
        *,
        service_token: str | None,
        client: httpx.Client | None = None,
        timeout_s: float = 20.0,
        max_attempts: int = 2,
        asset_cache_ttl_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._base = core_url.rstrip("/")
        self._token = service_token
        self._client = client or httpx.Client(timeout=timeout_s)
        self._max_attempts = max(1, max_attempts)
        self._ttl = asset_cache_ttl_s
        self._clock = clock
        self._lock = threading.Lock()
        self._asset_cache: dict[tuple[str, str], tuple[bool, float]] = {}

    # --- ReadBackend ------------------------------------------------------------

    def fetch(self, tool: str, tenant_id: str, params: dict[str, Any]) -> ToolOutput:
        """Без агента (совместимость с протоколом) — от имени Commander."""
        return self.fetch_as(tool, tenant_id, "ai-commander", params)

    def fetch_as(self, tool: str, tenant_id: str, agent_id: str,
                 params: dict[str, Any]) -> ToolOutput:
        url = self._base + TOOLS_PATH + tool
        headers = agent_headers(self._token, tenant_id, agent_id)
        response = self._post(url, {"input": params}, headers)
        if response.status_code == 200:
            return self._parse_ok(tool, response)
        problem = problem_of(response)
        if response.status_code == 401:
            raise ToolBackendError("core rejected orchestrator service credentials (401)")
        if response.status_code >= 500:
            raise ToolBackendError(f"core tool service error {response.status_code}: "
                                   f"{problem.get('title', '')}")
        raise ToolRefusal(problem_slug(problem, response.status_code),
                          str(problem.get("detail") or problem.get("title") or ""), problem)

    def _post(self, url: str, body: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        last = ""
        response: httpx.Response | None = None
        for _ in range(self._max_attempts):
            try:
                response = self._client.post(url, json=body, headers=headers)
            except httpx.TransportError as exc:
                last = type(exc).__name__
                response = None
                continue
            if response.status_code not in (502, 503, 504):
                return response
            last = f"HTTP {response.status_code}"
        if response is None:
            raise ToolBackendError(f"core API unreachable: {last}")
        return response

    @staticmethod
    def _parse_ok(tool: str, response: httpx.Response) -> ToolOutput:
        try:
            body = response.json()
        except ValueError as exc:
            raise ToolBackendError("core tool service returned non-JSON body") from exc
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise ToolBackendError("core tool service response lacks object 'data'")
        if body.get("tool") not in (None, tool):
            raise ToolBackendError(f"core answered for tool '{body.get('tool')}', "
                                   f"expected '{tool}'")
        raw_class = body.get("data_class")
        try:
            data_class = DataClass(raw_class) if raw_class is not None else DataClass.UNKNOWN
        except ValueError:
            data_class = DataClass.UNKNOWN  # неизвестный класс — fail closed
        return ToolOutput(data=body["data"], data_class=data_class)

    # --- AssetDirectory -----------------------------------------------------------

    def asset_exists(self, tenant_id: str, asset_id: str) -> bool:
        """Предварительная проверка CMDB tenant (``GET /api/v1/assets/{id}``).

        Ядро повторно проверяет актив при каждом вызове инструмента, поэтому
        при недоступности ядра проверка пропускается (ответ — ``True``), а
        ошибка проявится в самом вызове как ``backend_error``.
        """
        key = (tenant_id, asset_id)
        now = self._clock()
        with self._lock:
            cached = self._asset_cache.get(key)
            if cached is not None and now - cached[1] < self._ttl:
                return cached[0]
        headers = agent_headers(self._token, tenant_id, "ai-commander")
        try:
            resp = self._client.get(self._base + ASSETS_PATH + asset_id, headers=headers)
        except httpx.TransportError:
            return True
        if resp.status_code >= 500 or resp.status_code == 401:
            return True
        exists = resp.status_code == 200
        with self._lock:
            self._asset_cache[key] = (exists, now)
        return exists
