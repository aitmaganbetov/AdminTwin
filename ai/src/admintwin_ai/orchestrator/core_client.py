"""Клиент ядра для записей оркестратора от собственного имени (contracts §3).

``POST /api/v1/incidents/{id}/rca`` — только сервис ``orchestrator``:
``X-AdminTwin-Service-Token`` + ``X-AdminTwin-Tenant`` +
``X-AdminTwin-Actor: orchestrator`` + ``X-AdminTwin-Actor-Kind: service``.
Повтор при сетевой ошибке/5xx — с тем же ``Idempotency-Key``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from pydantic import BaseModel

from admintwin_ai.tools.http_backend import agent_headers, problem_of

log = logging.getLogger("admintwin.core")

ORCHESTRATOR_ACTOR = "orchestrator"


class PostResult(BaseModel):
    ok: bool
    status_code: int | None = None
    error: str | None = None
    attempts: int = 0


class CoreClient:
    def __init__(self, core_url: str, *, service_token: str | None,
                 client: httpx.AsyncClient | None = None, timeout_s: float = 10.0,
                 max_attempts: int = 3, backoff_s: float = 0.5) -> None:
        self._base = core_url.rstrip("/")
        self._token = service_token
        self._client = client or httpx.AsyncClient(timeout=timeout_s)
        self._max_attempts = max(1, max_attempts)
        self._backoff = backoff_s

    async def close(self) -> None:
        await self._client.aclose()

    async def post_rca(self, tenant_id: str, incident_id: str,
                       payload: dict[str, Any]) -> PostResult:
        url = f"{self._base}/api/v1/incidents/{incident_id}/rca"
        headers = agent_headers(self._token, tenant_id, ORCHESTRATOR_ACTOR, actor_kind="service")
        headers["Idempotency-Key"] = f"rca-{payload.get('task_id', incident_id)}"
        last = PostResult(ok=False)
        for attempt in range(1, self._max_attempts + 1):
            try:
                resp = await self._client.post(url, json=payload, headers=headers)
            except httpx.TransportError as exc:
                last = PostResult(ok=False, error=type(exc).__name__, attempts=attempt)
            else:
                if resp.status_code < 300:
                    return PostResult(ok=True, status_code=resp.status_code, attempts=attempt)
                problem = problem_of(resp)
                last = PostResult(ok=False, status_code=resp.status_code, attempts=attempt,
                                  error=str(problem.get("detail") or problem.get("title") or ""))
                if resp.status_code < 500:
                    break  # 4xx — повтор не поможет
            if attempt < self._max_attempts:
                await asyncio.sleep(self._backoff * attempt)
        log.warning("posting RCA to core failed", extra={"incident_id": incident_id,
                                                         "error": last.error})
        return last
