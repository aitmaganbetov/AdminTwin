"""Аудит вызовов LLM и инструментов в неизменяемый журнал ядра.

§6.3, §21: «аудит … провайдер и модель».

Записи (метаданные и хэши; сырые промпты сюда не попадают) буферизуются и отправляются пакетами
``POST {core}/api/v1/audit/ai-calls`` от имени сервиса ``orchestrator``, отдельно по tenant.
Отправка идёт в фоновом потоке и не задерживает агентов; при недоступности ядра запись остаётся
в локальном структурированном журнале (вложенный sink) и повторяется ограниченное число раз.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Any

import httpx

from admintwin_ai.audit import AuditRecord, AuditSink

log = logging.getLogger("admintwin.core_audit")

_SHIPPED = ("llm_call", "tool_call")  # routing-записи остаются только в локальном журнале


class CoreAuditSink:
    def __init__(
        self,
        core_url: str,
        service_token: str,
        inner: AuditSink,
        *,
        client: httpx.Client | None = None,
        flush_interval_s: float = 2.0,
        batch_size: int = 100,
        max_retries: int = 3,
        start: bool = True,
    ) -> None:
        self._url = core_url.rstrip("/") + "/api/v1/audit/ai-calls"
        self._token = service_token
        self._inner = inner
        self._client = client or httpx.Client(timeout=10.0)
        self._interval = flush_interval_s
        self._batch = max(1, min(batch_size, 200))
        self._retries = max_retries
        self._lock = threading.Lock()
        self._pending: list[tuple[AuditRecord, int]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        if start:
            self._thread = threading.Thread(target=self._loop, name="core-audit", daemon=True)
            self._thread.start()

    def emit(self, record: AuditRecord) -> None:
        self._inner.emit(record)
        if record.record_type in _SHIPPED:
            with self._lock:
                self._pending.append((record, 0))

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.flush()

    def flush(self) -> int:
        """Отправляет накопленное; возвращает число принятых ядром записей."""
        with self._lock:
            pending, self._pending = self._pending, []
        if not pending:
            return 0
        by_tenant: dict[str, list[tuple[AuditRecord, int]]] = defaultdict(list)
        for rec, attempt in pending:
            by_tenant[rec.tenant_id].append((rec, attempt))
        accepted = 0
        retry: list[tuple[AuditRecord, int]] = []
        for tenant, items in by_tenant.items():
            for i in range(0, len(items), self._batch):
                chunk = items[i : i + self._batch]
                outcome = self._post(tenant, [r for r, _ in chunk])
                if outcome == "ok":
                    accepted += len(chunk)
                    continue
                if outcome == "retry":
                    retry.extend((r, a + 1) for r, a in chunk if a + 1 < self._retries)
                dropped = (
                    len(chunk)
                    if outcome == "drop"
                    else sum(1 for _, a in chunk if a + 1 >= self._retries)
                )
                if dropped:
                    log.error(
                        "AI audit records not delivered to the core (kept in the local audit log)",
                        extra={"tenant_id": tenant, "dropped": dropped, "reason": outcome},
                    )
        if retry:
            with self._lock:
                self._pending[:0] = retry
        return accepted

    def _post(self, tenant: str, records: list[AuditRecord]) -> str:
        """``ok`` — принято; ``retry`` — временный сбой; ``drop`` — ядро отвергло формат/права."""
        body: dict[str, Any] = {"records": [r.model_dump(mode="json") for r in records]}
        headers = {
            "X-AdminTwin-Service-Token": self._token,
            "X-AdminTwin-Tenant": tenant,
            "X-AdminTwin-Actor": "orchestrator",
            "X-AdminTwin-Actor-Kind": "service",
        }
        try:
            resp = self._client.post(self._url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            log.warning("core audit unreachable: %s", type(exc).__name__)
            return "retry"
        if resp.status_code == 202:
            return "ok"
        if resp.status_code >= 500 or resp.status_code in (408, 429):
            return "retry"
        log.warning("core audit refused batch", extra={"status": resp.status_code})
        return "drop"

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.flush()
