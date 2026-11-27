"""Учёт стоимости по провайдерам (§6.6, §10: стоимость видна в реальном времени).

``CostTrackingSink`` — обёртка ``AuditSink``: передаёт записи дальше и
накапливает стоимость/токены успешных LLM-вызовов по ``task_id`` и
провайдеру. ``drain(task_id)`` возвращает приращения с прошлого вызова —
их агент-исполнитель публикует событиями ``cost``.
"""

from __future__ import annotations

import threading
from collections import defaultdict

from pydantic import BaseModel

from admintwin_ai.audit import AuditRecord, AuditSink, LLMCallRecord


class CostDelta(BaseModel):
    provider: str
    model: str
    cost_usd: float
    tokens: int


class CostTrackingSink:
    def __init__(self, inner: AuditSink | None = None) -> None:
        self._inner = inner
        self._lock = threading.Lock()
        self._pending: dict[str, list[CostDelta]] = defaultdict(list)
        self.totals: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    def emit(self, record: AuditRecord) -> None:
        if self._inner is not None:
            self._inner.emit(record)
        if isinstance(record, LLMCallRecord) and record.task_id and record.status != "error":
            delta = CostDelta(provider=record.provider, model=record.model,
                              cost_usd=record.cost_usd,
                              tokens=record.input_tokens + record.output_tokens)
            with self._lock:
                self._pending[record.task_id].append(delta)
                self.totals[record.task_id][record.provider] += record.cost_usd

    def drain(self, task_id: str) -> list[CostDelta]:
        with self._lock:
            return self._pending.pop(task_id, [])
