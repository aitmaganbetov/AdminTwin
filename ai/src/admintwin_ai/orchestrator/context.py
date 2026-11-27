"""Детерминированное определение контекста инцидента для Commander (§5.3).

Контракт ``POST /v1/tasks`` (contracts §4) не передаёт тип алерта, поэтому
Commander выводит его по правилам, в порядке приоритета:

1. явная подсказка ``context.alert_type`` в запросе (расширение контракта);
2. типы событий ``events.list`` по активам задачи (ядро: ``http_5xx``,
   ``disk_usage``, ``container_down``, ``service_down``, ``db_connections``);
3. ключевые слова в ``objective`` (ru/en).

Правила — данные этого модуля; LLM в выборе не участвует.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

#: тип события ядра → тип алерта правил агентов (agents/mvp-agents.yaml: routing.alert_types)
EVENT_KIND_ALERT: dict[str, str] = {
    "http_502": "http_502",
    "http_5xx": "http_5xx",
    "disk_usage": "disk_usage_high",
    "disk_usage_high": "disk_usage_high",
    "disk_full": "disk_full",
    "container_down": "container_stopped",
    "container_stopped": "container_stopped",
    "container_restart_loop": "container_restart_loop",
    "healthcheck_failed": "healthcheck_failed",
    "service_down": "service_down",
    "host_down": "host_down",
    "db_connections": "db_connections_exhausted",
    "db_connections_exhausted": "db_connections_exhausted",
    "replication_lag": "replication_lag",
    "slow_queries": "slow_queries",
    "high_cpu": "high_cpu",
    "high_memory": "high_memory",
    "network_unreachable": "network_unreachable",
    "packet_loss": "packet_loss",
    "vpn_down": "vpn_down",
}

_TEXT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b502\b|bad gateway", re.IGNORECASE), "http_502"),
    (re.compile(r"\b5\d\d\b|\b5xx\b", re.IGNORECASE), "http_5xx"),
    (re.compile(r"disk|диск|no space|заполнен|inode|файлов\w* систем", re.IGNORECASE),
     "disk_usage_high"),
    (re.compile(r"container|контейнер", re.IGNORECASE), "container_stopped"),
    (re.compile(r"connections? exhausted|too many (clients|connections)|соединени",
                re.IGNORECASE), "db_connections_exhausted"),
    (re.compile(r"service (down|failed)|сервис\w* (упал|останов)", re.IGNORECASE),
     "service_down"),
]

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def alert_from_event(event: Mapping[str, Any]) -> str | None:
    kind = str(event.get("type", "")).lower()
    alert = EVENT_KIND_ALERT.get(kind)
    summary = str(event.get("summary", ""))
    if alert == "http_5xx" and re.search(r"\b502\b|bad gateway", summary, re.IGNORECASE):
        return "http_502"
    return alert


def infer_alert_type(explicit: str | None, events: Iterable[Mapping[str, Any]],
                     objective: str) -> tuple[str | None, str]:
    """(тип алерта, правило) — правило попадает в журнал задачи."""
    if explicit:
        return explicit, "request.context.alert_type"
    ranked = sorted(events, key=lambda e: _SEVERITY_RANK.get(str(e.get("severity")), 9))
    for ev in ranked:
        alert = alert_from_event(ev)
        if alert:
            return alert, f"events.list:{ev.get('type')}"
    for pattern, alert in _TEXT_RULES:
        if pattern.search(objective):
            return alert, f"objective~{pattern.pattern[:24]}"
    return None, "none"


def alert_from_text(text: str) -> str | None:
    """Разбор ответа пользователя на вопрос «уточните тип проблемы»."""
    lowered = text.strip().lower()
    if lowered in EVENT_KIND_ALERT:
        return EVENT_KIND_ALERT[lowered]
    for pattern, alert in _TEXT_RULES:
        if pattern.search(text):
            return alert
    return None
