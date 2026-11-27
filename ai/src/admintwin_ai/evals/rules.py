"""Детерминированные правила диагностики для офлайн-модели (``ScriptedDiagnostician``).

Это НЕ замена LLM, а воспроизводимый «эталонный диагност» для CI: он читает
те же обёрнутые ответы инструментов, что получила бы модель, и сопоставляет
сигналы с кодами причин. Так регрессия проверяет весь путь оркестратора
(выбор агентов, шина, Tool Layer, таблица гипотез, разделяющая проверка,
результат RCA) без вызова внешних провайдеров.

Семейства сценариев MVP: ``web`` (HTTP 502/5xx), ``container`` (остановка
контейнера), ``disk`` (исчерпание диска).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

Family = Literal["web", "container", "disk"]

FAMILY_OF_ALERT: dict[str, Family] = {
    "http_502": "web", "http_5xx": "web",
    "container_stopped": "container", "container_restart_loop": "container",
    "healthcheck_failed": "container",
    "disk_usage_high": "disk", "disk_full": "disk",
}


def family_of(alert_type: str | None) -> Family:
    return FAMILY_OF_ALERT.get(alert_type or "", "web")


@dataclass
class Signal:
    cause: str
    confidence: float
    supports: bool = True
    statement: str = ""
    check: dict[str, Any] | None = None  # {"tool","params","description"}


@dataclass
class Observation:
    evidence_id: str
    tool: str
    params: dict[str, Any]
    data: dict[str, Any]


@dataclass
class CauseAgg:
    cause: str
    confidence: float = 0.0
    supporting: list[str] = field(default_factory=list)
    refuting: list[str] = field(default_factory=list)
    statements: list[str] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)


def _names(family: Family) -> dict[str, str]:
    if family == "container":
        return {"oom": "container_oom_killed", "stopped": "container_crash",
                "loop": "container_crash", "config": "container_config_error"}
    return {"oom": "upstream_container_oom", "stopped": "upstream_container_stopped",
            "loop": "upstream_container_restart_loop",
            "config": "upstream_container_config_error"}


def _check(tool: str, params: dict[str, Any], description: str) -> dict[str, Any]:
    return {"tool": tool, "params": {k: v for k, v in params.items() if v is not None},
            "description": description}


def _text(data: dict[str, Any]) -> str:
    parts: list[str] = []
    for e in data.get("entries", []) or []:
        parts.append(str(e.get("line", "")))
    for e in data.get("events", []) or []:
        parts.append(f"{e.get('type', '')} {e.get('summary', '')}")
    for line in data.get("recent_log", []) or []:
        parts.append(str(line))
    return "\n".join(parts).lower()


def _container_checks(family: Family, asset: str | None, container: str | None,
                      kind: str, query: str | None = None) -> dict[str, Any]:
    n = _names(family)
    if kind == "oom":
        return _check("logs.search", {"asset_id": asset, "query": "memory cgroup out of memory",
                                      "window": "1h"},
                      "журнал ядра: OOM в cgroup контейнера")
    if kind == "config":
        return _check("logs.search", {"asset_id": asset, "query": query or "permission denied",
                                      "window": "1h"}, "ошибки чтения конфигурации")
    del n
    return _check("docker.container.inspect", {"asset_id": asset, "container": container},
                  "состояние и exit code контейнера")


def text_signals(text: str, family: Family, asset: str | None,
                 db_asset: str | None = None) -> list[Signal]:
    n = _names(family)
    out: list[Signal] = []
    db = db_asset or asset

    def add(cause: str, conf: float, stmt: str, check: dict[str, Any] | None = None,
            supports: bool = True) -> None:
        out.append(Signal(cause=cause, confidence=conf, supports=supports, statement=stmt,
                          check=check))

    if re.search(r"permission denied|invalid configuration|unknown directive|yaml: line",
                 text) and re.search(r"config|\.ya?ml|\.conf|configuration", text):
        phrase = next((p for p in ("permission denied", "yaml", "unknown directive",
                                   "invalid configuration") if p in text), None)
        add(n["config"], 0.85, "ошибка чтения конфигурации приложения",
            _container_checks(family, asset, None, "config", phrase))
    if "memory cgroup out of memory" in text or ("oom-kill" in text and "cgroup" in text):
        add(n["oom"], 0.85, "OOM killer в cgroup контейнера",
            _container_checks(family, asset, None, "oom"))
    elif re.search(r"out of memory: kill(ed)? process", text):
        add("host_out_of_memory", 0.7, "глобальный OOM на хосте",
            _check("metrics.query", {"asset_id": asset, "metric": "node_memory_used_percent",
                                     "window": "1h"}, "использование памяти хоста за 1 ч"))
    if re.search(r"too many clients|remaining connection slots are reserved", text):
        add("db_connections_exhausted", 0.8, "PostgreSQL отклоняет соединения: too many clients",
            _check("postgres.activity", {"asset_id": db}, "соединения PostgreSQL против лимита"))
    if family == "container" and re.search(
            r"could not connect to server|connection to .*5432.* refused|dial tcp .*:5432", text):
        add("dependency_unavailable", 0.75, "зависимость (БД) недоступна для контейнера",
            _check("logs.search", {"asset_id": asset, "query": "could not connect to server",
                                   "window": "1h"}, "ошибки подключения к зависимости"))
    if "no space left on device" in text:
        add("host_disk_full", 0.85, "no space left on device",
            _check("linux.disk.usage", {"asset_id": asset}, "заполнение файловых систем хоста"))
    if re.search(r"pull access denied|manifest unknown|error pulling image", text):
        add("image_pull_failure", 0.85, "образ контейнера не загружается",
            _check("logs.search", {"asset_id": asset, "query": "pull access denied",
                                   "window": "1h"}, "ошибки загрузки образа"))
    if re.search(r"action=deny|policy.{0,20}deny|denied by policy", text):
        add("firewall_policy_block", 0.6, "трафик отбрасывается политикой МЭ")
    if re.search(r"stopped by user|manual stop|docker stop|container stop requested", text):
        add("manual_stop" if family == "container" else n["stopped"], 0.8,
            "контейнер остановлен вручную/оператором",
            _check("events.list", {"asset_id": asset, "window": "1h"}, "события остановки"))
    if re.search(r"logrotate.{0,80}(error|skipping)|error: skipping", text):
        add("log_rotation_failure", 0.8, "logrotate не ротирует журналы",
            _check("logs.search", {"asset_id": asset, "query": "logrotate", "window": "24h"},
                   "журнал logrotate за сутки"))
    elif re.search(r"logrotate.{0,60}rotating pattern", text) and "error" not in text:
        add("application_log_growth", 0.7, "logrotate работает, журналы растут быстрее ротации")
        add("log_rotation_failure", 0.0, "logrotate отработал без ошибок", supports=False)
    if re.search(r"archive command failed|archiver process .* failed|archive_command", text):
        add("wal_archiving_failure", 0.85, "archive_command завершается ошибкой",
            _check("logs.search", {"asset_id": db, "query": "archive command failed",
                                   "window": "6h"}, "ошибки архивирования WAL"))
    if re.search(r"deadlock detected|lock timeout|canceling statement due to lock", text):
        add("db_lock_contention", 0.75, "конкуренция блокировок в PostgreSQL",
            _check("postgres.activity", {"asset_id": db, "min_duration_s": 30},
                   "сессии в ожидании блокировок"))
    if family != "disk" and re.search(r"segfault|panic:|traceback \(most recent", text):
        add(n["stopped"], 0.6, "аварийное завершение приложения")
    return out


def evaluate(obs: Observation, family: Family, *, db_asset: str | None = None) -> list[Signal]:
    """Сигналы одного ответа инструмента."""
    tool, data, params = obs.tool, obs.data, obs.params
    asset = params.get("asset_id")
    n = _names(family)
    out: list[Signal] = []
    if tool == "docker.container.inspect":
        st = data.get("state", {}) or {}
        status = st.get("status")
        oom = bool(st.get("oom_killed"))
        code = st.get("exit_code")
        restarts = int(st.get("restart_count") or 0)
        container = data.get("container") or params.get("container")
        cid = params.get("container")
        if status == "running" and st.get("health") in (None, "none", "healthy") \
                and restarts < 3:
            for kind in ("oom", "stopped", "loop", "config"):
                out.append(Signal(cause=n[kind], confidence=0.0, supports=False,
                                  statement=f"контейнер {container} работает"))
            if family == "container":
                out.append(Signal(cause="manual_stop", confidence=0.0, supports=False))
        elif status in ("exited", "dead"):
            if oom:
                out.append(Signal(cause=n["oom"], confidence=0.85,
                                  statement=f"{container}: exited {code}, oom_killed",
                                  check=_container_checks(family, asset, cid, "oom")))
            elif code in (0, 143):
                if family == "container":
                    out.append(Signal(cause="manual_stop", confidence=0.55,
                                      statement=f"{container}: штатный выход {code}",
                                      check=_check("events.list",
                                                   {"asset_id": asset, "window": "1h"},
                                                   "события остановки")))
                else:
                    out.append(Signal(cause=n["stopped"], confidence=0.75,
                                      statement=f"{container}: остановлен (exit {code})",
                                      check=_container_checks(family, asset, cid, "stopped")))
            else:
                conf = 0.7 if family == "web" else 0.5
                out.append(Signal(cause=n["stopped"], confidence=conf,
                                  statement=f"{container}: exited {code}",
                                  check=_container_checks(family, asset, cid, "stopped")))
            if restarts >= 5 and family == "web":
                out.append(Signal(cause=n["loop"], confidence=0.55,
                                  statement=f"{container}: {restarts} перезапусков"))
        elif status == "restarting" or restarts >= 5:
            out.append(Signal(cause=n["loop"], confidence=0.7 if family == "web" else 0.55,
                              statement=f"{container}: цикл перезапусков ({restarts})",
                              check=_container_checks(family, asset, cid, "stopped")))
        elif status == "created":
            out.append(Signal(cause="image_pull_failure", confidence=0.5,
                              statement=f"{container}: создан, но не запущен"))
    elif tool in ("logs.search", "events.list", "linux.service.status"):
        out.extend(text_signals(_text(data), family, asset, db_asset))
        if tool == "logs.search" and not data.get("entries"):
            out.extend(_empty_search_refutes(str(params.get("query", "")), family))
        if tool == "linux.service.status" and family == "web":
            if data.get("active_state") == "failed":
                out.append(Signal(cause="upstream_service_failed", confidence=0.8,
                                  statement=f"{data.get('unit')}: failed",
                                  check=_check("linux.service.status",
                                               {"asset_id": asset, "unit": data.get("unit")},
                                               "состояние systemd-юнита")))
            elif data.get("active_state") == "active":
                out.append(Signal(cause="upstream_service_failed", confidence=0.0,
                                  supports=False, statement=f"{data.get('unit')}: active"))
    elif tool == "postgres.activity":
        total = int(data.get("total_connections") or 0)
        mx = int(data.get("max_connections") or 0) or 1
        ratio = total / mx
        if ratio >= 0.95:
            out.append(Signal(cause="db_connections_exhausted", confidence=0.7,
                              statement=f"соединения {total}/{mx}",
                              check=_check("logs.search", {"asset_id": asset,
                                                           "query": "too many clients",
                                                           "window": "30m"},
                                           "ошибки 'too many clients' в журнале")))
        elif ratio <= 0.8:
            out.append(Signal(cause="db_connections_exhausted", confidence=0.0, supports=False,
                              statement=f"соединения {total}/{mx} — запас есть"))
        sessions = data.get("sessions", []) or []
        locks = [s for s in sessions if (s.get("wait_event_type") or "") == "Lock"
                 and float(s.get("duration_s") or 0) >= 30]
        if len(locks) >= 3:
            out.append(Signal(cause="db_lock_contention", confidence=0.7,
                              statement=f"{len(locks)} сессий ждут блокировок ≥30 с",
                              check=_check("logs.search", {"asset_id": asset,
                                                           "query": "lock timeout",
                                                           "window": "30m"},
                                           "ошибки блокировок в журнале PostgreSQL")))
        elif family == "web":
            out.append(Signal(cause="db_lock_contention", confidence=0.0, supports=False,
                              statement="ожиданий блокировок нет"))
    elif tool == "fortigate.policy.status":
        policies = data.get("policies", []) or []
        blocking = [p for p in policies if (p.get("action") == "deny"
                                            and p.get("status") == "enable"
                                            and int(p.get("hit_count") or 0) >= 100)]
        disabled = [p for p in policies if p.get("action") == "accept"
                    and p.get("status") == "disable"]
        if blocking or disabled:
            names = ", ".join(str(p.get("name") or p.get("policy_id"))
                              for p in blocking + disabled)
            out.append(Signal(cause="firewall_policy_block", confidence=0.7,
                              statement=f"политики блокируют трафик: {names}",
                              check=_check("fortigate.policy.status", {"asset_id": asset},
                                           "статус и счётчики политик МЭ")))
        else:
            out.append(Signal(cause="firewall_policy_block", confidence=0.0, supports=False,
                              statement="разрешающие политики активны, deny без срабатываний"))
    elif tool == "linux.disk.usage":
        out.extend(_disk_signals(data, family, asset, params))
    elif tool == "metrics.query":
        out.extend(_metric_signals(data, family, asset))
    return out


def _empty_search_refutes(query: str, family: Family) -> list[Signal]:
    """Целевой поиск по журналу без совпадений опровергает соответствующую причину."""
    n = _names(family)
    q = query.lower()
    table = [
        ("too many clients", "db_connections_exhausted"),
        ("memory cgroup out of memory", n["oom"]),
        ("out of memory: killed", "host_out_of_memory"),
        ("permission denied", n["config"]), ("yaml", n["config"]),
        ("unknown directive", n["config"]), ("invalid configuration", n["config"]),
        ("could not connect to server", "dependency_unavailable"),
        ("pull access denied", "image_pull_failure"),
        ("archive command failed", "wal_archiving_failure"),
        ("lock timeout", "db_lock_contention"),
    ]
    return [Signal(cause=cause, confidence=0.0, supports=False,
                   statement=f"в журнале нет совпадений для '{query}'")
            for phrase, cause in table if phrase == q]


def _disk_signals(data: dict[str, Any], family: Family, asset: str | None,
                  params: dict[str, Any]) -> list[Signal]:
    out: list[Signal] = []
    fss = data.get("filesystems", []) or []
    if not fss:
        return out
    worst = max(fss, key=lambda f: float(f.get("use_percent") or 0))
    use = float(worst.get("use_percent") or 0)
    inodes = max(float(f.get("inodes_use_percent") or 0) for f in fss)
    if family != "disk":
        if use >= 98:
            out.append(Signal(cause="host_disk_full", confidence=0.7,
                              statement=f"{worst.get('mount')}: {use}%",
                              check=_check("linux.disk.usage", {"asset_id": asset},
                                           "заполнение файловых систем")))
        return out
    if inodes >= 95 and use < 85:
        out.append(Signal(cause="inode_exhaustion", confidence=0.85,
                          statement=f"inodes {inodes}% при занятости {use}%",
                          check=_check("linux.disk.usage", {"asset_id": asset},
                                       "inodes по файловым системам")))
        return out
    top = sorted(data.get("top_dirs", []) or [], key=lambda d: -int(d.get("size_bytes") or 0))
    if use < 85 or not top:
        return out
    path = str(top[0].get("path", ""))
    size_gb = int(top[0].get("size_bytes") or 0) / 1e9
    stmt = f"{worst.get('mount')} {use}%, крупнейший каталог {path} ({size_gb:.1f} GB)"
    disk_check = _check("linux.disk.usage", {"asset_id": asset, "mount": worst.get("mount")},
                        "крупнейшие каталоги на заполненной ФС")
    if "pg_wal" in path:
        out.append(Signal(cause="wal_archiving_failure", confidence=0.7, statement=stmt,
                          check=_check("logs.search", {"asset_id": asset,
                                                       "query": "archive command failed",
                                                       "window": "6h"},
                                       "ошибки архивирования WAL")))
    elif "postgres" in path or "pgsql" in path:
        out.append(Signal(cause="database_bloat", confidence=0.7, statement=stmt,
                          check=disk_check))
    elif path.startswith("/var/lib/docker"):
        out.append(Signal(cause="docker_images_accumulation", confidence=0.75, statement=stmt,
                          check=disk_check))
    elif "crash" in path or "core" in path:
        out.append(Signal(cause="core_dumps_accumulation", confidence=0.8, statement=stmt,
                          check=disk_check))
    elif "backup" in path:
        out.append(Signal(cause="backup_files_left", confidence=0.75, statement=stmt,
                          check=disk_check))
    elif path.startswith("/var/log") or "/log" in path:
        out.append(Signal(cause="application_log_growth", confidence=0.6, statement=stmt,
                          check=_check("metrics.query", {"asset_id": asset,
                                                         "metric": "node_disk_used_percent",
                                                         "window": "24h"},
                                       "динамика заполнения диска за сутки")))
        out.append(Signal(cause="log_rotation_failure", confidence=0.55, statement=stmt,
                          check=_check("logs.search", {"asset_id": asset, "query": "logrotate",
                                                       "window": "24h"},
                                       "журнал logrotate за сутки")))
    del params
    return out


def _metric_signals(data: dict[str, Any], family: Family, asset: str | None) -> list[Signal]:
    metric = str(data.get("metric", ""))
    values = [float(p[1]) for s in data.get("series", []) or [] for p in s.get("points", [])
              if isinstance(p, list) and len(p) == 2 and p[1] is not None]
    if not values:
        return []
    peak = max(values)
    out: list[Signal] = []
    if metric == "node_memory_used_percent":
        if peak >= 95:
            out.append(Signal(cause="host_out_of_memory", confidence=0.75 if family == "container"
                              else 0.6, statement=f"память хоста до {peak:.0f}%",
                              check=_check("logs.search", {"asset_id": asset,
                                                           "query": "out of memory: killed",
                                                           "window": "1h"},
                                           "глобальный OOM в журнале ядра")))
        elif peak < 80:
            out.append(Signal(cause="host_out_of_memory", confidence=0.0, supports=False,
                              statement=f"память хоста не выше {peak:.0f}%"))
    elif metric == "node_disk_used_percent" and family == "disk" and len(values) >= 2:
        growth = values[-1] - values[0]
        if growth >= 10:
            out.append(Signal(cause="application_log_growth", confidence=0.7,
                              statement=f"рост заполнения {growth:.0f} п.п. за окно"))
        elif growth < 3:
            out.append(Signal(cause="application_log_growth", confidence=0.0, supports=False,
                              statement=f"заполнение стабильно ({growth:+.0f} п.п.): "
                                        "журналы не растут, не удаляются старые"))
    elif metric == "container_restarts_total" and len(values) >= 2 \
            and values[-1] - values[0] >= 3:
        out.append(Signal(cause=_names(family)["loop"], confidence=0.6,
                          statement="частые перезапуски контейнера"))
    return out


def aggregate(observations: list[Observation], family: Family, *,
              db_asset: str | None = None) -> dict[str, CauseAgg]:
    causes: dict[str, CauseAgg] = {}
    for obs in observations:
        for sig in evaluate(obs, family, db_asset=db_asset):
            agg = causes.setdefault(sig.cause, CauseAgg(cause=sig.cause))
            if sig.supports:
                if obs.evidence_id not in agg.supporting:
                    agg.supporting.append(obs.evidence_id)
                # независимые подтверждения немного повышают уверенность
                agg.confidence = max(agg.confidence, sig.confidence) if len(
                    agg.supporting) == 1 else min(0.95, max(agg.confidence, sig.confidence) + 0.05)
                if sig.statement:
                    agg.statements.append(sig.statement)
                if sig.check and sig.check not in agg.checks:
                    agg.checks.append(sig.check)
            elif obs.evidence_id not in agg.refuting:
                agg.refuting.append(obs.evidence_id)
                if sig.statement:
                    agg.statements.append(sig.statement)
    for agg in causes.values():
        if agg.refuting and agg.supporting:
            agg.confidence = max(0.05, round(agg.confidence - 0.2, 4))
    return causes
