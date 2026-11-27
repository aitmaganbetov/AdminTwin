# Контракты Этапа 1 (MVP): ядро ↔ модули ↔ оркестратор ↔ UI

Нормативно для параллельной разработки. Все пути — относительно ядра (`admintwin-core`, :8080).
Ошибки — RFC 9457 (`pkg/problem`). Все ответы tenant-scoped; объект другого tenant неотличим от
отсутствующего (`404`).

## 0. Общие правила

- **Модули Go** регистрируют маршруты через `pkg/httpapi.Module` (`Routes(r *httpapi.Router)`); `api-gateway`
  не правится. Хелперы: `httpapi.WriteJSON`, `httpapi.Fail`, `httpapi.Decode`, `httpapi.RequireAny`, `httpapi.RequireHuman`.
- **Сборка** (`internal/app/app.go`) — зона интегратора. Модуль предоставляет конструктор и тест, который
  подключает модуль так: `a, _ := app.New(cfg); a.Server.Modules = append(a.Server.Modules, m)`.
- **Миграции**: `db/migrations/0002_*` — ядро (интегратор), `0003_*` — observability/incidents/discovery.
- **Идентичность**:
  - человек — OIDC JWT `Authorization: Bearer` (ядро; в dev — заголовки `X-AdminTwin-*`);
  - сервис (оркестратор, сборщики) — `X-AdminTwin-Service-Token: <ADMINTWIN_SERVICE_TOKEN>` **плюс**
    заголовки идентичности `X-AdminTwin-Tenant`, `X-AdminTwin-Actor`, `X-AdminTwin-Actor-Kind` (`ai_agent` или
    `service`). Без валидного токена заголовки идентичности игнорируются. Сравнение токена — constant-time.
  - Оркестратор, действуя от имени агента, передаёт `X-AdminTwin-Actor: <agent id>` (`devops-engineer`, ...),
    `X-AdminTwin-Actor-Kind: ai_agent`. От своего имени (запись результатов RCA) — `Actor-Kind: service`,
    `Actor: orchestrator`.

## 1. Tool Service (готово, `services/tool-service`)

`POST /api/v1/tools/{name}` body `{"input": {...}}` → `200 {"tool","version","data_class","data"}`.
`data` строго соответствует `output_schema` из `ai/tools/read/{name}.json`; иначе ответ не отдаётся (500).
Обработчики регистрируют модули: `toolsvc.Service.Register(name, toolsvc.Handler)`.
Встроенные: `asset.get`, `topology.blast_radius`. Регистрируют:

| tool | кто | источник |
|---|---|---|
| `metrics.query`, `logs.search`, `events.list` | telemetry | `telemetry.Query` |
| `docker.container.inspect` | connectors/docker | Docker Engine API |
| `linux.service.status`, `linux.disk.usage` | connectors/linux | SSH read-only (argv allowlist) |
| `postgres.activity` | connectors/db | PostgreSQL read-only |
| `fortigate.policy.status` | connectors/network | FortiOS REST API (read-only токен) |

Регулярные выражения в JSON Schema — только RE2-совместимые (без lookahead): контракты компилируются и в Go, и в Python.

## 2. Коннекторы и Vault (`connectors/*`, `services/execution-gateway/vault`)

- Движки исполнения реализуют `gateway.Engine` для `docker_api` (restart через Engine API) и `ssh_argv`
  (argv без shell; `systemctl restart <unit>`), `builtin` → `logs_rotate_cleanup` поверх SSH с allowlist каталогов и dry-run.
- `gateway.Facts` реализуется композитом, выбирающим коннектор по `Asset.Connection.Method`.
- `gateway.CredentialBroker` — Vault/OpenBao (KV v2), путь из `Asset.Connection.CredentialRef`,
  TTL аренды ≤ timeout runbook + 60 с; при недоступности Vault — ошибка (исполнения невозможны, §17.2).
- `discovery.Collector` (контракт в `services/discovery/collector.go`) для `ssh`, `docker_api`, `postgres`, `fortigate_api`.
- Сборщики метрик пишут в `telemetry.Sink`: `node_cpu_usage_percent`, `node_memory_used_percent`,
  `node_disk_used_percent{mount}`, `container_up{container}`, `container_restarts_total{container}`,
  `pg_connections_total`, `pg_connections_max`, `pg_replication_lag_bytes{client}`, `http_5xx_rate` (из журналов nginx).
- SSH: только ключ, **обязательная проверка host key** (`Connection.HostKey`), read-only команды из allowlist.

## 3. Observability, инциденты, discovery

### Телеметрия
| Method | Path | Тело / параметры | Ответ |
|---|---|---|---|
| POST | `/api/v1/telemetry/samples` | `{"samples":[Sample]}` (service) | `202 {"accepted":n}` |
| POST | `/api/v1/telemetry/logs` | `{"logs":[LogRecord]}` (service) | `202` |
| POST | `/api/v1/telemetry/events` | `{"events":[Event]}` (service или внешний webhook) | `202 {"accepted":n,"incidents":[id]}` |
| GET | `/api/v1/telemetry/metrics` | `asset_id, metric, window=15m, step=1m` | `{"asset_id","metric","window","series":[{"labels","points":[[ts,v]]}]}` |
| GET | `/api/v1/telemetry/logs` | `asset_id, contains, min_severity, window, limit` | `{"entries":[LogRecord],"truncated":bool}` |
| GET | `/api/v1/events` | `asset_id, window, limit` | `{"events":[Event]}` |

Syslog-приёмник UDP/TCP (RFC 3164/5424), адрес `ADMINTWIN_SYSLOG_ADDR` (по умолчанию выключен);
источник сопоставляется с активом по `Connection.Address`; tenant — по активу (неизвестный источник отбрасывается
со счётчиком). Типы — `services/telemetry/types.go`.

### Инциденты (M06, C.7)
`new → triaged → investigating → mitigated → resolved → closed`, `reopened` (из resolved/closed → investigating).

| Method | Path | Назначение |
|---|---|---|
| GET | `/api/v1/incidents?status=&severity=` | список |
| POST | `/api/v1/incidents` | ручное создание `{"title","severity","asset_ids":[],"description"}` |
| GET | `/api/v1/incidents/{id}` | инцидент с timeline и RCA |
| POST | `/api/v1/incidents/{id}/transitions` | `{"to","reason","evidence_ref"?}`; `mitigated` требует evidence_ref; `resolved` для severity ≥ high требует постмортем |
| POST | `/api/v1/incidents/{id}/analyze` | запустить RCA (создаёт задачу оркестратора) → `202 {"task_id"}` |
| POST | `/api/v1/incidents/{id}/rca` | **только service `orchestrator`**: результат RCA (см. ниже) |
| POST | `/api/v1/incidents/{id}/feedback` | `{"correct":bool,"actual_cause"?,"rating":1..5,"comment"?}` → кандидат в golden dataset |
| POST | `/api/v1/incidents/{id}/postmortem` | `{"summary","root_cause","corrective_actions":[...]}` |

Инцидент:
```json
{"id","tenant_id","title","severity","status","owner","asset_ids":[],"event_ids":[],"fingerprint",
 "created_at","updated_at","triaged_at","assigned_at",
 "timeline":[{"at","actor","kind","text","ref"}],
 "rca":{"status":"not_started|running|completed|uncertain|failed","task_id","hypotheses":[
    {"cause","confidence","supporting":[{"fact","evidence_id"}],"refuting":[...],"next_checks":[...]}],
    "conclusion","uncertainty_check","agents":[],"cost_usd","proposed_changes":[change_id]},
 "postmortem":null,"feedback":null,"slo_impact":null}
```
Корреляция: события с одинаковым `fingerprint` в окне 30 мин — дедупликация; события severity ≥ high на одном
активе или на активах, связанных в графе (blast radius ≤ 2), в окне 10 мин — один инцидент. Создание и
назначение owner (owner актива) — < 30 с от события (§21). На `triaged` автоматически запускается RCA (C.7).

Ядро → оркестратор: `POST {ADMINTWIN_ORCHESTRATOR_URL}/v1/tasks` (см. §4), `kind:"rca"`.

Оркестратор → ядро: `POST /api/v1/incidents/{id}/rca`
```json
{"task_id","status":"completed|uncertain|failed","hypotheses":[...как выше...],"conclusion","uncertainty_check",
 "agents":["network-engineer","devops-engineer","dba-engineer"],"cost_usd":0.12,"proposed_changes":["<change id>"]}
```

### Discovery (M03, C.9)
| Method | Path | Назначение |
|---|---|---|
| GET/POST | `/api/v1/discovery/scopes` | Scope Document `{"name","ranges":["10.0.0.0/24"],"methods":["ssh"],"limits":{"max_sessions":4,"pps":50},"responsible","valid_until"}` |
| POST | `/api/v1/discovery/scopes/{id}/approve` | Tenant Admin; без утверждения scope не действует |
| POST | `/api/v1/discovery/jobs` | `{"scope_id","targets":[{"address","method","port"?,"credential_ref","host_key"?}]}`; без активного scope или вне диапазона — `403 policy-denied` |
| GET | `/api/v1/discovery/jobs/{id}` | статус, найдено new/changed/missing |
| POST | `/api/v1/discovery/jobs/{id}/confirm` | `{"keys":[...]}` подтверждение объектов с низким confidence → CMDB |

## 4. Оркестратор (Python, `ai/`, сервис `admintwin-orchestrator`, :8090)

Доступ только с `X-AdminTwin-Service-Token`; tenant и пользователь — из заголовков, выставленных ядром.

| Method | Path | Назначение |
|---|---|---|
| POST | `/v1/tasks` | `{"kind":"rca|chat|diagnose","tenant_id","incident_id"?,"objective","scope":{"asset_ids":[]},"requested_by"}` → `202 {"task_id","status"}` |
| GET | `/v1/tasks?tenant_id=` / `/v1/tasks/{id}` | дерево задач, агенты, факты, стоимость |
| POST | `/v1/tasks/{id}/cancel` | отмена |
| POST | `/v1/tasks/{id}/input` | ответ на `waiting_input` `{"text"}` |
| GET | `/v1/tasks/{id}/events` | **SSE**: `event: <тип §7 | tool_call | fact | hypothesis | cost>`, `data: JSON`; поддержка `Last-Event-ID` |
| POST | `/v1/chat/sessions` | `{"tenant_id","incident_id"?}` → `{"session_id"}` |
| POST | `/v1/chat/sessions/{id}/messages` | `{"text"}` → создаёт/дополняет задачу |
| GET | `/v1/chat/sessions/{id}/events` | SSE |
| POST | `/v1/kill` | `{"tenant_id"? , "platform":bool}` — отмена всех задач < 5 с |
| GET | `/healthz` | здоровье, состояние провайдеров |

Ядро публикует для UI прокси (с проверенной идентичностью пользователя):
`/api/v1/agent-tasks[...]` → `/v1/tasks[...]`, `/api/v1/chat/sessions[...]` → `/v1/chat/sessions[...]`.
Kill switch ядра вызывает `POST /v1/kill`.

Read tools оркестратора вызывают `POST /api/v1/tools/{name}`; propose — `POST /api/v1/changes`.

## 5. Web UI (`apps/web`, Next.js)

Разделы MVP: Command Center, Incidents (+ RCA, timeline, feedback), Agent Collaboration (SSE), Changes & Approvals,
Assets/CMDB, Live Topology, Runbooks, AI Providers & Budgets (read-only), Audit (+ integrity), Platform Health,
Settings (kill switch). i18n ru/kk/en, тёмная/светлая тема, WCAG 2.2 AA.
UI ходит только в `/api/v1/*` ядра (rewrite в `next.config`), токен пользователя — OIDC (PKCE); в dev — форма
выбора dev-идентичности, передаваемой заголовками `X-AdminTwin-*`.
