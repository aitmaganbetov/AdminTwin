# Observability, инциденты, RCA, Discovery — подключение (Этап 1, MVP)

Пакеты: `services/telemetry` (M05), `services/incidents` (M06 + инцидентная сторона M07),
`services/discovery` (M03). Контракты — `docs/api/stage1-contracts.md` §3–4. Миграция —
`db/migrations/0003_observability.{up,down}.sql` (применять после 0001; RLS ENABLE + FORCE на всех таблицах).

`internal/app/app.go` эти модули не подключает — это зона интегратора. Ниже — что добавить.

## Конструкторы

| Что | Конструктор | Примечание |
|---|---|---|
| Хранилище телеметрии (dev/MVP) | `telemetry.NewMemoryStore(telemetry.Limits{}, retention)` | кольцевые буферы на tenant, ретенция §9.1 |
| Хранилище (production) | `telemetry.Composite{Metrics: &telemetry.VictoriaMetrics{URL: vm}, Logs: &telemetry.Loki{URL: loki}, Events: mem}` | события — пока в памяти (таблица `events` готова) |
| Конвейер телеметрии | `tel := telemetry.NewService(store, a.Inventory)` | `httpapi.Module`; правила порогов и журналов включены |
| Read tools | `tel.RegisterTools(a.Tools)` | `metrics.query`, `logs.search` (класс ≥ confidential), `events.list` |
| Sink для коннекторов | `tel.AsSink()` | `telemetry.Sink` через тот же конвейер (валидация, правила, корреляция) |
| Syslog | `&telemetry.SyslogReceiver{Addr, Resolver: telemetry.NewInventoryResolver(a.Inventory, tenantIDs), Ingest: tel}` + `Start(ctx)` | UDP+TCP, RFC 3164/5424 |
| Инциденты | `inc := incidents.New(incidents.NewMemoryRepo(), a.Inventory, a.Audit, rca, incidents.Config{AutoTriage: ...})` | `httpapi.Module`, `telemetry.EventSubscriber` |
| Инциденты (PostgreSQL) | `incidents.NewPGRepo(pool)` | `pool` — `*pgxpool.Pool` или `*pgx.Conn` (интерфейс `incidents.DB`) |
| Оркестратор | `incidents.NewOrchestratorClient(url, serviceToken)` | реализует `incidents.RCAStarter` |
| Discovery | `discovery.New(discovery.NewMemoryRepo(), a.Inventory, a.Audit, a.Evidence, vaultCreds, discovery.Config{}, collectors...)` | `httpapi.Module`; `a.Evidence` реализует `discovery.EvidenceSink` |

## Пример сборки (internal/app/app.go, после создания `a.Tools`)

```go
store := telemetry.Store(telemetry.NewMemoryStore(telemetry.Limits{}, retention))
if vm, loki := os.Getenv("ADMINTWIN_VICTORIAMETRICS_URL"), os.Getenv("ADMINTWIN_LOKI_URL"); vm != "" && loki != "" {
	store = telemetry.Composite{Metrics: &telemetry.VictoriaMetrics{URL: vm}, Logs: &telemetry.Loki{URL: loki}, Events: telemetry.NewMemoryStore(telemetry.Limits{}, retention)}
}
tel := telemetry.NewService(store, a.Inventory)
tel.ServiceToken = os.Getenv("ADMINTWIN_SERVICE_TOKEN")
if err := tel.RegisterTools(a.Tools); err != nil { return nil, err }

var starter incidents.RCAStarter
if u := os.Getenv("ADMINTWIN_ORCHESTRATOR_URL"); u != "" {
	c, err := incidents.NewOrchestratorClient(u, os.Getenv("ADMINTWIN_SERVICE_TOKEN"))
	if err != nil { return nil, err }
	starter = c
}
inc := incidents.New(incidents.NewMemoryRepo(), a.Inventory, a.Audit, starter,
	incidents.Config{AutoTriage: os.Getenv("ADMINTWIN_INCIDENT_AUTO_TRIAGE") == "true"})
inc.ServiceToken = tel.ServiceToken
tel.Subscriber = inc

resolver := telemetry.NewInventoryResolver(a.Inventory, a.TenantIDs) // TenantIDs — см. «Что нужно от интегратора»
disc := discovery.New(discovery.NewMemoryRepo(), a.Inventory, a.Audit, a.Evidence, vaultCreds, discovery.Config{} /*, connectors... */)
disc.OnCMDBChange = resolver.Invalidate

a.Server.Modules = append(a.Server.Modules, tel, inc, disc)

if addr := os.Getenv("ADMINTWIN_SYSLOG_ADDR"); addr != "" { // по умолчанию выключен
	sys := &telemetry.SyslogReceiver{Addr: addr, Resolver: resolver, Ingest: tel}
	if err := sys.Start(ctx); err != nil { return nil, err }
}
```

Остановка: `disc.Wait()` (задания discovery), `sys.Close()`.

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `ADMINTWIN_SERVICE_TOKEN` | токен сервисов; модули дополнительно сверяют `X-AdminTwin-Service-Token` (constant-time) для ingest и `POST /incidents/{id}/rca`; им же ядро подписывает вызовы оркестратора | пусто — проверка только в gateway |
| `ADMINTWIN_ORCHESTRATOR_URL` | `POST {url}/v1/tasks` (kind `rca`) | пусто — RCA не запускается, `rca.status=failed` с пояснением |
| `ADMINTWIN_SYSLOG_ADDR` | адрес syslog UDP+TCP, например `:5514` | выключен |
| `ADMINTWIN_VICTORIAMETRICS_URL`, `ADMINTWIN_LOKI_URL` | внешние хранилища метрик/журналов | in-memory |
| `ADMINTWIN_RETENTION_METRICS_RAW`, `_LOGS`, `_SYSLOG`, `_EVENTS` | ретенция горячего слоя (`telemetry.RetentionFromEnv(os.Getenv)`), формат `15d` | 15d / 14d / 30d / 395d (§9.1) |
| `ADMINTWIN_INCIDENT_AUTO_TRIAGE` | авто-triage инцидентов severity ≥ high (RCA стартует сразу, §17.1 «алерт → RCA < 30 с») | `false` (triage делает человек, C.7) |

## Поведение (кратко)

- **Ingest** (`POST /api/v1/telemetry/{samples,logs,events}`) — только `Actor-Kind: service`. Tenant берётся из
  идентичности; запись с другим `tenant_id` или активом чужого tenant — `422`. ID событий назначает ядро
  (внешний id → `labels.external_id`).
- **Правила**: `node_disk_used_percent` ≥ 90 → high, ≥ 95 → critical; `container_up == 0` → high;
  `http_5xx_rate` > 5 (**проценты 0..100**) → high; `pg_connections_total / pg_connections_max` > 0.9 → high;
  журналы: nginx `upstream timed out | connect() failed … upstream | no live upstreams | 502` → `http_5xx`
  (`labels.status=502`), `No space left on device` → `disk_usage` critical, OOM killer → `oom_kill`.
  Повторы подавляются на 5 мин (кроме эскалации). Заголовок события — шаблон правила, не текст журнала.
- **Syslog**: актив и tenant — только по IP источника (`Connection.Address`, IP-литерал); поле hostname не
  используется. Неизвестный или неоднозначный (адрес в двух tenant) источник отбрасывается, счётчик
  `SyslogReceiver.Stats().DroppedUnknown`.
- **Корреляция**: тот же fingerprint в окне 30 мин — дедупликация; события severity ≥ high на том же активе или
  на активах, связанных blast radius ≤ 2 (в любую сторону), в окне 10 мин — один инцидент; иначе severity ≥ high
  создаёт инцидент. Owner = owner актива; задержки `latency.event_to_created_ms/event_to_assigned_ms`.
- **Переходы** — люди с ролями operator / engineer / it_manager / tenant_admin; AI-агенты и сервисы не меняют
  состояние. `mitigated` требует `evidence_ref`; `resolved` при severity ≥ high — постмортем (и CHECK в БД).
  На `triaged` запускается RCA; ошибка оркестратора видна в `rca.note`, triage не откатывается.
- **RCA** (`POST /{id}/rca`) — только `service` + `Actor: orchestrator`; строгая схема (неизвестные поля — 400),
  `task_id` обязан совпадать с активной задачей (иначе 409). Выводы — гипотезы: статус инцидента не меняется;
  `completed` без evidence у лучшей гипотезы понижается до `uncertain`. `proposed_changes` → timeline `change_linked`.
- **Оценка** → кандидат golden dataset (`ai/evals/eval-case.schema.json`), экспорт JSONL:
  `GET /api/v1/incidents/golden-candidates` (tenant_admin, it_manager). Сигналы — только ссылки на события.
- **Discovery**: scope создаёт и утверждает Tenant Admin (автор ≠ согласующий); диапазоны не шире /16 (IPv6 /48),
  срок ≤ 366 дн. Задание без активного scope, с целью вне диапазонов или с неразрешённым методом —
  `403 policy-denied` + аудит `discovery.job_rejected`. Цели — только IP. `max_sessions` и `pps` из scope.
  Reconciliation: new / changed / missing / unchanged по (type, address) и (type, name); confidence < 0.8 —
  только после `POST /jobs/{id}/confirm`. Environment / criticality / owner / data_class discovery не выставляет
  (классификация неполная → execution заблокирован). Evidence задания — `a.Evidence.Store(..., "compliance", "discovery_job:<id>", ...)`.

## Что нужно от интегратора / смежных модулей

1. **api-gateway**: проверка `X-AdminTwin-Service-Token` для `Actor-Kind service|ai_agent` (сейчас `DevHeaderAuth`
   принимает `service` без токена). Модули сверяют токен сами, если задан `ServiceToken`.
2. **App**: экспортируемый список tenant (`func (a *App) TenantIDs() []string`) для `InventoryResolver`
   — либо метод `inventory.Repository` для поиска актива по адресу на уровне платформы.
3. **go.mod**: `github.com/jackc/pgx/v5` теперь импортируется напрямую (`services/incidents/postgres.go`) —
   `go mod tidy` снимет пометку `// indirect`. Для `pgxpool` нужен `github.com/jackc/puddle/v2` в go.sum.
4. **Change Coordinator**: при создании change с `incident_id` вызывать `inc.LinkChange(ctx, tenant, incidentID, changeID, actor)`.
5. **Vault**: реализация `discovery.CredentialSource` (read-only учётки по `credential_ref`).
