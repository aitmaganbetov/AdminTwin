# Эксплуатация AdminTwin

Инструкции для администраторов площадки (редакция Enterprise). Платформа не стоит в критическом пути production:
её остановка не влияет на наблюдаемую инфраструктуру (§17.3).

## 1. Компоненты

| Компонент | Процесс | Порт | Обязателен |
|---|---|---|---|
| Ядро (API, Change Coordinator, Policy, Approval, Execution Gateway, Audit, реестры) | `admintwin-core` | 8080, метрики 9464 | да |
| AI-оркестратор (агенты, RCA, ChatOps) | `admintwin-orchestrator` | 8090 | нет — без него AI-функции недоступны, остальное работает |
| Web UI | `admintwin-web` | 3000 | нет |
| PostgreSQL 16+ | — | 5432 | да (HA для 99.9%) |
| Vault / OpenBao | — | 8200 | для исполнений (без него — принудительно только чтение, §17.2) |
| NATS JetStream | — | 4222 | для шины агентов (без него — in-process) |
| VictoriaMetrics / Loki | — | — | для долгосрочной телеметрии |

## 2. Секреты

Ни один секрет не хранится в репозитории или образах. Генерация:

```bash
openssl rand -base64 32   # ADMINTWIN_AUDIT_SIGNING_KEY — seed Ed25519 подписи checkpoint'ов аудита
openssl rand -base64 32   # ADMINTWIN_PII_MASTER_KEY — KEK для ключей ПДн tenant (crypto-shredding)
openssl rand -base64 48   # ADMINTWIN_SERVICE_TOKEN — общий секрет ядро ↔ оркестратор/сборщики (≥ 32 символов)
```

Храните их в Vault и доставляйте в процессы через Vault Agent / External Secrets. В режиме БД ядро **не стартует**
без `ADMINTWIN_AUDIT_SIGNING_KEY` и `ADMINTWIN_PII_MASTER_KEY` (кроме dev-режима).

> **Потеря `ADMINTWIN_PII_MASTER_KEY` равна уничтожению всех ПДн в аудите** (цепочка останется верифицируемой).
> Делайте резервную копию KEK отдельно от резервных копий БД.

Публичный ключ подписи аудита передайте аудиторам: им проверяются checkpoint'ы. При ротации ключа подписи
сохраняйте архив прежних публичных ключей — checkpoint'ы, подписанные до ротации, проверяются старым ключом.

## 3. Аутентификация (OIDC)

```
ADMINTWIN_OIDC_ISSUER=https://sso.example.kz/realms/admintwin
ADMINTWIN_OIDC_AUDIENCE=admintwin
```

Токен пользователя должен содержать утверждения:

| Утверждение | Значение |
|---|---|
| `sub` | идентификатор пользователя |
| `admintwin_tenant` | UUID tenant |
| `admintwin_roles` | массив ролей: `tenant_admin`, `it_manager`, `engineer`, `operator`, `compliance_manager`, `auditor`, `viewer`, `platform_super_admin` |
| `admintwin_scopes` | области Engineer: `sysadmin`, `network`, `devops`, `security`, `dba`, `sre` |
| `amr` | методы аутентификации; второй фактор (`otp`, `mfa`, `hwk`, ...) обязателен для согласований, kill switch, break-glass и смены политики |

В Keycloak это user attribute / group mappers в client scope `admintwin`. Роль `ai_agent` из токена пользователя
игнорируется. `ADMINTWIN_DEV_AUTH=true` (заголовки `X-AdminTwin-*`) — **только** для локальной разработки.

## 4. Запуск

- Kubernetes (HA): `kubectl apply -k infra/kubernetes/overlays/<площадка>` — см. `infra/kubernetes/`.
- Docker Compose (small, без SLA 99.9%): `infra/docker/docker-compose.yml`.
- Миграции применяются при старте (`ADMINTWIN_DB_MIGRATE=true`), с advisory lock — безопасно при нескольких репликах.
  Роль подключения ядра должна иметь `BYPASSRLS` (или быть владельцем схемы с этим атрибутом): она нужна только
  для миграций, списка tenants и восстановления после рестарта; все запросы приложения выполняются под ролью
  `admintwin_app` с RLS.

## 5. Наблюдение за платформой (M24)

- `GET /api/v1/health/platform` — `ok | degraded | down`; `down` (503) — недоступен PostgreSQL.
- Метрики Prometheus: `:9464/metrics` (`ADMINTWIN_METRICS_ADDR`). Рекомендуемые алерты:

| Алерт | Условие |
|---|---|
| Нарушена целостность аудита | `admintwin_audit_chain_valid == 0` — **инцидент ИБ**, см. §7 |
| Активен kill switch | `admintwin_kill_switch_active > 0` |
| Изменения ждут ручной проверки | `admintwin_changes{status="manual_review"} > 0` |
| Ошибки API | доля `admintwin_http_requests_total{status=~"5.."}` > 1% за 5 мин |
| Задержка API | p95 `admintwin_http_request_duration_seconds` > 0.5 с (§17.1) |

## 6. Резервное копирование и restore-учения

```bash
pg_dump --format=custom --no-owner --file=admintwin-$(date +%F).dump "$ADMINTWIN_DATABASE_URL"
```

Restore-учение (§19, ежеквартально): восстановить дамп в изолированный экземпляр, запустить ядро с теми же
`ADMINTWIN_AUDIT_SIGNING_KEY` / `ADMINTWIN_PII_MASTER_KEY`, затем проверить:
1. `GET /api/v1/audit-logs/integrity` → `valid: true` для каждого tenant;
2. последний сохранённый checkpoint (`audit_chain_checkpoints`) совпадает с подписанной копией в WORM-хранилище;
3. изменения в `executing` на момент бэкапа после старта — в `manual_review` (так задумано, §11.7).
Зафиксируйте фактические RPO/RTO (цель ≤ 15 мин / ≤ 1 ч).

## 7. Нарушение целостности аудита

1. Не останавливайте и не «чините» таблицу `audit_logs` — она append-only, триггеры запрещают UPDATE/DELETE даже владельцу.
2. Зафиксируйте `broken_at_seq` из `/api/v1/audit-logs/integrity` и последний валидный checkpoint.
3. Сравните с WORM-копиями checkpoint'ов; доступ к БД за период — из журналов PostgreSQL и Vault.
4. Откройте инцидент ИБ (Security Analyst), сохраните дамп БД как forensic evidence с purpose-of-access.

## 8. Kill switch

- Tenant: `POST /api/v1/kill-switch {"active": true, "reason": "..."}` (Tenant Admin, IT Manager, Operator; MFA).
- Платформа: `{"scope": "platform", ...}` — только Platform Super Admin.
- Эффект: новые изменения → `409 kill-switch-active`; открытые согласования отозваны; исполнения получают
  cooperative cancellation → `cancelled` или `unknown → manual_review`; задачи AI отменяются в оркестраторе.
- Платформа **не утверждает** успех остановки без подтверждения: проверьте все `manual_review` вручную и закройте
  их через PIR (`POST /api/v1/changes/{id}/pir`).

## 9. Break-glass (emergency change)

Только Tenant Admin / IT Manager с MFA: `POST /api/v1/changes` с `"type": "emergency"` и причиной.
Runbook — только из каталога; `critical` всё равно требует двух согласующих. PIR обязателен в течение 72 ч
(`pir_due_at`); просроченный PIR помечается `overdue` и виден Compliance.

## 10. Запрос субъекта на удаление ПДн

ПДн в аудите удаляются crypto-shredding'ом ключа tenant (ADR-016) — действие необратимо и затрагивает все ПДн
tenant в аудите; hash chain остаётся верифицируемой. Выполняется процедурой Compliance Manager с журналом
основания; гранулярность «ключ на субъекта» — в плане ADR-016.

## 11. Режимы деградации (§17.2)

| Недоступен | Поведение |
|---|---|
| Внешний LLM | оркестратор переключается на secondary → local; при отказе всех — задачи `blocked`, мониторинг и ручные changes работают |
| Оркестратор | `/api/v1/agent-tasks` → `502`, health `degraded`; всё остальное работает |
| Vault | новые исполнения завершаются `failed` до вызова движка; чтение продолжается |
| PostgreSQL | платформа недоступна (`503`), наблюдаемая инфраструктура не затронута |
| Управляющий канал во время change | цепочка остановлена, повтора нет, `unknown → manual_review` |
