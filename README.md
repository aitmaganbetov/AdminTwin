# AdminTwin

**AI Infrastructure Digital Twin & Autonomous IT Operations Platform** — *Observe · Analyze · Automate · Secure*

Техническое задание: [`AdminTwin_TZ_v1_3_1.md`](AdminTwin_TZ_v1_3_1.md) (v1.3.1, окончательная редакция).

> **Инварианты.** LLM не получает production-credentials и не выполняет произвольные команды. Любое изменение
> проходит единый контур **Change → Policy → Approval → Secure Execution Gateway → Audit**. Режим по умолчанию —
> Advisor (только предложения). Ссылка на стандарт не означает сертификацию.

## Статус: Этап 0 — Foundation (§20)

Реализовано ядро безопасности, на которое опираются все последующие этапы:

| Компонент | Где | Что сделано |
|---|---|---|
| Change & Release Coordinator (M27) | `services/change-coordinator` | ChangeRequest — единственная точка записи; state machine §11.1/C.8 как данные; impact (blast radius), PIR, идемпотентность |
| Policy Engine (M10) | `services/policy` | матрица «риск × режим × согласование» §11.4, legal hold, kill switch, rate limit, классификация активов, break-glass §11.5 |
| Approval Service (M10) | `services/approval` | AI никогда не approver, автор не согласует, dual control для critical, Engineer — только своя область |
| Secure Execution Gateway (M09) | `services/execution-gateway` | preflight → краткоживущие креды → исполнение без shell → post-check → compensation → evidence; cooperative cancellation с fencing |
| Runbook-каталог | `runbooks/catalog` | 3 MVP-runbook §11.3; валидатор правил сертификации, заморозка версий, параметры по схеме + allowlist |
| Аудит | `services/audit` | append-only hash chain на tenant, подписанные checkpoint'ы (Ed25519), crypto-shredding ПДн (ADR-016) |
| Evidence | `services/compliance-evidence` | digest SHA-256, custody, legal hold, доступ только с purpose-of-access |
| CMDB (M04, минимально) | `services/inventory` | активы с environment/ring/service_tier/criticality/data_class/legal_hold, граф, blast radius |
| Реестры (M25) | `services/capability-registry`, `capabilities/`, `standards/` | 28 стандартов Приложения A, capabilities MVP; правило «AI ≤ propose», матрица трассируемости из данных |
| API v1 (§13) | `services/api-gateway`, [`docs/api/openapi.yaml`](docs/api/openapi.yaml) | RFC 9457, request_id, Idempotency-Key, роли по матрице §2.2; `POST /executions` отсутствует |
| Схема БД (§12) | `db/migrations` | RLS (ENABLE+FORCE) на всех tenant-таблицах, append-only аудит, инварианты SoD и legal hold на уровне БД |
| AI-слой (M21, M22) | `ai/` | провайдеры Claude / OpenAI / Local, маскирование, fail-closed маршрутизация, бюджеты, Tool Layer read/propose — см. [`ai/README.md`](ai/README.md) |

Спорные места ТЗ и выбранные толкования — [`docs/architecture/spec-interpretations.md`](docs/architecture/spec-interpretations.md).
Реестр ADR — [`docs/adr/README.md`](docs/adr/README.md).

**Пока не реализовано** (следующие шаги Этапа 0 → 1): OIDC/JWT и MFA (сейчас только dev-аутентификация по
заголовкам), хранилище ядра на PostgreSQL (сейчас in-memory за интерфейсами; схема и RLS готовы и протестированы),
NATS, Vault/OpenBao, реальные коннекторы Docker/SSH/FortiGate/PostgreSQL (сейчас — симулятор с теми же
интерфейсами), discovery и scope documents, инциденты/RCA, ChatOps, Web UI, OPA-адаптер (ADR-003).

## Быстрый старт

```bash
make run          # ядро на :8080 с dev-аутентификацией и симулятором инфраструктуры
```

```bash
T=11111111-1111-4111-8111-111111111111
# AI-агент предлагает перезапуск контейнера (propose tool → ChangeRequest)
curl -s -X POST localhost:8080/api/v1/changes \
  -H "X-AdminTwin-Tenant: $T" -H 'X-AdminTwin-Actor: devops-engineer' -H 'X-AdminTwin-Actor-Kind: ai_agent' \
  -H 'Idempotency-Key: demo-1' -H 'Content-Type: application/json' \
  -d '{"runbook_id":"docker.container.restart","asset_id":"a0000000-0000-4000-8000-000000000002",
       "params":{"container_id":"3f2a9c1b7d4e"},"reason":"HTTP 502: upstream unhealthy"}'
```

Демо-данные — [`infra/dev/fixtures.yaml`](infra/dev/fixtures.yaml): tenant A в режиме Operator (сценарий HTTP 502,
актив под legal hold), tenant B в режиме Advisor (проверка изоляции).

Docker: `ADMINTWIN_PG_PASSWORD=... make up`.

## Тесты

```bash
make lint test-race                                            # Go: unit + e2e через HTTP
ADMINTWIN_TEST_DATABASE_URL=postgres://... make test-db        # RLS и инварианты схемы на реальном PostgreSQL
make ai-test                                                   # Python AI-слой (офлайн, без вызовов LLM)
```

### Критерии приёмки §21 [MVP], уже покрытые тестами

| Критерий | Тест |
|---|---|
| Нет cross-tenant доступа через API и БД (T-TENANT-001) | `tests/e2e` `TestTenantIsolation`, `tests/security` `TestRLSIsolationAndInvariants` |
| Запись только через ChangeRequest; `POST /executions` отсутствует | `TestNoDirectExecutionEndpoint`, `TestExecutionMustBelongToChange` |
| AI не может согласовать (T-CAP-002) | `TestAINeverApprover`, `TestNormalChangeApprovalSeparationOfDuties`, RLS-тест (CHECK на уровне БД) |
| Три runbook с preflight/post-check/compensation; параметр вне allowlist отклоняется | `TestCertificationRules`, `TestParamValidation`, `TestLegalHoldAndAllowlist`, `TestPostCheckFailureCompensates` |
| Preflight блокирует при legal hold (T-LH-001) | `TestLegalHoldBlocksCleanup` |
| При отказе Gateway нет обходного пути | `TestGatewayFailureHasNoBypass`, `TestVaultDownMeansNoExecution` |
| Kill switch: отказ новых операций, отмена < 5 с, `cancelled`/`cancellation_pending`/`unknown → manual_review` | `TestKillSwitch` |
| Аудит с actor/policy/runbook/result; hash chain верифицируется; ПДн зашифрованы | `TestStandardChangeAutoExecutesWithEvidenceAndAudit`, `TestHashChainAndTamperDetection`, `TestCryptoShredding` |
| Capability без tool scope отклоняется (T-CAP-001); execute не бывает tool (T-CAP-003) | `TestToolScope`, `TestRegistryRules`, Python Tool Layer |
| `pii`/`secret` не уходят внешнему провайдеру; fail closed; ≥ 50 prompt-injection payload (T-AI-001) | `ai/tests` |

## Структура (§22)

```
cmd/admintwin-core/       единый бинарник ядра
internal/app/             сборка сервисов
pkg/                      problem (RFC 9457), fsm, identity, killswitch
services/                 api-gateway, change-coordinator, policy, approval, execution-gateway,
                          audit, compliance-evidence, capability-registry, inventory
ai/                       Python: providers, tools/{read,propose}, contracts, orchestrator, evals
runbooks/catalog/         YAML runbook-каталог
capabilities/             Приложение B (машиночитаемо)
standards/                Приложение A (registry.yaml)
db/migrations/            схема PostgreSQL с RLS
docs/                     api, adr, architecture
tests/                    e2e, security
infra/                    docker, dev fixtures
```
