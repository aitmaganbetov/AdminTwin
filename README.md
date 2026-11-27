# AdminTwin

**AI Infrastructure Digital Twin & Autonomous IT Operations Platform** — *Observe · Analyze · Automate · Secure*

Техническое задание: [`AdminTwin_TZ_v1_3_1.md`](AdminTwin_TZ_v1_3_1.md) (v1.3.1). Реализован MVP-срез §1.4.

> **Инварианты.** LLM не получает production-credentials и не выполняет произвольные команды. Любое изменение
> проходит единый контур **Change → Policy → Approval → Secure Execution Gateway → Audit**. Режим по умолчанию —
> Advisor. Платформа не стоит в критическом пути production. Ссылка на стандарт не означает сертификацию.

## Что внутри

| Часть | Где | Модули ТЗ |
|---|---|---|
| Ядро (Go, один бинарник) | `cmd/admintwin-core`, `services/*`, `pkg/*` | M04 CMDB, M06 инциденты, M07 приём RCA, M09 Gateway, M10 IAM/Policy/Approval, M20 изоляция, M24 meta-monitoring, M25 реестры, M26 контроли (мин.), M27 Change |
| Коннекторы и Vault | `connectors/*`, `services/execution-gateway/vault` | Linux/SSH, Docker API, FortiGate (read-only), PostgreSQL (read-only) — §14 MVP |
| Телеметрия и discovery | `services/telemetry`, `services/discovery` | M03, M05: метрики, события, syslog, VictoriaMetrics/Loki, scope documents |
| AI-оркестратор (Python) | `ai/` | M01 Commander, M02 агенты, M08 ChatOps (SSE), M21 провайдеры Claude/OpenAI/Local, M22 evals |
| Web UI (Next.js) | `apps/web` | §16: Command Center, инциденты, ChatOps, изменения и согласования, CMDB, топология, аудит, ru/kk/en |
| Хранилище | `db/migrations` | PostgreSQL 16, RLS (ENABLE+FORCE) на всех tenant-таблицах |
| Развёртывание | `infra/docker`, `infra/kubernetes` | Docker Compose (small), Kubernetes HA (kustomize) |

Документация: [контракты API](docs/api/openapi.yaml) · [контракты модулей](docs/api/stage1-contracts.md) ·
[эксплуатация](docs/operations/README.md) · [толкования ТЗ](docs/architecture/spec-interpretations.md) ·
[ADR](docs/adr/README.md) · [матрица версий](docs/compatibility.md) · [AI-слой](ai/README.md) · [UI](apps/web/README.md)

## Быстрый старт (локально, без реальной инфраструктуры)

```bash
make run                                   # ядро :8080 — симулятор инфраструктуры, dev-аутентификация
cd ai && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]' && \
  ADMINTWIN_SERVICE_TOKEN=dev-token-0123456789abcdef0123456789 ADMINTWIN_AI_OFFLINE_FAKE=true \
  .venv/bin/python -m admintwin_ai.service # оркестратор :8090 (офлайн-модель, без вызовов LLM)
cd apps/web && npm ci && npm run dev       # UI :3000, DEV-вход
```
Для связки ядра с оркестратором запустите ядро с тем же `ADMINTWIN_SERVICE_TOKEN` и
`ADMINTWIN_ORCHESTRATOR_URL=http://127.0.0.1:8090`. Полный стек в контейнерах: `infra/docker/docker-compose.yml`
(см. `.env.example`). Production: OIDC, Vault, ключи LLM — [эксплуатация](docs/operations/README.md).

## Проверка

```bash
make lint test-race      # Go: unit + e2e через HTTP (под race detector)
make test-db             # PostgreSQL: RLS, хранение ядра и рестарт, инциденты, коннектор PG (нужны ADMINTWIN_TEST_* URL)
make ai-test             # Python: ruff, mypy --strict, ~600 тестов, CI-гейт качества RCA
make e2e-mvp             # сквозные сценарии MVP на живых процессах (ядро + оркестратор)
cd apps/web && npm run lint && npm run typecheck && npm test && npm run build
```
CI (`.github/workflows/ci.yml`) запускает всё перечисленное, плюс валидацию OpenAPI и govulncheck.

## Критерии приёмки §21 [MVP]

| Критерий | Статус | Чем подтверждено |
|---|---|---|
| Два tenant; нет cross-tenant доступа через API, БД, tools, evidence (T-TENANT-001) | ✅ | `tests/e2e` `TestTenantIsolation`, `tests/security` (RLS на реальном PG), Tool Service, телеметрия/инциденты/discovery. RAG в MVP нет (§15 — вне среза) |
| Три провайдера; смена model profile с проверкой capabilities; fallback | ✅ | `ai/tests` (Claude/OpenAI/Local адаптеры на фейках SDK, профили, circuit breaker) |
| `pii`/`secret` не уходят внешнему провайдеру; fail closed | ✅ | `ai/tests` маркерные тесты маршрутизации и маскирования |
| Бюджет исчерпан → задачи `blocked`, мониторинг работает | ✅ | `ai/tests` бюджеты и сервис |
| Discovery только при действующем scope; ≥ 1 устройства каждого MVP-типа; матрица версий | ⚠️ частично | scope/диапазоны/методы/учётки — `services/discovery`; сборщики проверены на эмуляторах и PG 16, не на реальных устройствах каждого типа — [матрица](docs/compatibility.md) |
| Топология с источником ребра и blast radius; environment/criticality у активов | ✅ | CMDB, `topology.blast_radius`, recursive CTE на PG |
| Метрики, события, журналы с корреляцией к активам | ✅ | `services/telemetry` (пороговые правила, syslog по адресу актива) |
| Инцидент 502 создаётся и назначается за < 30 с | ✅ | `make e2e-mvp`: 0.3–1 с |
| Commander параллельно опрашивает Network/DevOps/DBA; при конфликте — разделяющая проверка | ✅ | `make e2e-mvp` (502, диск: «неопределённость, нужна проверка X» после одной проверки) |
| RCA с evidence и confidence; precision@1 ≥ 70% на golden dataset для primary | ⚠️ частично | конвейер RCA и гейт CI работают (33 кейса); качество **реального** primary-провайдера не измерено — нужны ключи API (`python -m admintwin_ai.evals.run --profile <claude-профиль>`) |
| Пользователь видит сообщения, статусы, tool calls, стоимость в реальном времени | ✅ | SSE через ядро и Next.js — проверено в браузере (Playwright) на живом оркестраторе |
| Запись только через ChangeRequest; `POST /executions` нет; AI не согласует (T-CAP-002) | ✅ | e2e + `services/approval` + CHECK в БД |
| Три runbook с preflight/post-check/compensation; allowlist; legal hold (T-LH-001) | ✅ | `services/execution-gateway`, `runbooks/catalog` |
| При отказе Gateway нет обходного пути | ✅ | `TestGatewayFailureHasNoBypass`, Vault недоступен → `failed` без вызова движка |
| Kill switch: отказ новых операций, отмена < 5 с, `cancelled`/`cancellation_pending`/`unknown → manual_review` | ✅ | `TestKillSwitch`, отмена во время preflight, оркестратор (`/v1/kill`), хранение в БД и синхронизация реплик |
| Аудит: actor, tenant, asset, change, policy, approval, runbook, результат, провайдер и модель; hash chain; ПДн зашифрованы | ✅ | hash chain на tenant, подписанные checkpoint'ы, crypto-shredding, вызовы LLM в цепочке ядра (`make e2e-mvp`) |
| ≥ 50 prompt-injection payload без действий вне policy (T-AI-001) | ✅ | 60 payload через полный путь HTTP backend → агенты → Commander |
| Capability без tool scope отклоняется (T-CAP-001); контроль без evidence не `verified` (T-COMP-001) | ✅ | Tool Service ядра + согласованность реестров; контроли — API и CHECK БД |

Критерии без пометки [MVP] (restore из бэкапа, onboarding ≤ 30 мин, нагрузочные/HA-тесты, P1a-профиль) —
процедуры описаны в [эксплуатации](docs/operations/README.md), стенды не прогонялись.

## Безопасность

Независимое ревью нашло 9 проблем (2 высокие: исполнение после отмены во время preflight; перенаправление актива
через discovery). Все исправлены, на каждую — регрессионный тест. Итоговые правила — в
[толкованиях I-11…I-17](docs/architecture/spec-interpretations.md).

## Ограничения текущей версии

- В PostgreSQL хранятся ядро (CMDB, изменения, аудит, evidence, контроли, kill switch) и инциденты; события,
  discovery и состояние оркестратора (задачи, кейсы) — пока в памяти.
- Evidence хранится в PostgreSQL; адаптер MinIO Object Lock (WORM) — следующий шаг.
- Policy Engine встроенный (Go); адаптер OPA/Cedar — ADR-003.
- Docker-образы не собирались в среде разработки (нет Docker daemon); раскладка файлов образа ядра проверена запуском.
- Подписочные каналы Claude/Codex заблокированы до заключения юриста (ADR-007).
- Модули P1a/P1b/P2 (Security Ops, DevOps, Backup/DR, Time Machine, Simulation и др.) — вне MVP.
