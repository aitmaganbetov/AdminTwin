# Матрица поддерживаемых версий (ТЗ §14, ADR-010)

Статусы:
- **проверено** — интеграционный тест на реальном экземпляре;
- **эмуляция** — тест против эмулятора протокола в репозитории (httptest / in-process SSH-сервер);
- **заявлено** — по документации вендора, тестом не подтверждено.

Перед пилотом каждую строку «эмуляция» нужно перевести в «проверено» на стенде заказчика (§19 Compatibility).

| Интеграция (MVP) | Интерфейс | Версии | Статус | Тест |
|---|---|---|---|---|
| Linux / Ubuntu (SSH) | OpenSSH, systemd (`systemctl show`, `journalctl`), `df -P`, `/proc` | Ubuntu 20.04 / 22.04 / 24.04 LTS, systemd ≥ 245 (NRestarts ≥ 235) | эмуляция | `connectors/linux` (in-process SSH-сервер, точные строки команд, host key pinning) |
| Docker Engine API | REST, unix socket или TCP+mTLS | API v1.41 (Docker Engine ≥ 20.10) | эмуляция | `connectors/docker` (httptest + unix socket, mTLS) |
| FortiGate (read-only) | FortiOS REST API v2 (`/api/v2/cmdb`, `/api/v2/monitor`), API-токен | FortiOS 7.0 / 7.2 / 7.4 | эмуляция | `connectors/network` (фейковый FortiOS; тест запрещает методы записи) |
| PostgreSQL (read-only) | pgx, `pg_stat_activity`, `pg_stat_replication`, `SET TRANSACTION READ ONLY` | 16 | **проверено** | `connectors/db` `TestIntegrationPostgres` (PostgreSQL 16.15) |
| PostgreSQL (read-only) | то же | 13–15 | заявлено | — |
| Vault / OpenBao | HTTP API, KV v2, dynamic `database/creds`, AppRole | Vault 1.15+, OpenBao 2.x | эмуляция | `services/execution-gateway/vault` (фейковый TLS-Vault) |

| Компонент платформы | Версии | Статус |
|---|---|---|
| PostgreSQL (хранилище ядра, RLS) | 16 | **проверено** (`tests/security`, `tests/e2e` `TestPostgresStore`, `services/incidents`) |
| NATS JetStream (шина агентов) | nats-server 2.10.22 | **проверено** (`ai/tests/test_bus_nats.py` с реальным сервером) |
| VictoriaMetrics / Loki | VM 1.106, Loki 3.3 | эмуляция (`services/telemetry`, httptest) |
| Kubernetes (манифесты) | 1.30 | схемы проверены `kubeconform -strict`; на кластере не разворачивалось |
| Go / Python / Node.js | Go 1.24, Python 3.13, Node.js 22 | **проверено** (CI) |
| Браузеры UI | Chromium (Playwright) | **проверено** (`apps/web/scripts/smoke.cjs`) |
