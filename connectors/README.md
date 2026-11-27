# Коннекторы инфраструктуры (MVP, §1.4, §14 п.1–4)

Реальные исполнители и источники фактов для Secure Execution Gateway, Discovery, Tool Service и телеметрии.
Симулятор (`services/execution-gateway/sim`) остаётся только для dev/test и **никогда** не используется как
запасной вариант: актив без `Connection` или с неподдерживаемым методом — ошибка (fail closed).

| Пакет | Метод (`Connection.Method`) | Что даёт |
|---|---|---|
| `connectors/docker` | `docker_api` | движок `docker_api` (restart через Engine API), факты, `docker.container.inspect`, discovery, `container_up`, `container_restarts_total` |
| `connectors/linux` | `ssh` | движки `ssh_argv` (`systemctl restart`) и `builtin` (`logs_rotate_cleanup`), факты, `linux.service.status`, `linux.disk.usage`, discovery, `node_*` |
| `connectors/db` | `postgres` | `postgres.activity`, discovery, `pg_connections_total/max`, `pg_replication_lag_bytes` |
| `connectors/network` | `fortigate_api` | `fortigate.policy.status`, discovery (read-only, только GET) |
| `connectors` (композит) | — | `Set`: выбор коннектора по методу, `gateway.Facts`, движки, read tools, сборщики, опрос метрик |
| `services/execution-gateway/vault` | — | `gateway.CredentialBroker` и `discovery.CredentialSource` поверх Vault/OpenBao |

## Подключение (зона интегратора, `internal/app/app.go`)

```go
import (
	"github.com/aitmaganbetov/admintwin/connectors"
	"github.com/aitmaganbetov/admintwin/connectors/linux"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/vault"
)

// 1. Vault: ошибка конфигурации — отказ старта (fail closed, §17.2).
vcfg, err := vault.ConfigFromEnv() // VAULT_ADDR, VAULT_TOKEN | VAULT_ROLE_ID+VAULT_SECRET_ID, VAULT_CACERT, VAULT_NAMESPACE
if err != nil { return nil, err }
vcfg.Logger = cfg.Logger
broker, err := vault.New(vcfg)
if err != nil { return nil, err }

// 2. Allowlist берём из сертифицированного каталога runbook (единый источник правды).
dirs := []string(nil)
if rb, ok := cat.Get("linux.logs.rotate_cleanup"); ok { dirs = rb.Parameters["directory"].Enum }
units := []string(nil)
if rb, ok := cat.Get("linux.service.restart"); ok { units = rb.Parameters["unit"].Enum }

set := connectors.New(connectors.Config{
	Inventory:   a.Inventory, // inventory.Repository
	Credentials: broker,      // read-only учётки (см. соглашение ниже)
	Logger:      cfg.Logger,
	Linux:       linux.Options{Sudo: os.Getenv("ADMINTWIN_SSH_SUDO") == "true", LogDirectories: dirs, RestartUnits: units},
})

// 3. Gateway: без симулятора — реальные движки, факты и брокер.
if !cfg.Simulator {
	gw.Engines, gw.Facts, gw.Broker = set.Engines(), set.Facts(), broker
}

// 4. Read tools — после toolsvc.Load.
if err := set.RegisterTools(a.Tools); err != nil { return nil, err }

// 5. Метрики: sink — реализация telemetry.Sink; tenants — список tenant_id (inventory их не перечисляет).
poller := set.Poller(sink, func() []string { /* tenant ids */ })
go poller.Run(ctx) // Interval 30 с, Concurrency 8 — поля Poller

// 6. Discovery: сборщики по методам.
// (сервиса discovery ещё нет; ниже — ожидаемая форма регистрации)
for _, c := range set.Collectors() { discoveryService.Register(c) } // c.Method(): ssh, docker_api, postgres, fortigate_api
```

`gateway.Facts` не принимает контекст, поэтому каждый факт ограничен `Config.FactTimeout` (20 с);
HTTP-проверка здоровья — `Config.HealthTimeout` (5 с).

## Vault / OpenBao

- **Аутентификация**: `VAULT_TOKEN` или AppRole (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`, mount `VAULT_APPROLE_MOUNT`=`approle`).
  Токен AppRole кэшируется и обновляется заранее; при 403 — один повторный вход.
- **TLS**: только `https://` с проверкой сертификата (`VAULT_CACERT` — PEM корней). `http://` отклоняется
  (кроме `Config.AllowHTTP` для loopback dev). Редиректы не выполняются (токен не уходит на другой адрес).
- **Fail closed**: Vault недоступен, запечатан (503), standby/429, неожиданный ответ — ошибка; Gateway завершает
  исполнение `failed` («vault unavailable»). Тексты ошибок не содержат путей, токенов и тел ответов.
- **Путь секрета** = `Connection.CredentialRef`, полный путь API без `/v1/`:
  - KV v2: `kv/data/tenants/<tenant_id>/assets/<asset_id>/<method>` — читается `data.data`;
  - динамический: `database/creds/<tenant_id>-<role>` — настоящая аренда Vault, `Revoke` вызывает `sys/leases/revoke`.
  - Запрещены `..`, пустые сегменты, `sys/`, `auth/`, `identity/`, `cubbyhole/`, `*/metadata|delete|destroy/...`.
  - `TenantScoped` (по умолчанию включено; `ADMINTWIN_VAULT_TENANT_SCOPED=false` отключает): путь обязан содержать
    `tenant_id` отдельным сегментом (или имя роли `database/creds/<tenant_id>-...`) — нельзя прочитать секрет другого tenant.
- **Аренда**: `ExpiresAt = now + ttl` (Gateway передаёт timeout runbook + 60 с; не более 1 ч); для динамического
  секрета — не позже срока аренды Vault. Для KV `Revoke` — локальный учёт (хук сохранён), отзывать в Vault нечего.
  Коннекторы отклоняют аренду без срока или с истёкшим сроком.
- **Поля секрета**: `username` (`user`), `password`, `private_key` (`ssh_private_key`, PEM/OpenSSH; при шифровании
  пароль ключа — `password`), `token` (`api_token`, `api_key`), `client_cert` (`tls_cert`), `client_key` (`tls_key`),
  `ca_cert` (`tls_ca`).
- **Read-only учётка** (`ReadOnly`, для фактов, read tools, метрик и discovery):
  1. секрет `<ref>-readonly` (например, `kv/data/tenants/<tid>/assets/<id>/ssh-readonly`);
  2. если его нет — вложенный объект `readonly` в секрете `<ref>`: `{"username":"root",...,"readonly":{"username":"admintwin-ro","private_key":"..."}}`.

  Нет ни того, ни другого — ошибка; учётка исполнения **никогда** не выдаётся вместо read-only.
  Композит кэширует read-only учётку в памяти на `CredentialCacheTTL` (60 с; отрицательное значение — без кэша).
- Пример политики Vault для ядра:
  ```hcl
  path "kv/data/tenants/+/assets/*"   { capabilities = ["read"] }
  path "database/creds/*"             { capabilities = ["read"] }
  path "sys/leases/revoke"            { capabilities = ["update"] }
  ```

## Docker (`docker_api`)

- `Connection.Address`: `unix:///var/run/docker.sock` (или абсолютный путь) либо хост (`tcp://host`, `host:port`);
  порт по умолчанию 2376. По TCP — **только mTLS**: `client_cert` + `client_key` (+ `ca_cert`) из Vault;
  `http://` и TCP без TLS не поддерживаются. Для unix-сокета `credential_ref` для фактов/метрик может быть пустым,
  но для исполнения аренда Vault обязательна всегда (секрет без материала отклоняется — для сокета достаточно
  маркера `{"username":"local-socket"}`).
- Restart: `POST /v1.41/containers/{id}/restart?t=10`; повторно проверяются формат id, наличие в
  `Objects["container"]` и отсутствие в `Protected`.
- Отмена: `ErrCancelConfirmed` — только если ни один байт запроса не отправлен (httptrace); после отправки —
  ошибка контекста (Gateway → `unknown` → manual_review); разрыв после отправки — `ErrChannelLost`; отказ соединения
  до отправки — обычная ошибка (`failed`, состояние не менялось). 404/5xx демона — `exit_code=1`.
- `RestartsLastHour` — число событий `start` контейнера за час из `/events?since&until` (ручные и по restart policy;
  первичный запуск нового контейнера тоже учитывается — оценка сверху, безопасная для лимита). Учёт переживает
  перезапуск AdminTwin.
- `ContainerRunning` — `Running && !Paused && !Restarting`. `docker.container.inspect` не читает `Config.Env`;
  значения меток проходят `gateway.Redact`, ответ укладывается в 32 КиБ.
- Discovery: актив `docker_host`, `Objects["container"]` — короткие (12 символов) ID, именно их принимает
  `container_id` runbook; `Objects["docker_version"]`, `Objects["os"]`; предупреждения о `restarting`/`dead`.

## Linux SSH (`ssh`)

- **Host key обязателен**: `Connection.HostKey` в формате authorized_keys (`ssh-ed25519 AAAA...`). Нет ключа —
  отказ до TCP-подключения; несовпадение — отказ (`ErrHostKeyMismatch`), предупреждение в журнале.
  Сертификаты хоста не поддерживаются. `InsecureIgnoreHostKey` в коде нет.
- Аутентификация: ключ (предпочтительно; контракт Этапа 1 рекомендует только ключ) или пароль из Vault.
- **Никакого shell как интерпретатора**: SSH exec передаёт строку, поэтому каждый аргумент экранируется отдельно
  (`linux.Quote`: безопасные символы — как есть, иначе одинарные кавычки; NUL, `\n`, `\r`, табуляция и прочие
  управляющие символы, U+2028/2029, невалидный UTF-8 — **отказ**). Итоговый argv повторно сверяется с шаблонами
  allowlist перед исполнением. Окружение `LC_ALL=C` передаётся запросом `env` сессии, а не в строке команды.
- Allowlist команд:
  - read-only: `systemctl show <unit…> --property=… --no-pager`, `systemctl list-units --type=service --all --no-legend --no-pager --plain`,
    `df -P -B1 [path]`, `df -P -i`, `findmnt -r -n -o TARGET,SOURCE,FSTYPE`, `du -s -x -B1 <каталог из allowlist>`,
    `journalctl -u <unit> -n <1..200> --no-pager -o short-iso`, `cat` из `/proc/loadavg /proc/meminfo /proc/stat /proc/uptime /etc/os-release /proc/sys/kernel/hostname`;
  - только Gateway: `systemctl restart <unit из RestartUnits>`; очистка
    `find <dir> -xdev -type f -mtime +N -name '*.log*' [! -name '*-json.log'] -printf '%s\t%p\0' [-delete]`.
- `Options.Sudo=true` → write-команды как `sudo -n -- <argv>`. В sudoers перечисляются **точные** команды:
  ```
  admintwin ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx.service, /usr/bin/systemctl restart php-fpm.service
  ```
  **Не используйте `*` в правилах для `find`**: подстановка sudoers допускает любые аргументы (`-exec …` → root).
  Для очистки либо перечисляйте точные argv для согласованных значений `older_than_days` (с экранированием `\` и `,`
  по правилам sudoers), либо (предпочтительно) выдайте сервисной учётке права записи в каталоги журналов через группу
  владельца и оставьте `Sudo=false`.
  Read-only учётке для `journalctl` нужна группа `systemd-journal` (или `adm`); без неё `recent_log` пуст.
- `logs_rotate_cleanup` (движок `builtin`): каталог должен быть в `Options.LogDirectories` (enum runbook) **и** в
  `Asset.Objects["log_directory"]`, не в `Protected`; legal hold и активное расследование — отказ (дублирует
  preflight, §11.6, T-LH-001); `older_than_days` 3..365. Dry-run — только листинг с отчётом «would delete N files,
  X bytes (Y% of filesystem M)»; настоящий прогон — тот же `find` с `-delete` (удаляется ровно то, что вошло в отчёт).
  Для `/var/lib/docker/containers` активные `*-json.log` исключены. Ротация (`logrotate`) не выполняется — только
  очистка старых ротированных файлов. Требуется GNU findutils (`-printf`).
- Факты: `UnitActive` (ActiveState=active); `RestartsLastHour` — 0, если unit активен непрерывно > 1 ч
  (`ActiveEnterTimestampMonotonic` vs `/proc/uptime`), иначе `NRestarts` + перезапуски этим процессом за час
  (оценка сверху); `DiskUsagePercent` — максимум по постоянным ФС (tmpfs/overlay/… исключены);
  `LogWritersHealthy` — `systemd-journald` активен, `rsyslog` (если установлен) активен, ни одна служба актива из CMDB
  не в `failed`.
- Discovery: `linux_host`, hostname, `Objects["os"]`, `Objects["systemd_unit"]` (loaded services),
  `Objects["filesystem"]`. `Objects["log_directory"]` **не** заполняется автоматически — каталоги очистки утверждает человек.
- Метрики: `node_memory_used_percent` (MemTotal−MemAvailable), `node_disk_used_percent{mount}`,
  `node_cpu_usage_percent` — по разности `/proc/stat` между опросами (появляется со второго опроса).

## PostgreSQL (`postgres`)

- TLS по умолчанию `verify-full` (CA из `ca_cert`, имя — `TLSServerName` или адрес); **без fallback** на открытый
  текст. `Connection.TLSSkipVerify=true` — шифрование без проверки (предупреждение). `Options.SSLMode="disable"` —
  только dev/test. Конфигурация pgx строится без DSN-строки.
- Сессия: `default_transaction_read_only=on`, `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`,
  `statement_timeout` (5 с), `lock_timeout`, `application_name=admintwin-readonly`. Это второй рубеж:
  роль в Vault обязана быть read-only (`CREATE ROLE admintwin_ro LOGIN IN ROLE pg_monitor`).
- `postgres.activity`: `query` — нормализованный отпечаток (`db.Fingerprint`): литералы, числа, `$$…$$`, комментарии
  удалены, списки свёрнуты; оборванный литерал поглощает остаток; ≤ 512 байт; ответ укладывается в 32 КиБ.
- Метрики: `pg_connections_total` (client backends), `pg_connections_max`, `pg_replication_lag_bytes{client}`
  (на primary — по `pg_stat_replication`, на standby — `client="local_replay"`).
- Discovery: `database`, `Objects["version"|"role"|"database"]`, имя — `cluster_name` или `host:port`.

## FortiGate (`fortigate_api`)

- `Connection.Address` — хост/IP (только https, порт 443 по умолчанию); токен read-only профиля REST API в
  `token`; заголовок `Authorization: Bearer` (не `access_token` в URL); TLS-проверка включена (CA — `ca_cert`).
- Только `GET`: `/api/v2/cmdb/firewall/policy[/<id>]`, `/api/v2/monitor/firewall/policy` (hit_count, last_used),
  `/api/v2/cmdb/system/ha`, `/api/v2/monitor/system/ha-checksums`, `/api/v2/monitor/system/status`,
  `/api/v2/cmdb/system/interface`, `/api/v2/monitor/vpn/ipsec`. Методов изменения в коде нет (проверяется тестом).
- Discovery: `firewall`, hostname, `Objects["model"|"firmware"|"serial"|"interface"|"ipsec_tunnel"]`,
  предупреждения о туннелях с selector в состоянии down.

## Безопасность (сводка)

- Shell не используется нигде в production-коде; движка `shell` нет.
- `InsecureSkipVerify` — только при явном `Connection.TLSSkipVerify=true` и с предупреждением в журнале.
- Секреты: `gateway.Credential` редактируется при печати/JSON; коннекторы не журналируют креды и тела ответов;
  ошибки не содержат паролей/токенов (проверяется тестами).
- Таймауты на каждом сетевом вызове; лимиты размера ответов (Vault 1 МиБ, Docker 4 МиБ, FortiOS 8 МиБ, SSH stdout 1 МиБ).
- Данные удалённых систем — недоверенные (§18.6): управляющие символы удаляются, длины ограничены.

## Тесты

```
go test -race ./connectors/... ./services/execution-gateway/...
# интеграционный тест PostgreSQL (пропускается без переменной):
ADMINTWIN_TEST_DATABASE_URL='postgres://admintwin_ro:...@127.0.0.1:5432/postgres?sslmode=disable' go test -race ./connectors/db/
```

Сетевой доступ тестам не нужен: fake Vault (httptest TLS), эмуляция Engine API (mTLS и unix-сокет),
SSH-сервер в процессе (x/crypto/ssh) с проверкой точных строк команд, fake FortiOS. `TestQuoteRoundTrip` использует
системный `sh` как эталон интерпретации строки exec (только в тесте; пропускается без `sh`).
