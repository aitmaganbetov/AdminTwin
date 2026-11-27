# AdminTwin Web UI (MVP)

Next.js 16 + React 19 + TypeScript. UI ходит только в `/api/v1/*` ядра через rewrites `next.config.ts`
(ТЗ §13, `docs/api/stage1-contracts.md` §5). Язык по умолчанию — русский; также казахский и английский.

## Запуск локально

```bash
# ядро (из корня репозитория)
ADMINTWIN_DEV_AUTH=true ADMINTWIN_SIMULATOR=true ADMINTWIN_FIXTURES=infra/dev/fixtures.yaml \
  ADMINTWIN_ADDR=127.0.0.1:8080 go run ./cmd/admintwin-core

# UI
cd apps/web && npm ci && npm run dev        # http://localhost:3000
```

Проверки: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`,
`npm run smoke` (Playwright против запущенных ядра и `next start`; скриншоты — `docs/screenshots/`).

## Переменные окружения

| Переменная | Назначение |
|---|---|
| `ADMINTWIN_CORE_URL` | адрес ядра для rewrites (по умолчанию `http://localhost:8080`); читается при `next dev` / `next build` |
| `NEXT_PUBLIC_OIDC_ISSUER` | включает OIDC Authorization Code + PKCE; без неё — DEV-вход с заголовками `X-AdminTwin-*` |
| `NEXT_PUBLIC_OIDC_CLIENT_ID` | публичный клиент (по умолчанию `admintwin-web`); redirect URI — `<origin>/auth/callback` |
| `NEXT_PUBLIC_OIDC_SCOPE` | по умолчанию `openid profile email` |
| `NEXT_PUBLIC_OIDC_AUDIENCE` | необязательный `audience` |
| `NEXT_PUBLIC_OIDC_ROLES_CLAIM` / `NEXT_PUBLIC_OIDC_TENANT_CLAIM` | claims для отображения ролей/tenant (по умолчанию `roles`, `tenant_id`) |
| `ADMINTWIN_WEB_STANDALONE=1` | сборка `output: standalone` (Docker, `infra/docker/Dockerfile.web`) |
| `WEB_URL` | адрес UI для `npm run smoke` |

Токен OIDC хранится только в памяти вкладки; в `sessionStorage` — лишь одноразовые `state`/`code_verifier`
на время редиректа и DEV-идентичность (не секрет). Роли в UI управляют только видимостью элементов —
решения принимает сервер (Policy Engine), его ошибки RFC 9457 показываются как есть.

## Структура

- `src/app/*` — разделы (§16): Командный центр, Инциденты, Совместная работа агентов, Изменения и согласования,
  Активы/CMDB, Живая топология, Runbooks, Способности и стандарты, AI-провайдеры и бюджеты, Аудит,
  Здоровье платформы, Настройки (kill switch), вход DEV/OIDC.
- `src/lib/api` — типы, клиент, RFC 9457, SSE (fetch-reader с заголовками и переподключением).
- `src/lib/i18n` — словари `ru` (ключи-эталон), `kk`, `en`.
- `src/lib/params.ts` — форма параметров runbook из схемы; `permissions.ts` — матрица §2.2 для UI.

Модули Этапа 1, которые ядро ещё не публикует (incidents, telemetry, discovery, agent-tasks, chat, ai),
отображаются как «Модуль ещё не доступен» (404 без problem-тела от мультиплексора ядра).
