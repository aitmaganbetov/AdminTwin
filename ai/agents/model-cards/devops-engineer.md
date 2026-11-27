# Model card: devops-engineer

> Заполнено по шаблону `_template.md` (ТЗ §6.10). Поля `<...>` заполняются по результатам
> прогона evals на реальных профилях перед релизом.

## 1. Идентификация

| Поле | Значение |
|---|---|
| Агент | `devops-engineer` (DevOps Engineer), версия `1.0.0` |
| Промпт | `agents/prompts/devops-engineer-v1.md` + `_common.md` |
| Model Profile | primary `claude-primary`, fallback `openai-secondary` |
| Требуемые capabilities модели | `tool_calling`, контекст ≥ 32768 |
| Capabilities (Приложение B) | DEV-006 |
| Политика | `policy-ai-devops-v1` |
| Владелец | `<команда / ответственный>` |
| Дата ревью | `<YYYY-MM-DD>` |

## 2. Назначение и границы

- Назначение: Docker-хосты и контейнеры: state, exit code, OOM, перезапуски, healthcheck, журналы.
- Вне области: перезапуск — только ChangeRequest docker.container.restart, решение за Policy Engine и человеком.
- Уровни операций: observe / diagnose / recommend / propose; execute и approve недоступны никогда.
- Разрешённые инструменты: `asset.get`, `topology.blast_radius`, `events.list`, `metrics.query`, `logs.search`, `docker.container.inspect`, `linux.service.status`, `change.propose`.
- Runbooks для `change.propose`: `docker.container.restart`.
- Класс данных ≤ `confidential`; секреты не выдаются.

## 3. Данные, маршрутизация, бюджет

- Источник данных — read tools ядра; ответы обёрнуты как недоверенные данные, к каждому
  успешному вызову оркестратор добавляет `evidence_id`.
- `pii`/`secret` → только Local; `unknown` → fail closed; внешним провайдерам — маскирование.
- Бюджет подзадачи: tokens 60000, tool_calls 25, wall_time 300 с,
  глубина 2; исчерпание → `blocked` (`budget.exhausted`).

## 4. Оценка качества (`evals/golden/mvp-v2.jsonl`, 33 кейса)

| Профиль | precision@1 | precision@3 | ложно-уверенные | необоснованные отказы | tool calls до верной |
|---|---|---|---|---|---|
| `offline-fake` (регрессия пайплайна, не модели) | 100% | 100% | 0% | 0% | см. baseline |
| `claude-primary` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |
| `openai-secondary` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |
| `local-default` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |

Команда: `python -m admintwin_ai.evals.run --profile <profile> --output <file>.json`.
Порог релиза: precision@1 ≥ 70% (primary), падение ≤ 5 п.п. к baseline, ложно-уверенных < 5%.

## 5. Риски и меры

| Риск | Мера | Тест |
|---|---|---|
| Prompt injection через данные | обёртка «данные, не инструкции»; Tool Layer; Policy Engine | T-AI-001 (`test_prompt_injection*.py`) |
| Галлюцинация evidence | неизвестные evidence_id отбрасываются; без evidence confidence ≤ 0.5 | `test_findings_cases.py` |
| Ложно-уверенный вывод | разрыв < 0.2 → «неопределённость, нужна проверка X» | `test_rca_flow.py` |
| Перезапуск при ошибке конфигурации (цикл) | runbook preflight restart_count_last_hour_lt; правило промпта | golden container-* |

## 6. Ограничения

- Качество на реальных моделях не измерено в CI (офлайн-модель проверяет только пайплайн).
- `<...>`

## 7. История изменений

| Дата | Изменение | prompt_version | Профиль | precision@1 |
|---|---|---|---|---|
| `<...>` | первая версия | `devops-engineer-v1` | `claude-primary` | `<...>` |
