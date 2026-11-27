# Model card: ai-commander

> Заполнено по шаблону `_template.md` (ТЗ §6.10). Поля `<...>` заполняются по результатам
> прогона evals на реальных профилях перед релизом.

## 1. Идентификация

| Поле | Значение |
|---|---|
| Агент | `ai-commander` (AdminTwin Commander), версия `1.0.0` |
| Промпт | `agents/prompts/commander-v1.md` + `_common.md` |
| Model Profile | primary `claude-primary`, fallback `openai-secondary` |
| Требуемые capabilities модели | `tool_calling, structured_output`, контекст ≥ 65536 |
| Capabilities (Приложение B) | ITSM-001, ITSM-005, SRE-001, NET-011 |
| Политика | `policy-ai-commander-v1` |
| Владелец | `<команда / ответственный>` |
| Дата ревью | `<YYYY-MM-DD>` |

## 2. Назначение и границы

- Назначение: координация RCA: сбор контекста (CMDB, blast radius, события), детерминированный выбор агентов, таблица гипотез, разделяющая проверка, итог RCA; чат с оператором.
- Вне области: не предлагает изменений (нет change.propose), не исполняет и не согласует.
- Уровни операций: observe / diagnose / recommend; execute и approve недоступны никогда.
- Разрешённые инструменты: `asset.get`, `topology.blast_radius`, `events.list`, `metrics.query`, `logs.search`.
- Runbooks для `change.propose`: нет.
- Класс данных ≤ `confidential`; секреты не выдаются.

## 3. Данные, маршрутизация, бюджет

- Источник данных — read tools ядра; ответы обёрнуты как недоверенные данные, к каждому
  успешному вызову оркестратор добавляет `evidence_id`.
- `pii`/`secret` → только Local; `unknown` → fail closed; внешним провайдерам — маскирование.
- Бюджет подзадачи: tokens 120000, tool_calls 40, wall_time 600 с,
  глубина 3; исчерпание → `blocked` (`budget.exhausted`).

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
| Ошибочный выбор агентов | выбор только по правилам routing; LLM лишь предлагает, Commander подтверждает по blast radius | test_commander.py |

## 6. Ограничения

- Качество на реальных моделях не измерено в CI (офлайн-модель проверяет только пайплайн).
- `<...>`

## 7. История изменений

| Дата | Изменение | prompt_version | Профиль | precision@1 |
|---|---|---|---|---|
| `<...>` | первая версия | `commander-v1` | `claude-primary` | `<...>` |
