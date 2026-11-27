# Model card: <agent id> (шаблон)

> Шаблон model card агента AdminTwin (ТЗ §6.10, ISO/IEC 42001 / NIST AI RMF — Приложение A).
> Заполняется на каждого агента и обновляется при смене `prompt_version`, Model Profile,
> провайдера или Tool Layer. Поля в `<...>` — обязательны к заполнению перед релизом.

## 1. Идентификация

| Поле | Значение |
|---|---|
| Агент | `<id>` (`<name>`), версия `<x.y.z>` |
| Промпт | `agents/prompts/<prompt_version>.md` + `_common.md` |
| Model Profile | primary `<profile>`, fallback `<profile>` (`config/model-profiles*.yaml`) |
| Требуемые capabilities модели | `<tool_calling, structured_output>`, контекст ≥ `<N>` |
| Владелец | `<команда / ответственный>` |
| Дата ревью | `<YYYY-MM-DD>` |

## 2. Назначение и границы

- Назначение: `<что диагностирует>`.
- Уровни операций: observe / diagnose / recommend / propose (никогда execute, approve).
- Разрешённые инструменты: `<allowed_tools>`; runbooks для `change.propose`: `<allowed_runbooks>`.
- Класс данных ответа ≤ `<data_sensitivity_max>`; секреты агенту не выдаются никогда.
- Вне области: `<что агент не делает>`.

## 3. Данные и маршрутизация

- Источники данных: read tools ядра (`POST /api/v1/tools/{name}`), все ответы — недоверенные данные.
- `pii`/`secret` → только Local; `unknown` → fail closed (§6.4). Маскирование для внешних провайдеров.
- Бюджет: `<tokens / tool_calls / wall_time>`; при исчерпании — `blocked`.

## 4. Оценка качества (golden dataset `evals/golden/mvp-v2.jsonl`)

| Профиль | precision@1 | precision@3 | ложно-уверенные | необоснованные отказы | tool calls до верной |
|---|---|---|---|---|---|
| `offline-fake` (регрессия пайплайна, не модели) | см. `evals/baselines/offline-fake.json` | | | | |
| `<claude-primary>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |
| `<local-default>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |

Команда: `python -m admintwin_ai.evals.run --profile <profile> --output <file>.json`.
Порог релиза: precision@1 ≥ 70% (primary), падение ≤ 5 п.п. к baseline, ложно-уверенных < 5%.

## 5. Риски и меры (AI risk register, M26)

| Риск | Мера | Тест |
|---|---|---|
| Prompt injection через данные | обёртка «данные, не инструкции», Tool Layer, Policy Engine | T-AI-001 |
| Галлюцинация evidence | оркестратор отбрасывает неизвестные evidence_id, confidence ≤ 0.5 без evidence | `test_findings_cases.py` |
| Утечка ПДн во внешний LLM | классификация + маскирование + fail closed | маркерный тест |
| Ложно-уверенный вывод | правило разрыва < 0.2 → «неопределённость, нужна проверка X» | `test_rca_flow.py` |
| `<специфичный риск агента>` | `<мера>` | `<тест>` |

## 6. Ограничения и известные проблемы

- `<...>`

## 7. История изменений

| Дата | Изменение | prompt_version | Профиль | precision@1 |
|---|---|---|---|---|
| `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |
