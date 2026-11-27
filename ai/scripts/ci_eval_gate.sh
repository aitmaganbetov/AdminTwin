#!/usr/bin/env bash
# CI gate регрессии AI (ТЗ §6.10): офлайн-прогон golden dataset через полный путь
# оркестратора детерминированной моделью и сравнение с baseline.
# Блокирует при падении precision@1 > 5 п.п., precision@1 < 70% или ложно-уверенных ≥ 5%.
# Реальные LLM не вызываются никогда.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-.venv/bin/python}"
"$PY" -m admintwin_ai.evals.gate --run --profile offline --offline-fake \
  --baseline evals/baselines/offline-fake.json --max-drop-pp 5
