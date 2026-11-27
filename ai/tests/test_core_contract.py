"""Межъязыковой контракт: тело POST /v1/tasks, которое формирует ядро (Go, services/incidents),
принимается оркестратором без изменений. Образец — docs/api/fixtures/core_rca_task.json;
Go-сторона проверяет, что сериализует ровно тот же набор полей."""

import json
from pathlib import Path

from admintwin_ai.service.app import TaskCreate

FIXTURE = Path(__file__).resolve().parents[2] / "docs" / "api" / "fixtures" / "core_rca_task.json"


def test_core_rca_task_is_accepted() -> None:
    body = json.loads(FIXTURE.read_text(encoding="utf-8"))
    task = TaskCreate.model_validate(body)
    assert task.kind == "rca"
    assert task.context is not None and task.context.alert_type == "http_5xx"
    assert task.context.events[0].evidence_ref.startswith("event:")
