"""Контракт сообщения (§7) и state machine задачи."""

from __future__ import annotations

import copy
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import jsonschema
import pytest

from admintwin_ai.contracts import (
    AgentMessage,
    MessageDeduplicator,
    MessageType,
    TaskState,
    TaskStateMachine,
    allowed_transitions,
    validate_message,
)
from admintwin_ai.errors import ContractValidationError, InvalidTransitionError
from admintwin_ai.resources import load_json

SPEC_TYPES = {
    "task.request", "task.accepted", "task.progress", "task.result", "task.failed",
    "task.blocked", "task.input_required", "task.cancelled", "evidence.added",
    "change.proposed", "approval.requested", "execution.started", "execution.completed",
    "execution.cancellation_pending", "budget.warning", "budget.exhausted",
}


def spec_example() -> dict[str, Any]:
    """Пример из §7 с подставленными UUID."""
    u = lambda: str(uuid.uuid4())  # noqa: E731
    return {
        "schema_version": "1.3",
        "message_id": u(), "tenant_id": u(), "task_id": u(), "parent_task_id": None,
        "correlation_id": u(), "causation_id": u(),
        "from_agent": "ai-commander", "to_agent": "devops-engineer",
        "type": "task.request", "priority": "high", "timestamp": "2026-11-09T05:00:00Z",
        "scope": {"asset_ids": [u()], "environment": "production",
                  "data_sensitivity_max": "confidential"},
        "budget": {"max_tokens": 60000, "max_tool_calls": 25,
                   "deadline_at": "2026-11-09T05:05:00Z"},
        "payload": {"objective": "Diagnose HTTP 502", "constraints": ["read_only"],
                    "context_summary_ref": "evidence://incidents/abc/summary"},
    }


def test_schema_is_valid_and_lists_all_types() -> None:
    schema = load_json("contracts", "agent-message.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    assert set(schema["properties"]["type"]["enum"]) == SPEC_TYPES
    assert {t.value for t in MessageType} == SPEC_TYPES
    assert schema["properties"]["schema_version"] == {"const": "1.3"}
    example_keys = set(spec_example())
    assert example_keys == set(schema["required"]) == set(schema["properties"])


def test_spec_example_validates_and_roundtrips() -> None:
    raw = spec_example()
    validate_message(raw)
    msg = AgentMessage.from_wire(raw)
    assert msg.type is MessageType.TASK_REQUEST
    wire = msg.to_wire()
    assert json.loads(json.dumps(wire))["payload"] == raw["payload"]
    assert AgentMessage.from_wire(wire) == msg


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(schema_version="1.2"),
        lambda m: m.update(type="task.execute"),
        lambda m: m.update(tenant_id="not-a-uuid"),
        lambda m: m.update(from_agent="Bad Agent"),
        lambda m: m.update(extra_field=1),
        lambda m: m["scope"].update(data_sensitivity_max="unknown"),
        lambda m: m["budget"].update(max_tokens=-1),
        lambda m: m["payload"].pop("objective"),
        lambda m: m.pop("causation_id"),
    ],
)
def test_invalid_messages_rejected(mutate: Any) -> None:
    raw = copy.deepcopy(spec_example())
    mutate(raw)
    with pytest.raises(ContractValidationError):
        validate_message(raw)


def test_non_request_types_do_not_need_objective() -> None:
    raw = spec_example()
    raw["type"] = "budget.warning"
    raw["payload"] = {"scope": "task:x", "utilization": 0.83}
    validate_message(raw)


def test_deduplicator() -> None:
    msg = AgentMessage.from_wire(spec_example())
    d = MessageDeduplicator(capacity=2)
    assert d.first_delivery(msg) and not d.first_delivery(msg)


# --- state machine ---------------------------------------------------------------


def _clock() -> datetime:
    return datetime(2026, 11, 9, 5, 0, tzinfo=UTC)


def test_happy_path_with_journal() -> None:
    sm = TaskStateMachine("t1", correlation_id="c1", clock=_clock)
    for target in (TaskState.QUEUED, TaskState.RUNNING, TaskState.WAITING_APPROVAL,
                   TaskState.RUNNING, TaskState.WAITING_INPUT, TaskState.RUNNING,
                   TaskState.BLOCKED, TaskState.RUNNING, TaskState.COMPLETED):
        sm.transition(target, reason=f"to {target}", actor="ai-commander",
                      evidence_ref="evidence://x")
    assert sm.state is TaskState.COMPLETED and sm.terminal
    assert len(sm.journal) == 9
    first = sm.journal[0]
    assert (first.from_state, first.to_state, first.reason, first.actor, first.correlation_id) == (
        TaskState.CREATED, TaskState.QUEUED, "to queued", "ai-commander", "c1")
    assert first.at == _clock()


@pytest.mark.parametrize(
    ("path", "bad"),
    [
        ([], TaskState.RUNNING),  # created -> running
        ([TaskState.QUEUED], TaskState.COMPLETED),
        ([TaskState.QUEUED, TaskState.RUNNING, TaskState.COMPLETED], TaskState.RUNNING),
        ([TaskState.QUEUED, TaskState.RUNNING, TaskState.WAITING_INPUT], TaskState.COMPLETED),
        ([TaskState.QUEUED, TaskState.RUNNING, TaskState.WAITING_APPROVAL], TaskState.TIMED_OUT),
        ([TaskState.QUEUED, TaskState.RUNNING, TaskState.FAILED], TaskState.CANCELLED),
    ],
)
def test_invalid_transitions_raise(path: list[TaskState], bad: TaskState) -> None:
    sm = TaskStateMachine("t1")
    for s in path:
        sm.transition(s, reason="step", actor="x")
    with pytest.raises(InvalidTransitionError):
        sm.transition(bad, reason="nope", actor="x")
    assert len(sm.journal) == len(path)


def test_reason_and_actor_required() -> None:
    sm = TaskStateMachine("t1")
    with pytest.raises(InvalidTransitionError, match="reason"):
        sm.transition(TaskState.QUEUED, reason="  ", actor="x")
    with pytest.raises(InvalidTransitionError, match="actor"):
        sm.transition(TaskState.QUEUED, reason="r", actor="")
    assert sm.state is TaskState.CREATED


def test_timeouts_and_notifications() -> None:
    blocked = TaskStateMachine("t1")
    for s in (TaskState.QUEUED, TaskState.RUNNING, TaskState.BLOCKED):
        blocked.transition(s, reason="r", actor="x")
    rec = blocked.transition(TaskState.TIMED_OUT, reason="deadline_at passed", actor="scheduler")
    assert rec.notify == "requester"
    waiting = TaskStateMachine("t2")
    for s in (TaskState.QUEUED, TaskState.RUNNING, TaskState.WAITING_INPUT):
        waiting.transition(s, reason="r", actor="x")
    rec = waiting.transition(TaskState.CANCELLED, reason="input timeout", actor="scheduler")
    assert rec.notify == "requester"


def test_kill_switch_can_cancel_any_non_terminal_state() -> None:
    for state in TaskState:
        terminal = not allowed_transitions(state)
        assert (TaskState.CANCELLED in allowed_transitions(state)) is not terminal
