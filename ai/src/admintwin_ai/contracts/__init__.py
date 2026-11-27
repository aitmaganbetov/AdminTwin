"""Контракты межагентного взаимодействия и state machine задачи (§7)."""

from admintwin_ai.contracts.messages import (
    AgentMessage,
    MessageBudget,
    MessageDeduplicator,
    MessageScope,
    MessageType,
    validate_message,
)
from admintwin_ai.contracts.task_state import (
    TaskState,
    TaskStateMachine,
    TransitionRecord,
    allowed_transitions,
)

__all__ = [
    "AgentMessage",
    "MessageBudget",
    "MessageDeduplicator",
    "MessageScope",
    "MessageType",
    "TaskState",
    "TaskStateMachine",
    "TransitionRecord",
    "allowed_transitions",
    "validate_message",
]
