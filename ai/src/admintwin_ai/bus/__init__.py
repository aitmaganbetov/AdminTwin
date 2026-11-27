"""Межагентная шина (§7): in-process (по умолчанию) и NATS JetStream."""

from __future__ import annotations

from admintwin_ai.bus.base import (
    CONTROL_CANCEL,
    AgentBus,
    DeadLetter,
    DeliveryPolicy,
    Handler,
    dlq_subject_for,
    subject_for,
)
from admintwin_ai.bus.inprocess import InProcessBus


def build_bus(nats_url: str | None, policy: DeliveryPolicy | None = None) -> AgentBus:
    """``ADMINTWIN_NATS_URL`` задан — NATS JetStream, иначе in-process."""
    if nats_url:
        from admintwin_ai.bus.nats_bus import NatsBus

        return NatsBus(nats_url, policy=policy)
    return InProcessBus(policy)


__all__ = [
    "CONTROL_CANCEL",
    "AgentBus",
    "DeadLetter",
    "DeliveryPolicy",
    "Handler",
    "InProcessBus",
    "build_bus",
    "dlq_subject_for",
    "subject_for",
]
