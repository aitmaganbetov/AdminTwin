"""Скелет AdminTwin Commander (§5.3). Чистый Python без LangGraph
(ADR-005 открыт): логика выбора агентов и разрешения противоречий не
зависит от движка оркестрации и может быть перенесена в узлы графа.

* Выбор агентов — детерминированные правила по ``asset.type``,
  ``service.kind`` и типу алерта (правила — данные в Agent Registry,
  ``AgentDefinition.routing``). LLM может предложить дополнительного агента;
  Commander подтверждает предложение по тем же правилам.
* Параллельная read-only диагностика: на каждого выбранного агента —
  сообщение ``task.request`` с ограничением ``read_only``.
* Разрешение противоречий: таблица «гипотеза × подтверждающие/опровергающие
  факты», confidence; при разрыве confidence между лидерами < 0.2 — вывод
  «неопределённость, нужна проверка X» с одной разделяющей безопасной проверкой.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field

from admintwin_ai.agents.model import AgentDefinition
from admintwin_ai.agents.registry import AgentRegistry
from admintwin_ai.contracts.messages import (
    AgentMessage,
    Environment,
    MessageBudget,
    MessageScope,
    MessageType,
    Priority,
    Sensitivity,
)

COMMANDER_ID = "ai-commander"
UNCERTAINTY_GAP = 0.2


# --- выбор агентов -----------------------------------------------------------


class IncidentContext(BaseModel):
    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    alert_type: str | None = None
    asset_type: str | None = None
    service_kind: str | None = None
    asset_ids: list[uuid.UUID] = Field(default_factory=list)
    # типы активов/сервисов из blast radius — основание для подтверждения предложений LLM
    related_asset_types: frozenset[str] = frozenset()
    related_service_kinds: frozenset[str] = frozenset()
    environment: Environment = "production"
    data_sensitivity_max: Sensitivity = "confidential"
    priority: Priority = "high"
    objective: str = "Diagnose incident"


class SelectionReason(BaseModel):
    agent_id: str
    rule: str  # например "alert.type=http_502"


class Selection(BaseModel):
    agents: list[str]
    reasons: list[SelectionReason]
    dropped: list[str] = Field(default_factory=list)  # превышение лимита параллельности


class SuggestionVerdict(BaseModel):
    agent_id: str
    accepted: bool
    reason: str


def _matches(agent: AgentDefinition, ctx: IncidentContext) -> list[str]:
    rules: list[str] = []
    r = agent.routing
    if ctx.alert_type and ctx.alert_type in r.alert_types:
        rules.append(f"alert.type={ctx.alert_type}")
    if ctx.asset_type and ctx.asset_type in r.asset_types:
        rules.append(f"asset.type={ctx.asset_type}")
    if ctx.service_kind and ctx.service_kind in r.service_kinds:
        rules.append(f"service.kind={ctx.service_kind}")
    return rules


class Commander:
    def __init__(self, agents: AgentRegistry, *, max_parallel_agents: int = 4,
                 commander_id: str = COMMANDER_ID) -> None:
        self._agents = agents
        self._max_parallel = max_parallel_agents
        self._commander_id = commander_id

    def _candidates(self) -> list[AgentDefinition]:
        return sorted((a for a in self._agents.all()
                       if a.id != self._commander_id and a.is_active), key=lambda a: a.id)

    def select_agents(self, ctx: IncidentContext) -> Selection:
        scored: list[tuple[int, str, list[str]]] = []
        for agent in self._candidates():
            rules = _matches(agent, ctx)
            if rules:
                scored.append((len(rules), agent.id, rules))
        # детерминированно: больше совпавших правил — выше; затем по id
        scored.sort(key=lambda s: (-s[0], s[1]))
        chosen = scored[: self._max_parallel]
        dropped = [s[1] for s in scored[self._max_parallel:]]
        reasons = [SelectionReason(agent_id=aid, rule=rule) for _, aid, rules in chosen
                   for rule in rules]
        return Selection(agents=sorted(aid for _, aid, _ in chosen), reasons=reasons,
                         dropped=dropped)

    def confirm_suggestion(self, ctx: IncidentContext, selection: Selection,
                           agent_id: str) -> SuggestionVerdict:
        """Предложение LLM добавить агента подтверждается только правилами."""
        if agent_id not in self._agents or agent_id == self._commander_id:
            return SuggestionVerdict(agent_id=agent_id, accepted=False, reason="unknown_agent")
        agent = self._agents.get(agent_id)
        if not agent.is_active:
            return SuggestionVerdict(agent_id=agent_id, accepted=False, reason="agent_not_active")
        if agent_id in selection.agents:
            return SuggestionVerdict(agent_id=agent_id, accepted=False, reason="already_selected")
        if len(selection.agents) >= self._max_parallel:
            return SuggestionVerdict(agent_id=agent_id, accepted=False,
                                     reason="parallel_agent_limit")
        r = agent.routing
        if r.asset_types & ctx.related_asset_types:
            return SuggestionVerdict(agent_id=agent_id, accepted=True,
                                     reason="blast_radius.asset_type")
        if r.service_kinds & ctx.related_service_kinds:
            return SuggestionVerdict(agent_id=agent_id, accepted=True,
                                     reason="blast_radius.service_kind")
        return SuggestionVerdict(agent_id=agent_id, accepted=False,
                                 reason="no_rule_matches_incident_scope")

    def dispatch(self, ctx: IncidentContext, selection: Selection, *,
                 parent_task_id: uuid.UUID | None = None,
                 correlation_id: uuid.UUID | None = None,
                 causation_id: uuid.UUID | None = None,
                 context_summary_ref: str | None = None,
                 now: datetime | None = None) -> list[AgentMessage]:
        """Параллельные read-only подзадачи: по одному ``task.request`` на агента."""
        now = now or datetime.now(UTC)
        correlation_id = correlation_id or ctx.incident_id
        causation_id = causation_id or ctx.incident_id
        messages: list[AgentMessage] = []
        for agent_id in selection.agents:
            agent = self._agents.get(agent_id)
            payload: dict[str, Any] = {"objective": ctx.objective, "constraints": ["read_only"]}
            if context_summary_ref:
                payload["context_summary_ref"] = context_summary_ref
            messages.append(AgentMessage(
                tenant_id=ctx.tenant_id, task_id=uuid.uuid4(), parent_task_id=parent_task_id,
                correlation_id=correlation_id, causation_id=causation_id,
                from_agent=self._commander_id, to_agent=agent_id,
                type=MessageType.TASK_REQUEST, priority=ctx.priority, timestamp=now,
                scope=MessageScope(asset_ids=ctx.asset_ids, environment=ctx.environment,
                                   data_sensitivity_max=_min_sensitivity(
                                       ctx.data_sensitivity_max,
                                       agent.data_sensitivity_max.value)),
                budget=MessageBudget(max_tokens=agent.budget.tokens,
                                     max_tool_calls=agent.budget.tool_calls,
                                     deadline_at=now + timedelta(seconds=agent.budget.wall_time_s)),
                payload=payload,
            ))
        return messages


_SENS_ORDER = ["public", "internal", "confidential", "pii", "secret"]


def _min_sensitivity(a: str, b: str) -> Sensitivity:
    value = min(a, b, key=_SENS_ORDER.index)
    return value  # type: ignore[return-value]


# --- гипотезы ----------------------------------------------------------------


class Check(BaseModel):
    """Безопасная (read-only) проверка, различающая гипотезы."""

    tool: str
    description: str
    params: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return self.tool, self.description


class Hypothesis(BaseModel):
    cause: str  # код причины, например "upstream_container_down"
    statement: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    proposed_by: list[str] = Field(default_factory=list)
    supporting: list[str] = Field(default_factory=list)  # evidence IDs
    refuting: list[str] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)


class Resolution(BaseModel):
    status: Literal["confident", "uncertain", "insufficient_evidence", "no_hypotheses"]
    leader: Hypothesis | None = None
    runner_up: Hypothesis | None = None
    gap: float | None = None
    next_check: Check | None = None
    message: str


class HypothesisTable:
    def __init__(self, *, uncertainty_gap: float = UNCERTAINTY_GAP,
                 exclusion_threshold: float = 0.05) -> None:
        self._by_cause: dict[str, Hypothesis] = {}
        self._facts: list[tuple[str, str]] = []
        self._gap = uncertainty_gap
        self._exclusion = exclusion_threshold

    def add(self, h: Hypothesis) -> Hypothesis:
        """Гипотезы с одинаковой причиной от разных агентов объединяются."""
        existing = self._by_cause.get(h.cause)
        if existing is None:
            self._by_cause[h.cause] = h
            return h
        merged = existing.model_copy(update={
            "confidence": max(existing.confidence, h.confidence),
            "statement": existing.statement or h.statement,
            "proposed_by": _union(existing.proposed_by, h.proposed_by),
            "supporting": _union(existing.supporting, h.supporting),
            "refuting": _union(existing.refuting, h.refuting),
            "checks": existing.checks + [c for c in h.checks
                                         if c.key not in {x.key for x in existing.checks}],
        })
        self._by_cause[h.cause] = merged
        return merged

    def add_fact(self, evidence_id: str, statement: str) -> None:
        self._facts.append((evidence_id, statement))

    def ranked(self) -> list[Hypothesis]:
        return sorted(self._by_cause.values(), key=lambda h: (-h.confidence, h.cause))

    def excluded(self) -> list[Hypothesis]:
        return [h for h in self.ranked()
                if (h.refuting and not h.supporting) or h.confidence < self._exclusion]

    def resolve(self) -> Resolution:
        excluded = {h.cause for h in self.excluded()}
        active = [h for h in self.ranked() if h.cause not in excluded]
        if not active:
            return Resolution(status="no_hypotheses",
                              message="нет действующих гипотез; требуется дополнительный сбор")
        leader = active[0]
        runner = active[1] if len(active) > 1 else None
        if runner is not None:
            gap = round(leader.confidence - runner.confidence, 6)
            if gap < self._gap:
                check = _separating_check(leader, runner)
                what = f"{check.tool}: {check.description}" if check else "дополнительные данные"
                return Resolution(
                    status="uncertain", leader=leader, runner_up=runner, gap=gap, next_check=check,
                    message=(f"неопределённость: разрыв confidence {gap:.2f} < {self._gap:.2f} "
                             f"между '{leader.cause}' и '{runner.cause}', нужна проверка {what}"),
                )
        else:
            gap = None
        if not leader.supporting:
            check = leader.checks[0] if leader.checks else None
            return Resolution(
                status="insufficient_evidence", leader=leader, runner_up=runner, gap=gap,
                next_check=check,
                message=f"первопричина '{leader.cause}' не утверждается без evidence",
            )
        return Resolution(status="confident", leader=leader, runner_up=runner, gap=gap,
                          message=f"наиболее вероятная причина: '{leader.cause}' "
                                  f"(confidence {leader.confidence:.2f})")

    def summary(self) -> dict[str, Any]:
        """Структурированный summary для передачи между агентами (§5.3)."""
        evidence = sorted({e for h in self._by_cause.values() for e in h.supporting + h.refuting}
                          | {eid for eid, _ in self._facts})
        return {
            "facts": [{"evidence_id": eid, "statement": s} for eid, s in self._facts],
            "evidence_ids": evidence,
            "hypotheses": [{"cause": h.cause, "confidence": h.confidence,
                            "supporting": h.supporting, "refuting": h.refuting}
                           for h in self.ranked()],
            "excluded_causes": [h.cause for h in self.excluded()],
        }


def _union(a: list[str], b: list[str]) -> list[str]:
    return list(dict.fromkeys([*a, *b]))


def _separating_check(a: Hypothesis, b: Hypothesis) -> Check | None:
    """Одна проверка, относящаяся к одной гипотезе, но не к другой."""
    b_keys = {c.key for c in b.checks}
    for c in a.checks:
        if c.key not in b_keys:
            return c
    a_keys = {c.key for c in a.checks}
    for c in b.checks:
        if c.key not in a_keys:
            return c
    return a.checks[0] if a.checks else (b.checks[0] if b.checks else None)
