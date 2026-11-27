"""Commander (§5.3): детерминированный выбор агентов и таблица гипотез."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from admintwin_ai.agents import AgentRegistry, load_agents
from admintwin_ai.contracts import MessageType
from admintwin_ai.orchestrator import Check, Commander, Hypothesis, HypothesisTable, IncidentContext


@pytest.fixture
def commander() -> Commander:
    return Commander(AgentRegistry(load_agents()))


def _incident(**kw: object) -> IncidentContext:
    base: dict[str, object] = {"tenant_id": uuid.uuid4(), "incident_id": uuid.uuid4(),
                               "asset_ids": [uuid.uuid4()]}
    base.update(kw)
    return IncidentContext.model_validate(base)


def test_http_502_selects_network_devops_dba_in_parallel(commander: Commander) -> None:
    sel = commander.select_agents(_incident(alert_type="http_502", asset_type="load_balancer",
                                            service_kind="reverse_proxy"))
    assert sel.agents == ["dba-engineer", "devops-engineer", "network-engineer"]
    rules = {(r.agent_id, r.rule) for r in sel.reasons}
    assert ("network-engineer", "asset.type=load_balancer") in rules
    assert ("dba-engineer", "alert.type=http_502") in rules


def test_selection_is_deterministic(commander: Commander) -> None:
    ctx = _incident(alert_type="container_stopped", asset_type="docker_host",
                    service_kind="container")
    results = {tuple(commander.select_agents(ctx).agents) for _ in range(20)}
    assert results == {("devops-engineer", "linux-admin")}


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"alert_type": "disk_usage_high", "asset_type": "linux_host"},
         ["dba-engineer", "linux-admin"]),
        ({"asset_type": "fortigate"}, ["network-engineer"]),
        ({"service_kind": "postgres"}, ["dba-engineer"]),
        ({"alert_type": "unknown_alert"}, []),
    ],
)
def test_rules_by_asset_service_alert(commander: Commander, kw: dict[str, str],
                                      expected: list[str]) -> None:
    assert commander.select_agents(_incident(**kw)).agents == expected


def test_parallel_limit(commander: Commander) -> None:
    small = Commander(AgentRegistry(load_agents()), max_parallel_agents=2)
    sel = small.select_agents(_incident(alert_type="http_502", asset_type="load_balancer"))
    # network совпал по двум правилам — приоритетнее
    assert "network-engineer" in sel.agents and len(sel.agents) == 2
    assert len(sel.dropped) == 1


def test_llm_suggestion_confirmed_only_by_rules(commander: Commander) -> None:
    ctx = _incident(alert_type="http_502", related_asset_types=frozenset({"linux_host"}))
    sel = commander.select_agents(ctx)
    ok = commander.confirm_suggestion(ctx, sel, "linux-admin")
    assert ok.accepted and ok.reason == "blast_radius.asset_type"
    assert not commander.confirm_suggestion(ctx, sel, "windows-admin").accepted
    assert commander.confirm_suggestion(ctx, sel, "dba-engineer").reason == "already_selected"
    no_scope = _incident(alert_type="http_502")
    verdict = commander.confirm_suggestion(no_scope, commander.select_agents(no_scope),
                                           "linux-admin")
    assert not verdict.accepted and verdict.reason == "no_rule_matches_incident_scope"


def test_dispatch_builds_valid_read_only_requests(commander: Commander) -> None:
    ctx = _incident(alert_type="http_502", objective="Diagnose HTTP 502")
    sel = commander.select_agents(ctx)
    now = datetime(2026, 11, 9, 5, 0, tzinfo=UTC)
    msgs = commander.dispatch(ctx, sel, context_summary_ref="evidence://inc/summary", now=now)
    assert [m.to_agent for m in msgs] == sel.agents
    for m in msgs:
        wire = m.to_wire()  # валидно по JSON Schema
        assert m.type is MessageType.TASK_REQUEST and m.from_agent == "ai-commander"
        assert wire["payload"]["constraints"] == ["read_only"]
        assert m.correlation_id == ctx.incident_id
        assert m.budget.deadline_at > now
    assert len({m.task_id for m in msgs}) == len(msgs)


# --- гипотезы --------------------------------------------------------------------

CHECK_CONTAINER = Check(tool="docker.container.inspect", description="state of shop-api")
CHECK_DB = Check(tool="postgres.activity", description="connections vs max_connections")


def test_gap_below_threshold_means_uncertainty_with_separating_check() -> None:
    t = HypothesisTable()
    t.add(Hypothesis(cause="upstream_container_stopped", confidence=0.55, proposed_by=["devops"],
                     supporting=["ev-1"], checks=[CHECK_CONTAINER]))
    t.add(Hypothesis(cause="db_connections_exhausted", confidence=0.45, proposed_by=["dba"],
                     supporting=["ev-2"], checks=[CHECK_DB, CHECK_CONTAINER]))
    r = t.resolve()
    assert r.status == "uncertain"
    assert r.gap == pytest.approx(0.1)
    assert r.next_check == CHECK_DB or r.next_check == CHECK_CONTAINER
    assert r.next_check is not None
    assert "неопределённость" in r.message and "нужна проверка" in r.message
    # разделяющая: относится к одной гипотезе, но не к обеим
    assert r.next_check == CHECK_DB


def test_boundary_gap_exactly_02_is_confident() -> None:
    t = HypothesisTable()
    t.add(Hypothesis(cause="a", confidence=0.7, supporting=["e1"]))
    t.add(Hypothesis(cause="b", confidence=0.5, supporting=["e2"]))
    r = t.resolve()
    assert r.status == "confident" and r.leader is not None and r.leader.cause == "a"
    assert r.gap == pytest.approx(0.2)


def test_no_root_cause_without_evidence() -> None:
    t = HypothesisTable()
    t.add(Hypothesis(cause="a", confidence=0.9, checks=[CHECK_CONTAINER]))
    r = t.resolve()
    assert r.status == "insufficient_evidence" and r.next_check == CHECK_CONTAINER


def test_merge_refute_exclude_and_summary() -> None:
    t = HypothesisTable()
    t.add(Hypothesis(cause="a", confidence=0.6, proposed_by=["devops"], supporting=["e1"]))
    t.add(Hypothesis(cause="a", confidence=0.8, proposed_by=["network"], supporting=["e2"]))
    t.add(Hypothesis(cause="firewall_block", confidence=0.5, proposed_by=["network"],
                     refuting=["e3"]))
    t.add_fact("e4", "policy 12 hit_count unchanged")
    merged = t.ranked()[0]
    assert merged.confidence == 0.8 and merged.proposed_by == ["devops", "network"]
    assert merged.supporting == ["e1", "e2"]
    r = t.resolve()
    assert r.status == "confident" and r.runner_up is None
    s = t.summary()
    assert s["excluded_causes"] == ["firewall_block"]
    assert s["evidence_ids"] == ["e1", "e2", "e3", "e4"]
    assert s["facts"][0]["evidence_id"] == "e4"


def test_empty_table() -> None:
    assert HypothesisTable().resolve().status == "no_hypotheses"
