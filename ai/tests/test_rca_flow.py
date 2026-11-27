"""Commander RCA (§5.3, §21): параллельные агенты, таблица гипотез, разделяющая проверка,
результат в ядро (contracts §3), стоимость, кейсы, деградация (§17.2), бюджеты (§6.6)."""

from __future__ import annotations

import json
import uuid

import pytest

from admintwin_ai.budgets import BudgetLedger
from admintwin_ai.contracts.task_state import TaskState
from admintwin_ai.errors import ProviderUnavailableError
from admintwin_ai.evals.fake_model import ScriptedDiagnostician
from admintwin_ai.orchestrator.cases import RcaCase
from admintwin_ai.orchestrator.engine import BudgetSettings
from admintwin_ai.orchestrator.tasks import Task
from admintwin_ai.providers.base import CompletionRequest, CompletionResult
from admintwin_ai.service.runtime import fake_registry

from support import TENANT_A
from svc import MVP_PROFILES, TOKEN, CoreMock, golden, make_runtime, scope_of, wait_for

INCIDENT = "cccccccc-0000-4000-8000-0000000000aa"
TERMINAL_OR_BLOCKED = (TaskState.COMPLETED, TaskState.FAILED, TaskState.BLOCKED,
                       TaskState.CANCELLED, TaskState.TIMED_OUT)


async def _run(case_id: str, **kw: object) -> tuple[Task, CoreMock, object]:
    case = golden(case_id)
    rt, core = make_runtime(case=case, **kw)  # type: ignore[arg-type]
    orch = rt.orchestrator
    await orch.start()
    task = orch.manager.create(tenant_id=TENANT_A, kind="rca", incident_id=INCIDENT,
                               objective=case.input["alert"]["summary"],
                               asset_ids=scope_of(case))
    orch.manager.start(task)
    await wait_for(task, TERMINAL_OR_BLOCKED)
    for _ in range(50):  # отправка RCA в ядро — фоновая
        if core.rca_posts() or task.state is TaskState.BLOCKED:
            break
        import asyncio
        await asyncio.sleep(0.01)
    return task, core, orch


async def test_http_502_runs_network_devops_dba_in_parallel_and_posts_rca() -> None:
    task, core, orch = await _run("http502-upstream-oom-002")
    try:
        assert task.state is TaskState.COMPLETED, task.reason
        assert sorted(task.agents) == ["dba-engineer", "devops-engineer", "network-engineer"]
        children = [orch.manager.get(c) for c in task.children]  # type: ignore[attr-defined]
        assert {c.agent_id for c in children} == set(task.agents)
        # параллельность: все подзадачи приняты до того, как какая-либо завершилась
        events = task.events.since(0)  # type: ignore[union-attr]
        accepted = [e.id for e in events if e.data.get("reason") == "task.accepted"]
        finished = [e.id for e in events if e.type == "task.result"
                    and e.data.get("task_id") != task.id]
        assert len(accepted) == 3 and max(accepted) < min(finished)
        # каждое сообщение межагентной шины валидно по контракту §7
        bus_types = {m["type"] for m in orch.bus.published}  # type: ignore[attr-defined]
        assert {"task.request", "task.accepted", "task.result", "evidence.added"} <= bus_types
        requests = [m for m in orch.bus.published  # type: ignore[attr-defined]
                    if m["type"] == "task.request"]
        assert all(m["payload"]["constraints"] == ["read_only"] for m in requests)
        assert all(m["parent_task_id"] == task.id for m in requests)
        # результат в ядро — ровно по контракту §3, от имени сервиса orchestrator
        posts = core.rca_posts()
        assert len(posts) == 1
        req = posts[0]
        assert req.url.path == f"/api/v1/incidents/{INCIDENT}/rca"
        assert req.headers["X-AdminTwin-Actor"] == "orchestrator"
        assert req.headers["X-AdminTwin-Actor-Kind"] == "service"
        assert req.headers["X-AdminTwin-Tenant"] == TENANT_A
        assert req.headers["X-AdminTwin-Service-Token"] == TOKEN
        body = json.loads(req.content)
        assert set(body) == {"task_id", "status", "hypotheses", "conclusion",
                             "uncertainty_check", "agents", "cost_usd", "proposed_changes"}
        assert body["status"] == "completed" and body["task_id"] == task.id
        top = body["hypotheses"][0]
        assert set(top) == {"cause", "confidence", "supporting", "refuting", "next_checks"}
        assert top["cause"] == "upstream_container_oom"
        assert top["supporting"] and all(set(s) == {"fact", "evidence_id"}
                                         for s in top["supporting"])
        assert body["cost_usd"] > 0
        # специалист предложил изменение (не согласовал): ChangeRequest ждёт человека
        assert body["proposed_changes"]
        change_reqs = [r for r in core.requests if r.url.path == "/api/v1/changes"]
        assert len(change_reqs) == 1
        assert change_reqs[0].headers["X-AdminTwin-Actor"] == "devops-engineer"
        assert change_reqs[0].headers["X-AdminTwin-Actor-Kind"] == "ai_agent"
        assert change_reqs[0].headers["X-AdminTwin-Service-Token"] == TOKEN
        assert not any("approve" in p or "decision" in p for p in core.paths())
    finally:
        await orch.close()  # type: ignore[attr-defined]


async def test_costs_tracked_per_provider_and_streamed() -> None:
    task, _, orch = await _run("http502-db-connections-004")
    try:
        cost_events = [e for e in task.events.since(0) if e.type == "cost"]  # type: ignore[union-attr]
        assert cost_events
        assert set(task.cost_by_provider) == {"offline-fake"}
        assert task.cost_usd == pytest.approx(sum(task.cost_by_provider.values()))
        assert cost_events[-1].data["total_usd"] == pytest.approx(task.cost_usd)
        assert task.result is not None and task.result["cost_usd"] == pytest.approx(
            task.cost_usd, abs=1e-6)
    finally:
        await orch.close()  # type: ignore[attr-defined]


async def test_conflict_triggers_exactly_one_separating_check() -> None:
    task, _, orch = await _run("http502-conflict-db-vs-loop-009")
    try:
        events = task.events.since(0)  # type: ignore[union-attr]
        checks = [e for e in events if e.data.get("event") == "separating_check"]
        assert len(checks) == 1
        assert checks[0].data["gap"] < 0.2
        assert checks[0].data["tool"] == "logs.search"
        check_calls = [e for e in events if e.type == "tool_call"
                       and e.data.get("evidence_id") == "ev-check-1"]
        assert len(check_calls) == 1
        assert task.result is not None
        assert task.result["status"] == "completed"
        assert task.result["hypotheses"][0]["cause"] == "db_connections_exhausted"
        ids = [s["evidence_id"] for s in task.result["hypotheses"][0]["supporting"]]
        assert "ev-check-1" in ids
        # Commander пересчитал гипотезы после проверки
        assert any(e.type == "hypothesis" and e.data.get("after_check") == "ev-check-1"
                   for e in events)
    finally:
        await orch.close()  # type: ignore[attr-defined]


class _NoDiffCommander(ScriptedDiagnostician):
    """Commander, для которого проверка не различает гипотезы."""

    def complete(self, request: CompletionRequest) -> CompletionResult:
        if "mode: adjudicate" in (request.system or ""):
            return CompletionResult(text=json.dumps({"hypotheses": [],
                                                     "conclusion": "не различает"}))
        return super().complete(request)


async def test_gap_below_threshold_reports_uncertainty_with_check() -> None:
    registry = fake_registry(MVP_PROFILES, provider=_NoDiffCommander())
    task, core, orch = await _run("http502-conflict-db-vs-loop-009", registry=registry)
    try:
        assert task.result is not None
        assert task.result["status"] == "uncertain"
        assert task.result["uncertainty_check"]
        assert "нужна проверка" in task.result["conclusion"]
        body = json.loads(core.rca_posts()[0].content)
        assert body["status"] == "uncertain"
        top2 = body["hypotheses"][:2]
        assert abs(top2[0]["confidence"] - top2[1]["confidence"]) < 0.2
    finally:
        await orch.close()  # type: ignore[attr-defined]


async def test_structured_summary_is_passed_to_commander_and_evidence_validated() -> None:
    provider = ScriptedDiagnostician()
    registry = fake_registry(MVP_PROFILES, provider=provider)
    task, _, orch = await _run("http502-conflict-db-vs-loop-009", registry=registry)
    try:
        adjudications = [r for r in provider.requests if "mode: adjudicate" in (r.system or "")]
        assert len(adjudications) == 1
        text = adjudications[0].messages[0].content
        assert "tool=agents.summary" in text  # summary агентов — как недоверенные данные
        assert '"excluded_causes"' in text and '"evidence_ids"' in text
        # в результате нет ссылок на evidence, которых не было в задаче
        known = set(task.context["evidence_index"])
        for h in task.result["hypotheses"]:  # type: ignore[index]
            for ref in h["supporting"] + h["refuting"]:
                assert ref["evidence_id"] in known
    finally:
        await orch.close()  # type: ignore[attr-defined]


async def test_similar_confirmed_cases_from_same_tenant_are_in_context() -> None:
    case = golden("http502-upstream-oom-002")
    rt, _ = make_runtime(case=case)
    orch = rt.orchestrator
    orch.cases.upsert(RcaCase(tenant_id=TENANT_A, incident_id="old-1",
                              cause="upstream_container_oom", confirmed=True,
                              summary="HTTP 502: shop-api OOM killed", alert_type="http_502"))
    orch.cases.upsert(RcaCase(tenant_id="22222222-2222-4222-8222-222222222222",
                              incident_id="foreign-1", cause="secret_cause_of_b",
                              confirmed=True, summary="HTTP 502 other tenant",
                              alert_type="http_502"))
    provider = rt.profiles.provider_for("claude-primary")
    await orch.start()
    try:
        task = orch.manager.create(tenant_id=TENANT_A, kind="diagnose",
                                   objective="HTTP 502 on shop", asset_ids=scope_of(case))
        orch.manager.start(task)
        await wait_for(task, TERMINAL_OR_BLOCKED)
        first = provider.requests[0].messages[0].content  # type: ignore[attr-defined]
        assert "old-1" in first and "upstream_container_oom" in first
        assert "secret_cause_of_b" not in "\n".join(
            m.content for r in provider.requests for m in r.messages)  # type: ignore[attr-defined]
    finally:
        await orch.close()


async def test_completed_rca_becomes_candidate_case_confirmed_by_feedback() -> None:
    _task, _, orch = await _run("http502-upstream-oom-002")
    try:
        case = orch.cases.get(TENANT_A, INCIDENT)  # type: ignore[attr-defined]
        assert case is not None and not case.confirmed
        orch.cases.confirm(TENANT_A, INCIDENT, correct=True)  # type: ignore[attr-defined]
        assert orch.cases.similar(TENANT_A, "http_502 upstream oom")  # type: ignore[attr-defined]
    finally:
        await orch.close()  # type: ignore[attr-defined]


class _Down(ScriptedDiagnostician):
    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        raise ProviderUnavailableError("connection refused", provider="offline-fake")


async def test_all_llms_down_blocks_task_with_clear_reason() -> None:
    registry = fake_registry(MVP_PROFILES, provider=_Down(external=True))
    task, core, orch = await _run("http502-upstream-oom-002", registry=registry)
    try:
        assert task.state is TaskState.BLOCKED
        assert task.reason is not None and task.reason.startswith("llm.unavailable")
        assert "§17.2" in task.reason
        blocked = [e for e in task.events.since(0) if e.type == "task.blocked"  # type: ignore[union-attr]
                   and e.data["task_id"] == task.id]
        assert blocked and "llm.unavailable" in blocked[0].data["reason"]
        assert core.rca_posts() == []  # blocked — не терминальное состояние
    finally:
        await orch.close()  # type: ignore[attr-defined]


class _PartiallyDown(ScriptedDiagnostician):
    def complete(self, request: CompletionRequest) -> CompletionResult:
        if "agent_id: network-engineer;" in (request.system or ""):
            raise ProviderUnavailableError("down", provider="offline-fake")
        return super().complete(request)


async def test_one_agent_without_llm_does_not_stop_rca() -> None:
    registry = fake_registry(MVP_PROFILES, provider=_PartiallyDown())
    task, _, orch = await _run("http502-upstream-oom-002", registry=registry)
    try:
        assert task.state is TaskState.COMPLETED
        assert "network-engineer" in task.result["conclusion"]  # type: ignore[index]
        net = [orch.manager.get(c) for c in task.children]  # type: ignore[attr-defined]
        assert any(c.agent_id == "network-engineer" and c.state is TaskState.BLOCKED
                   for c in net)
    finally:
        await orch.close()  # type: ignore[attr-defined]


async def test_budget_exhausted_blocks_task_and_other_tenants_keep_working() -> None:
    ledger = BudgetLedger()
    budgets = BudgetSettings(tenant_tokens_per_day=1500)
    task, _, orch = await _run("http502-upstream-oom-002", budgets=budgets, ledger=ledger)
    try:
        assert task.state is TaskState.BLOCKED
        assert task.reason is not None and task.reason.startswith("budget.exhausted")
        assert f"tenant:{TENANT_A}" in task.reason
        assert any(e.type == "budget.exhausted" for e in task.events.since(0))  # type: ignore[union-attr]
        # бюджет tenant A не останавливает AI-функции tenant B
        other = "22222222-2222-4222-8222-222222222222"
        task_b = orch.manager.create(tenant_id=other, kind="diagnose",  # type: ignore[attr-defined]
                                     objective="HTTP 502", asset_ids=[])
        orch.manager.start(task_b)  # type: ignore[attr-defined]
        await wait_for(task_b, TERMINAL_OR_BLOCKED)
        assert not (task_b.reason or "").startswith("budget.exhausted")
    finally:
        await orch.close()  # type: ignore[attr-defined]


async def test_blocked_task_times_out_and_reports_failed_rca() -> None:
    from admintwin_ai.orchestrator.engine import EngineSettings

    registry = fake_registry(MVP_PROFILES, provider=_Down())
    engine = EngineSettings(blocked_timeout_s=0.2, result_grace_s=5.0)
    task, core, orch = await _run("http502-upstream-oom-002", registry=registry, engine=engine)
    try:
        await wait_for(task, [TaskState.TIMED_OUT], timeout_s=5)
        import asyncio
        for _ in range(100):
            if core.rca_posts():
                break
            await asyncio.sleep(0.01)
        body = json.loads(core.rca_posts()[0].content)
        assert body["status"] == "failed" and "timed_out" in body["conclusion"]
        rec = task.sm.journal[-1]
        assert rec.notify == "requester"  # blocked → timed_out с уведомлением (§7)
    finally:
        await orch.close()  # type: ignore[attr-defined]


async def test_no_selectable_agent_waits_for_input_then_continues() -> None:
    case = golden("http502-upstream-oom-002")
    rt, _ = make_runtime(case=case)
    orch = rt.orchestrator
    await orch.start()
    try:
        # актив без событий и без ключевых слов в objective → тип алерта неизвестен
        backend = orch.invoker._assets  # type: ignore[attr-defined]
        backend._fixtures["events.list"] = [{"match": {}, "response": {"events": []}}]
        task = orch.manager.create(tenant_id=TENANT_A, kind="diagnose", objective="проверь",
                                   asset_ids=[scope_of(case)[2]])  # database-only
        # database-актив совпадает с dba по asset.type → убираем, оставляем неизвестный тип
        backend._assets[scope_of(case)[2]]["type"] = "unknown_box"
        orch.manager.start(task)
        await wait_for(task, [TaskState.WAITING_INPUT])
        assert task.question and "уточните тип" in task.question
        orch.manager.provide_input(task, "502 bad gateway")
        await wait_for(task, TERMINAL_OR_BLOCKED)
        assert task.context["alert_type"] == "http_502"
        assert task.context["alert_rule"] == "requester.input"
        states = [r.to_state for r in task.sm.journal]
        assert TaskState.WAITING_INPUT in states and states.count(TaskState.RUNNING) == 2
    finally:
        await orch.close()


async def test_every_transition_is_journaled_with_reason() -> None:
    task, _, orch = await _run("http502-upstream-oom-002")
    try:
        all_tasks = [task, *[orch.manager.get(c) for c in task.children]]  # type: ignore[attr-defined]
        for t in all_tasks:
            assert t.sm.journal
            for rec in t.sm.journal:
                assert rec.reason.strip() and rec.actor
        assert [r.to_state for r in task.sm.journal][:2] == [TaskState.QUEUED, TaskState.RUNNING]
    finally:
        await orch.close()  # type: ignore[attr-defined]


def test_incident_ids_need_not_be_uuids() -> None:
    from admintwin_ai.orchestrator.engine import _as_uuid

    assert _as_uuid("INC-42") == _as_uuid("INC-42")
    assert isinstance(_as_uuid(str(uuid.uuid4())), uuid.UUID)
