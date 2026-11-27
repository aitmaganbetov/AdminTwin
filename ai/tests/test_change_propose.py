"""change.propose → POST {core}/api/v1/changes (httpx MockTransport)."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from admintwin_ai.agents import AgentDefinition
from admintwin_ai.audit import InMemoryAuditSink
from admintwin_ai.tools import (
    ChangeProposeHandler,
    InMemoryReadBackend,
    ToolInvoker,
    ToolRegistry,
    build_tool_registry,
    parse_wrapped,
)

from support import ASSET_B_ONLY, ASSET_WEB, CORE_URL, INCIDENT, TENANT_A, CoreRecorder, ctx_for

PROPOSAL = {
    "runbook_id": "docker.container.restart",
    "asset_id": ASSET_WEB,
    "params": {"container": "shop-api"},
    "reason": "Container shop-api exited 137 (OOM); nginx upstream refused",
    "incident_id": INCIDENT,
}


def test_posts_change_request_with_dev_identity_headers(
        invoker: ToolInvoker, core: CoreRecorder, agents: dict[str, AgentDefinition]) -> None:
    res = invoker.invoke(ctx_for(agents["devops-engineer"], correlation_id="corr-1"),
                         "change.propose", PROPOSAL)
    assert res.status == "ok", res.content
    assert len(core.requests) == 1
    req = core.requests[0]
    assert req.method == "POST" and str(req.url) == f"{CORE_URL}/api/v1/changes"
    assert json.loads(req.content) == PROPOSAL
    assert uuid.UUID(req.headers["Idempotency-Key"])
    assert req.headers["X-AdminTwin-Tenant"] == TENANT_A
    assert req.headers["X-AdminTwin-Actor"] == "devops-engineer"
    assert req.headers["X-AdminTwin-Actor-Kind"] == "ai_agent"
    assert req.headers["X-Correlation-Id"] == "corr-1"
    assert "authorization" not in {k.lower() for k in req.headers}  # агент не держит секретов
    assert res.data is not None and res.data["status"] == "waiting_approval"
    assert res.kind == "propose"
    assert parse_wrapped(res.content) is not None


def test_incident_id_defaults_to_null_or_context(
        invoker: ToolInvoker, core: CoreRecorder, agents: dict[str, AgentDefinition]) -> None:
    body = {k: v for k, v in PROPOSAL.items() if k != "incident_id"}
    invoker.invoke(ctx_for(agents["devops-engineer"]), "change.propose", body)
    assert json.loads(core.requests[-1].content)["incident_id"] is None
    invoker.invoke(ctx_for(agents["devops-engineer"], incident_id=INCIDENT), "change.propose",
                   body)
    assert json.loads(core.requests[-1].content)["incident_id"] == INCIDENT


@pytest.mark.parametrize(
    ("status", "ptype", "reason"),
    [
        (403, "https://errors.admintwin.io/policy-denied", "policy-denied"),
        (409, "https://errors.admintwin.io/kill-switch-active", "kill-switch-active"),
        (409, "https://errors.admintwin.io/legal-hold", "legal-hold"),
        (409, "https://errors.admintwin.io/budget-exhausted", "budget-exhausted"),
        (422, "about:blank", "http_422"),
    ],
)
def test_problem_json_becomes_refusal(invoker: ToolInvoker, core: CoreRecorder,
                                      audit: InMemoryAuditSink, status: int, ptype: str,
                                      reason: str, agents: dict[str, AgentDefinition]) -> None:
    problem = {"type": ptype, "title": "Denied", "status": status,
               "detail": "Runbook not permitted in mode 'advisor' for 'production'",
               "policy_id": str(uuid.uuid4()), "request_id": str(uuid.uuid4()),
               "debug_trace": "internal"}
    core.responder = lambda r: httpx.Response(
        status, json=problem, headers={"content-type": "application/problem+json"})
    res = invoker.invoke(ctx_for(agents["devops-engineer"]), "change.propose", PROPOSAL)
    assert res.status == "refused" and res.reason == reason
    assert res.problem is not None and res.problem["status"] == status
    assert "debug_trace" not in res.problem
    assert audit.records[-1].status == "refused"  # type: ignore[union-attr]
    assert len(core.requests) == 1  # 4xx не повторяется


def test_retry_on_5xx_reuses_idempotency_key(
        invoker: ToolInvoker, core: CoreRecorder, agents: dict[str, AgentDefinition]) -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={"type": "about:blank", "status": 503})
        return CoreRecorder.default(request)

    core.responder = flaky
    res = invoker.invoke(ctx_for(agents["devops-engineer"]), "change.propose", PROPOSAL)
    assert res.status == "ok"
    keys = {r.headers["Idempotency-Key"] for r in core.requests}
    assert len(core.requests) == 2 and len(keys) == 1


def test_persistent_5xx_or_transport_error_is_error(
        backend: InMemoryReadBackend, agents: dict[str, AgentDefinition]) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(transport=httpx.MockTransport(down))
    reg = build_tool_registry(backend, ChangeProposeHandler(CORE_URL, client=client))
    inv = ToolInvoker(reg, InMemoryAuditSink(), assets=backend)
    res = inv.invoke(ctx_for(agents["devops-engineer"]), "change.propose", PROPOSAL)
    assert res.status == "error" and res.reason == "backend_error"


def test_runbook_outside_agent_allowlist_not_sent(
        invoker: ToolInvoker, core: CoreRecorder, agents: dict[str, AgentDefinition]) -> None:
    res = invoker.invoke(ctx_for(agents["devops-engineer"]), "change.propose",
                         {**PROPOSAL, "runbook_id": "firewall.policy.change"})
    assert res.reason == "runbook_not_allowed"
    assert core.requests == []


@pytest.mark.parametrize(
    "bad",
    [
        {**PROPOSAL, "runbook_id": "../../executions"},
        {**PROPOSAL, "reason": "short"},
        {**PROPOSAL, "params": {"cmd": {"nested": "rm -rf /"}}},
        {**PROPOSAL, "params": {"Bad-Key": "x"}},
        {**PROPOSAL, "approve": True},
        {**PROPOSAL, "asset_id": "not-a-uuid"},
    ],
)
def test_invalid_proposals_never_reach_core(invoker: ToolInvoker, core: CoreRecorder,
                                            bad: dict[str, object],
                                            agents: dict[str, AgentDefinition]) -> None:
    res = invoker.invoke(ctx_for(agents["devops-engineer"]), "change.propose", bad)
    assert res.status == "refused" and res.reason == "invalid_params"
    assert core.requests == []


def test_cross_tenant_asset_proposal_refused(invoker: ToolInvoker, core: CoreRecorder,
                                             agents: dict[str, AgentDefinition]) -> None:
    res = invoker.invoke(ctx_for(agents["devops-engineer"]), "change.propose",
                         {**PROPOSAL, "asset_id": ASSET_B_ONLY})
    assert res.reason == "asset_not_in_tenant"
    assert core.requests == []


def test_no_tool_targets_approval_or_execution(tool_registry: ToolRegistry) -> None:
    """T-CAP-002: у AI нет инструмента согласования; POST /executions не существует."""
    for name in tool_registry.names():
        assert "approv" not in name and "decision" not in name and "execut" not in name
