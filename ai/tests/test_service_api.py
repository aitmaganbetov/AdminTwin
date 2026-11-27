"""HTTP API оркестратора (contracts §4): аутентификация, tenant scope, задачи, SSE, чат,
kill switch, healthz, кейсы."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from admintwin_ai.service.__main__ import main as service_main
from admintwin_ai.service.app import create_app
from admintwin_ai.service.runtime import Runtime, fake_registry
from admintwin_ai.service.settings import ConfigurationError, ServiceSettings

from support import TENANT_A, TENANT_B
from svc import MVP_PROFILES, TOKEN, BlockingDiagnostician, golden, make_runtime, scope_of

H = {"X-AdminTwin-Service-Token": TOKEN}
HA = {**H, "X-AdminTwin-Tenant": TENANT_A, "X-AdminTwin-Actor": "user-1",
      "X-AdminTwin-Actor-Kind": "user"}
HB = {**H, "X-AdminTwin-Tenant": TENANT_B, "X-AdminTwin-Actor": "user-2",
      "X-AdminTwin-Actor-Kind": "user"}
CASE = golden("http502-upstream-oom-002")


async def _client(rt: Runtime) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(rt)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://orch") as client:
        yield client


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    rt, _ = make_runtime(case=CASE)
    async for c in _client(rt):
        yield c


async def _wait_status(client: httpx.AsyncClient, task_id: str, statuses: set[str],
                       headers: dict[str, str] = HA, timeout_s: float = 15.0) -> dict[str, Any]:
    async with asyncio.timeout(timeout_s):
        while True:
            r = await client.get(f"/v1/tasks/{task_id}", headers=headers)
            body: dict[str, Any] = r.json()
            if body["status"] in statuses:
                return body
            await asyncio.sleep(0.01)


def _sse(text: str) -> list[dict[str, Any]]:
    import json

    events = []
    for block in text.split("\n\n"):
        item: dict[str, Any] = {}
        data: list[str] = []
        for line in block.split("\n"):
            if line.startswith("id: "):
                item["id"] = int(line[4:])
            elif line.startswith("event: "):
                item["event"] = line[7:]
            elif line.startswith("data: "):
                data.append(line[6:])
        if "id" in item:
            item["data"] = json.loads("\n".join(data))
            events.append(item)
    return events


# --- настройки и аутентификация -------------------------------------------------------


def test_service_refuses_to_start_without_token() -> None:
    with pytest.raises(ConfigurationError, match="ADMINTWIN_SERVICE_TOKEN"):
        ServiceSettings.from_env({})
    with pytest.raises(ConfigurationError, match="at least 16"):
        ServiceSettings.from_env({"ADMINTWIN_SERVICE_TOKEN": "short"})
    dev = ServiceSettings.from_env({"ADMINTWIN_DEV_INSECURE": "true"})
    assert not dev.auth_enabled
    s = ServiceSettings.from_env({"ADMINTWIN_SERVICE_TOKEN": TOKEN,
                                  "ADMINTWIN_NATS_URL": "nats://n:4222",
                                  "ADMINTWIN_BUDGET_TASK_TOKENS": "1000"})
    assert s.auth_enabled and s.port == 8090 and s.nats_url == "nats://n:4222"
    assert s.budgets.task_tokens == 1000
    assert TOKEN not in repr(s)


def test_entrypoint_exits_with_error_without_token(monkeypatch: pytest.MonkeyPatch,
                                                   capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("ADMINTWIN_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("ADMINTWIN_DEV_INSECURE", raising=False)
    assert service_main() == 2
    assert "ADMINTWIN_SERVICE_TOKEN is required" in capsys.readouterr().err


@pytest.mark.parametrize("path", ["/healthz", "/v1/tasks", "/v1/kill"])
async def test_every_endpoint_requires_service_token(client: httpx.AsyncClient,
                                                     path: str) -> None:
    for headers in ({}, {"X-AdminTwin-Service-Token": "wrong-token-wrong-token"},
                    {"X-AdminTwin-Service-Token": TOKEN[:-1]}):
        r = await client.request("POST" if path != "/healthz" else "GET", path,
                                 headers=headers, json={})
        assert r.status_code == 401
        assert r.headers["content-type"].startswith("application/problem+json")
        assert r.json()["type"] == "https://errors.admintwin.io/unauthenticated"


def test_token_compare_is_constant_time() -> None:
    import inspect

    from admintwin_ai.service import app as app_mod

    assert "hmac.compare_digest" in inspect.getsource(app_mod.create_app)


# --- задачи --------------------------------------------------------------------------------


async def test_create_task_tree_and_tenant_scope(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/tasks", headers=HA, json={
        "kind": "rca", "tenant_id": TENANT_A, "incident_id": "INC-1",
        "objective": "HTTP 502 on shop", "scope": {"asset_ids": scope_of(CASE)},
        "requested_by": "user-1"})
    assert r.status_code == 202, r.text
    task_id = r.json()["task_id"]
    assert r.json()["status"] in ("queued", "running")
    body = await _wait_status(client, task_id, {"completed"})
    assert body["kind"] == "rca" and body["incident_id"] == "INC-1"
    assert sorted(body["agents"]) == ["dba-engineer", "devops-engineer", "network-engineer"]
    assert len(body["children"]) == 3
    assert {c["agent_id"] for c in body["children"]} == set(body["agents"])
    assert all(c["status"] == "completed" and c["transitions"] for c in body["children"])
    assert body["facts"] and body["hypotheses"] and body["cost_usd"] > 0
    assert body["result"]["status"] == "completed"
    assert [t["to"] for t in body["transitions"]][:2] == ["queued", "running"]
    # список — только задачи tenant
    r = await client.get("/v1/tasks", headers=HA)
    assert [t["task_id"] for t in r.json()["items"]] == [task_id]
    r = await client.get("/v1/tasks", headers=HB)
    assert r.json()["items"] == []
    # чужой tenant неотличим от отсутствующей задачи
    for method, path in (("GET", f"/v1/tasks/{task_id}"), ("POST", f"/v1/tasks/{task_id}/cancel"),
                         ("GET", f"/v1/tasks/{task_id}/events")):
        r = await client.request(method, path, headers=HB)
        assert r.status_code == 404
    r = await client.get(f"/v1/tasks/{task_id}?tenant_id={TENANT_B}", headers=HA)
    assert r.status_code == 403


async def test_body_tenant_must_match_header(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/tasks", headers=HA, json={"kind": "rca", "tenant_id": TENANT_B})
    assert r.status_code == 403
    r = await client.post("/v1/tasks", headers=H, json={"kind": "rca", "tenant_id": "not-a-uuid"})
    assert r.status_code == 422
    assert r.json()["type"] == "https://errors.admintwin.io/invalid-params"
    r = await client.post("/v1/tasks", headers=H, json={"kind": "execute", "tenant_id": TENANT_A})
    assert r.status_code == 422
    r = await client.get("/v1/tasks", headers=H)
    assert r.status_code == 400


async def test_cancel_and_input_endpoints() -> None:
    provider = BlockingDiagnostician({"devops-engineer"})
    rt, _ = make_runtime(case=CASE, registry=fake_registry(MVP_PROFILES, provider=provider))
    try:
        async for client in _client(rt):
            r = await client.post("/v1/tasks", headers=HA, json={
                "kind": "diagnose", "tenant_id": TENANT_A, "objective": "HTTP 502",
                "scope": {"asset_ids": scope_of(CASE)}})
            tid = r.json()["task_id"]
            await _wait_status(client, tid, {"running"})
            r = await client.post(f"/v1/tasks/{tid}/input", headers=HA, json={"text": "x"})
            assert r.status_code == 409
            r = await client.post(f"/v1/tasks/{tid}/cancel", headers=HA)
            assert r.status_code == 200
            assert r.json() == {"task_id": tid, "status": "cancelled",
                                "cancellation": "cancelled"}
            body = (await client.get(f"/v1/tasks/{tid}", headers=HA)).json()
            assert body["transitions"][-1]["reason"].startswith("cancelled by requester")
    finally:
        provider.release.set()


async def test_sse_stream_and_last_event_id_replay(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/tasks", headers=HA, json={
        "kind": "rca", "tenant_id": TENANT_A, "scope": {"asset_ids": scope_of(CASE)},
        "objective": "HTTP 502"})
    tid = r.json()["task_id"]
    await _wait_status(client, tid, {"completed"})
    r = await client.get(f"/v1/tasks/{tid}/events", headers=HA)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    events = _sse(r.text)
    ids = [e["id"] for e in events]
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    kinds = {e["event"] for e in events}
    assert {"task.progress", "tool_call", "fact", "hypothesis", "cost", "evidence.added",
            "task.result", "change.proposed"} <= kinds
    final = [e for e in events if e["event"] == "task.result" and e["data"]["task_id"] == tid]
    assert final and final[0]["data"]["result"]["status"] == "completed"
    # повтор с Last-Event-ID: только события после указанного
    cut = ids[len(ids) // 2]
    r = await client.get(f"/v1/tasks/{tid}/events", headers={**HA, "Last-Event-ID": str(cut)})
    replay = _sse(r.text)
    assert [e["id"] for e in replay] == [i for i in ids if i > cut]


async def test_chat_session_messages_and_waiting_input(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/chat/sessions", headers=HA, json={"tenant_id": TENANT_A,
                                                                "incident_id": "INC-7"})
    assert r.status_code == 201
    sid = r.json()["session_id"]
    r = await client.post(f"/v1/chat/sessions/{sid}/messages", headers=HA,
                          json={"text": "Что происходит с shop-frontend?"})
    assert r.status_code == 202
    tid = r.json()["task_id"]
    body = await _wait_status(client, tid, {"completed"})
    assert body["kind"] == "chat" and body["session_id"] == sid
    assert body["result"]["text"].startswith("За последний час событий")
    # короткий вопрос → модель просит уточнение → waiting_input → ответ через сообщение
    r = await client.post(f"/v1/chat/sessions/{sid}/messages", headers=HA, json={"text": "?"})
    tid2 = r.json()["task_id"]
    body = await _wait_status(client, tid2, {"waiting_input"})
    assert body["question"]
    r = await client.post(f"/v1/chat/sessions/{sid}/messages", headers=HA,
                          json={"text": "инцидент INC-7, актив nginx-lb-01"})
    assert r.json()["task_id"] == tid2
    await _wait_status(client, tid2, {"completed"})
    # события сессии — SSE (поток сессии не закрывается: читаем журнал напрямую)
    r = await client.get(f"/v1/chat/sessions/{sid}/events", headers=HB)
    assert r.status_code == 404


async def test_chat_session_event_log_contains_results() -> None:
    rt, _ = make_runtime(case=CASE)
    async for client in _client(rt):
        sid = (await client.post("/v1/chat/sessions", headers=HA,
                                 json={"tenant_id": TENANT_A})).json()["session_id"]
        r = await client.post(f"/v1/chat/sessions/{sid}/messages", headers=HA,
                              json={"text": "Сводка по событиям"})
        await _wait_status(client, r.json()["task_id"], {"completed"})
        log = rt.orchestrator.sessions[sid].events
        types = [e.type for e in log.since(0)]
        assert "tool_call" in types and "task.result" in types
        last = log.last_id
        tail = log.since(last - 2)
        assert [e.id for e in tail] == [last - 1, last]


async def test_input_endpoint_resumes_waiting_task() -> None:
    rt, _ = make_runtime(case=CASE)
    backend = rt.orchestrator.invoker._assets  # type: ignore[attr-defined]
    backend._fixtures["events.list"] = [{"match": {}, "response": {"events": []}}]
    db = scope_of(CASE)[2]
    backend._assets[db]["type"] = "unknown_box"
    async for client in _client(rt):
        r = await client.post("/v1/tasks", headers=HA, json={
            "kind": "diagnose", "tenant_id": TENANT_A, "objective": "проверь",
            "scope": {"asset_ids": [db]}})
        tid = r.json()["task_id"]
        body = await _wait_status(client, tid, {"waiting_input"})
        assert "уточните" in body["question"]
        r = await client.post(f"/v1/tasks/{tid}/input", headers=HA, json={"text": "http_502"})
        assert r.status_code == 202
        body = await _wait_status(client, tid, {"completed", "failed"})
        assert any(t["to"] == "waiting_input" for t in body["transitions"])


async def test_kill_tenant_requires_matching_tenant(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/kill", headers=HA, json={"tenant_id": TENANT_B})
    assert r.status_code == 403
    r = await client.post("/v1/kill", headers=HA, json={"platform": True})
    assert r.status_code == 403  # платформенный kill — только от сервиса ядра
    r = await client.post("/v1/kill", headers=HA, json={})
    assert r.status_code == 200 and r.json()["scope"] == f"tenant:{TENANT_A}"
    r = await client.post("/v1/chat/sessions", headers=HA, json={"tenant_id": TENANT_A})
    assert r.status_code == 409
    r = await client.post("/v1/tasks", headers=HB, json={"kind": "diagnose",
                                                        "tenant_id": TENANT_B})
    assert r.status_code == 202  # другой tenant не затронут


async def test_healthz_reports_provider_states(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["llm"] == "ok"
    assert body["bus"] == {"kind": "inprocess", "healthy": True}
    profiles = {p["profile"]: p for p in body["providers"]}
    assert {"claude-primary", "openai-secondary"} <= set(profiles)
    assert all(p["circuit"] == "closed" for p in profiles.values())
    r = await client.get("/healthz?probe=true", headers=H)
    assert all(p["health"]["ok"] for p in r.json()["providers"])


async def test_healthz_degraded_when_all_llms_down() -> None:
    rt, _ = make_runtime(case=CASE)
    for p in rt.profiles.all():
        b = rt.router.breakers.get(p.id)
        for _ in range(15):  # несколько циклов backoff — цепь открыта на десятки секунд
            b.record_failure("ProviderUnavailableError")
    async for client in _client(rt):
        body = (await client.get("/healthz", headers=H)).json()
        assert body["status"] == "degraded" and body["llm"] == "unavailable"
        assert "blocked" in body["degradation"]
        assert all(p["circuit"] == "open" for p in body["providers"])
        r = await client.post("/v1/tasks", headers=HA, json={
            "kind": "rca", "tenant_id": TENANT_A, "scope": {"asset_ids": scope_of(CASE)},
            "objective": "HTTP 502"})
        body = await _wait_status(client, r.json()["task_id"], {"blocked"})
        assert body["reason"].startswith("llm.unavailable")


async def test_no_llm_configured_blocks_tasks() -> None:
    from admintwin_ai.profiles import ProfileRegistry

    rt, _ = make_runtime(case=CASE, registry=ProfileRegistry([], {}))
    async for client in _client(rt):
        r = await client.post("/v1/tasks", headers=HA, json={"kind": "rca",
                                                            "tenant_id": TENANT_A})
        body = await _wait_status(client, r.json()["task_id"], {"blocked"})
        assert "ADMINTWIN_AI_CONFIG" in body["reason"]
        assert (await client.get("/healthz", headers=H)).json()["status"] == "degraded"


async def test_case_feedback_endpoint(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/cases", headers=HA, json={
        "tenant_id": TENANT_A, "incident_id": "INC-9", "correct": False})
    assert r.status_code == 404
    r = await client.post("/v1/cases", headers=HA, json={
        "tenant_id": TENANT_A, "incident_id": "INC-9", "correct": True,
        "cause": "upstream_container_oom", "summary": "OOM shop-api"})
    assert r.status_code == 202 and r.json()["confirmed"] is True
    r = await client.post("/v1/cases", headers=HB, json={
        "tenant_id": TENANT_A, "incident_id": "INC-9", "correct": True})
    assert r.status_code == 403


async def test_dev_insecure_mode_skips_token() -> None:
    rt, _ = make_runtime(case=CASE, token=None)
    async for client in _client(rt):
        r = await client.get("/healthz")
        assert r.status_code == 200 and r.json()["auth"].startswith("disabled")


def test_runtime_builds_from_provider_config_without_network() -> None:
    from admintwin_ai.resources import data_path
    from admintwin_ai.service.runtime import build_runtime

    from fakes import FakeAnthropicClient, FakeOpenAIClient

    settings = ServiceSettings(service_token=TOKEN,
                               ai_config=str(data_path("config",
                                                       "model-profiles.example.yaml")))
    rt = build_runtime(settings, provider_clients={"claude-api": FakeAnthropicClient(),
                                                   "openai-api": FakeOpenAIClient(),
                                                   "local-vllm": FakeOpenAIClient()})
    kinds = {p["profile"]: p["kind"] for p in rt.provider_states()}
    assert kinds["claude-primary"] == "claude" and kinds["openai-secondary"] == "openai"
    assert kinds["local-default"] == "local"
    assert rt.orchestrator.llm_configured
    assert rt.orchestrator.bus.kind == "inprocess"


def test_model_cards_exist_for_every_mvp_agent() -> None:
    from admintwin_ai.agents import load_agents
    from admintwin_ai.resources import data_path

    for agent in load_agents():
        card = data_path("agents", "model-cards", f"{agent.id}.md").read_text(encoding="utf-8")
        assert agent.prompt_version in card and agent.model_profile in card
        assert data_path("agents", "prompts", f"{agent.prompt_version}.md").is_file()
