"""Сквозной тест сервиса: настоящий uvicorn на loopback, живой SSE-поток с
Last-Event-ID во время выполнения задачи."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import Iterator

import httpx
import pytest
import uvicorn

from admintwin_ai.service.app import create_app
from admintwin_ai.service.runtime import fake_registry

from support import TENANT_A
from svc import MVP_PROFILES, TOKEN, BlockingDiagnostician, golden, make_runtime, scope_of

H = {"X-AdminTwin-Service-Token": TOKEN, "X-AdminTwin-Tenant": TENANT_A}


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def served() -> Iterator[tuple[str, BlockingDiagnostician]]:
    case = golden("http502-upstream-oom-002")
    provider = BlockingDiagnostician({"dba-engineer"})
    rt, _ = make_runtime(case=case, registry=fake_registry(MVP_PROFILES, provider=provider))
    port = _port()
    server = uvicorn.Server(uvicorn.Config(create_app(rt), host="127.0.0.1", port=port,
                                           log_level="warning", lifespan="on"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}", provider
    finally:
        provider.release.set()
        server.should_exit = True
        thread.join(timeout=10)


async def _read_events(client: httpx.AsyncClient, url: str, headers: dict[str, str],
                       stop: int) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    async with client.stream("GET", url, headers=headers) as resp:
        assert resp.status_code == 200
        cur: dict[str, object] = {}
        async for line in resp.aiter_lines():
            if line.startswith("id: "):
                cur["id"] = int(line[4:])
            elif line.startswith("event: "):
                cur["event"] = line[7:]
            elif line.startswith("data: "):
                cur["data"] = json.loads(line[6:])
            elif line == "" and "id" in cur:
                events.append(cur)
                cur = {}
                if len(events) >= stop:
                    break
    return events


async def test_live_sse_with_reconnect_and_last_event_id(
        served: tuple[str, BlockingDiagnostician]) -> None:
    base, provider = served
    case = golden("http502-upstream-oom-002")
    async with httpx.AsyncClient(base_url=base, timeout=20, trust_env=False) as client:
        r = await client.get("/healthz")
        assert r.status_code == 401
        r = await client.post("/v1/tasks", headers=H, json={
            "kind": "rca", "tenant_id": TENANT_A, "objective": "HTTP 502",
            "scope": {"asset_ids": scope_of(case)}})
        assert r.status_code == 202
        tid = r.json()["task_id"]
        url = f"/v1/tasks/{tid}/events"
        # задача ещё выполняется (DBA «завис» в вызове LLM): читаем первые события живьём
        first = await _read_events(client, url, H, stop=5)
        assert [e["id"] for e in first] == [1, 2, 3, 4, 5]
        # переподключение с Last-Event-ID: продолжение без повторов
        provider.release.set()
        rest = await _read_events(client, url, {**H, "Last-Event-ID": "5"}, stop=10_000)
        assert rest and rest[0]["id"] == 6
        ids = [e["id"] for e in rest]
        assert ids == list(range(6, 6 + len(ids)))
        final = [e for e in rest if e["event"] == "task.result"
                 and e["data"]["task_id"] == tid]  # type: ignore[index]
        assert final, "stream ends after the terminal event"
        body = (await client.get(f"/v1/tasks/{tid}", headers=H)).json()
        assert body["status"] == "completed"
        await asyncio.sleep(0)
