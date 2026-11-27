"""Аудит вызовов LLM/инструментов в ядро.

Пакеты по tenant, только метаданные, без блокировки агентов.
"""

import json

import httpx

from admintwin_ai.audit import InMemoryAuditSink, LLMCallRecord, RoutingRecord, ToolCallRecord
from admintwin_ai.classification import DataClass
from admintwin_ai.service.core_audit import CoreAuditSink

TA = "11111111-1111-4111-8111-111111111111"
TB = "22222222-2222-4222-8222-222222222222"


def llm(tenant: str) -> LLMCallRecord:
    return LLMCallRecord(
        tenant_id=tenant,
        agent_id="devops-engineer",
        provider="anthropic",
        model="m",
        requested_model="m",
        mode="api_key",
        profile_id="p",
        prompt_version="v1",
        input_sha256="a" * 64,
        status="ok",
        data_class=DataClass.INTERNAL,
        external=True,
    )


def test_batches_by_tenant_and_ships_only_call_records() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(202, json={"accepted": 1})

    inner = InMemoryAuditSink()
    sink = CoreAuditSink(
        "http://core",
        "tok",
        inner,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        start=False,
    )
    sink.emit(llm(TA))
    sink.emit(llm(TB))
    sink.emit(
        ToolCallRecord(
            tenant_id=TA,
            agent_id="devops-engineer",
            tool="asset.get",
            status="ok",
            params_sha256="b" * 64,
        )
    )
    sink.emit(
        RoutingRecord(
            tenant_id=TA,
            status="route",
            data_class=DataClass.INTERNAL,
            task_class="rca",
            reasons=[],
        )
    )
    assert sink.flush() == 3
    assert len(inner.records) == 4  # локальный журнал получает всё
    by_tenant = {r.headers["X-AdminTwin-Tenant"]: json.loads(r.content)["records"] for r in seen}
    assert set(by_tenant) == {TA, TB}
    assert {r["record_type"] for r in by_tenant[TA]} == {"llm_call", "tool_call"}
    for r in seen:
        assert r.headers["X-AdminTwin-Actor"] == "orchestrator"
        assert r.headers["X-AdminTwin-Actor-Kind"] == "service"
        for rec in json.loads(r.content)["records"]:
            assert not {"prompt", "messages", "input", "content", "output"} & set(rec)


def test_retries_transient_failures_and_drops_rejected() -> None:
    calls = {"n": 0}

    def flaky(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503) if calls["n"] == 1 else httpx.Response(202)

    sink = CoreAuditSink(
        "http://core",
        "tok",
        InMemoryAuditSink(),
        client=httpx.Client(transport=httpx.MockTransport(flaky)),
        start=False,
    )
    sink.emit(llm(TA))
    assert sink.flush() == 0  # 503 — оставлено на повтор
    assert sink.flush() == 1

    rejected = CoreAuditSink(
        "http://core",
        "tok",
        InMemoryAuditSink(),
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(422))),
        start=False,
    )
    rejected.emit(llm(TA))
    assert rejected.flush() == 0
    assert rejected.flush() == 0  # 4xx не повторяется бесконечно


def test_core_unreachable_does_not_raise() -> None:
    def down(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    sink = CoreAuditSink(
        "http://core",
        "tok",
        InMemoryAuditSink(),
        client=httpx.Client(transport=httpx.MockTransport(down)),
        start=False,
    )
    sink.emit(llm(TA))
    assert sink.flush() == 0
