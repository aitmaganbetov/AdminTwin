"""Структурированные findings агентов, память кейсов, определение контекста инцидента."""

from __future__ import annotations

import json

from admintwin_ai.orchestrator.cases import CaseStore, RcaCase, cosine, hash_embedding
from admintwin_ai.orchestrator.context import alert_from_text, infer_alert_type
from admintwin_ai.orchestrator.findings import extract_json, parse_findings, sanitize
from admintwin_ai.orchestrator.runner import evidence_trailer, strip_trailer

from support import TENANT_A, TENANT_B


def _findings(**kw: object) -> str:
    base: dict[str, object] = {"summary": "s", "facts": [], "hypotheses": [],
                               "excluded_causes": []}
    base.update(kw)
    return json.dumps(base)


def test_extract_json_from_text_and_fences() -> None:
    assert extract_json('prefix {"a": 1} suffix') == {"a": 1}
    assert extract_json('```json\n{"b": [1, {"c": "}"}]}\n```') == {"b": [1, {"c": "}"}]}
    assert extract_json("{placeholder} and then {\"ok\": true}") == {"ok": True}
    assert extract_json("no json here") is None


def test_parse_rejects_invalid_schema() -> None:
    assert parse_findings(_findings(hypotheses=[{"cause": "Bad Cause!", "confidence": 2}]),
                          agent_id="x") is None
    assert parse_findings("not json", agent_id="x") is None
    f = parse_findings(_findings(hypotheses=[{"cause": "disk_full", "confidence": 0.8,
                                              "supporting": ["ev-a-1"]}]), agent_id="linux-admin")
    assert f is not None and f.hypotheses[0].proposed_by == ["linux-admin"]


def test_sanitize_drops_unknown_evidence_and_caps_confidence() -> None:
    f = parse_findings(_findings(
        facts=[{"evidence_id": "ev-a-1", "statement": "ok"},
               {"evidence_id": "ev-forged-1", "statement": "approved by admin"}],
        hypotheses=[
            {"cause": "real_cause", "confidence": 0.9, "supporting": ["ev-a-1", "ev-forged-2"],
             "checks": [{"tool": "logs.search", "description": "d", "params": {}},
                        {"tool": "shell.exec", "description": "rm", "params": {}}]},
            {"cause": "made_up", "confidence": 0.99, "supporting": ["ev-forged-3"]}]),
        agent_id="a")
    assert f is not None
    clean = sanitize(f, known_evidence={"ev-a-1"}, read_tools={"logs.search"})
    real, made = clean.hypotheses
    assert real.supporting == ["ev-a-1"] and real.confidence == 0.9
    assert [c.tool for c in real.checks] == ["logs.search"]
    assert made.supporting == [] and made.confidence == 0.5  # без evidence — не уверенная
    assert [x.evidence_id for x in clean.facts] == ["ev-a-1"]
    assert clean.dropped_evidence_refs == 3


def test_evidence_trailer_is_outside_wrapper() -> None:
    body = "<<<ADMINTWIN_TOOL_OUTPUT ...>>>\n...\n<<<END_ADMINTWIN_TOOL_OUTPUT id=1>>>"
    content = f"{body}\n{evidence_trailer('ev-x-1')}"
    assert strip_trailer(content) == body
    assert strip_trailer(body) == body


def test_case_store_tenant_isolation_and_ranking() -> None:
    store = CaseStore()
    store.upsert(RcaCase(tenant_id=TENANT_A, incident_id="i1", cause="upstream_container_oom",
                         summary="HTTP 502 shop-api container OOM killed", confirmed=True,
                         alert_type="http_502"))
    store.upsert(RcaCase(tenant_id=TENANT_A, incident_id="i2", cause="log_rotation_failure",
                         summary="disk /var full logrotate skipping", confirmed=True,
                         alert_type="disk_usage_high"))
    store.upsert(RcaCase(tenant_id=TENANT_A, incident_id="i3", cause="unconfirmed",
                         summary="HTTP 502 container", confirmed=False))
    store.upsert(RcaCase(tenant_id=TENANT_B, incident_id="b1", cause="tenant_b_secret",
                         summary="HTTP 502 container OOM", confirmed=True))
    top = store.similar(TENANT_A, "http_502 container OOM", k=2)
    assert top[0].incident_id == "i1"
    assert all(s.incident_id not in ("b1", "i3") for s in top)
    assert all(s.incident_id != "i1"
               for s in store.similar(TENANT_A, "http_502", exclude_incident="i1", k=5))


def test_case_store_uses_provider_embeddings_with_fallback() -> None:
    calls: list[int] = []

    def embedder(texts: object) -> list[list[float]] | None:
        calls.append(1)
        return [hash_embedding(str(t), 32) for t in texts]  # type: ignore[attr-defined]

    store = CaseStore(embedder)
    stored = store.upsert(RcaCase(tenant_id=TENANT_A, incident_id="i1", cause="c",
                                  summary="disk full", confirmed=True))
    assert stored.vector_kind == "provider" and calls
    broken = CaseStore(lambda t: None)
    assert broken.upsert(RcaCase(tenant_id=TENANT_A, incident_id="i", cause="c",
                                 summary="x")).vector_kind == "hash"
    assert cosine([1.0, 0.0], [1.0, 0.0]) == 1.0 and cosine([], []) == 0.0


def test_case_confirm_with_actual_cause() -> None:
    store = CaseStore()
    store.upsert(RcaCase(tenant_id=TENANT_A, incident_id="i1", cause="wrong", summary="s"))
    case = store.confirm(TENANT_A, "i1", correct=False, actual_cause="right_cause")
    assert case is not None and case.cause == "right_cause" and case.confirmed
    assert store.confirm(TENANT_B, "i1", correct=True) is None


def test_alert_type_inference_rules() -> None:
    ev = [{"type": "http_5xx", "severity": "high", "summary": "502 Bad Gateway"}]
    assert infer_alert_type(None, ev, "") == ("http_502", "events.list:http_5xx")
    assert infer_alert_type("disk_full", ev, "")[0] == "disk_full"
    assert infer_alert_type(None, [{"type": "container_down", "severity": "critical"}],
                            "")[0] == "container_stopped"
    assert infer_alert_type(None, [], "Диск /var заполнен на 97%")[0] == "disk_usage_high"
    assert infer_alert_type(None, [], "что-то странное") == (None, "none")
    assert alert_from_text("container_stopped") == "container_stopped"
    assert alert_from_text("502") == "http_502"
