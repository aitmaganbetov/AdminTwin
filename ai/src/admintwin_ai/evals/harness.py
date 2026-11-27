"""Прогон golden dataset через полный путь оркестратора (M22, §6.10).

Каждый кейс: свежий runtime (шина in-process, Tool Layer поверх фикстур
кейса, ядро — MockTransport), задача ``rca`` по активам кейса, ожидание
результата, предсказание = ранжированные гипотезы результата RCA.

Модель: ``--offline-fake`` — ``ScriptedDiagnostician`` (CI, без сети);
иначе — реальные провайдеры из ``ADMINTWIN_AI_CONFIG`` с профилем,
заданным ``--profile`` для всех агентов.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Mapping
from typing import Any

import httpx

from admintwin_ai.bus.inprocess import InProcessBus
from admintwin_ai.contracts.task_state import TaskState
from admintwin_ai.evals.metrics import EvalCase, Prediction, RankedCause
from admintwin_ai.profiles import ProfileRegistry
from admintwin_ai.service.runtime import Runtime, build_runtime
from admintwin_ai.service.settings import ServiceSettings
from admintwin_ai.tools.registry import ToolBackendError, ToolOutput

EVAL_TENANT = "e0e0e0e0-0000-4000-8000-00000000e0a1"
_NS = uuid.UUID("0d1e5c00-0000-4000-8000-00000000e002")
_ASSET_FIELDS = ("asset_id", "name", "type", "environment", "criticality", "ring",
                 "service_tier", "data_class", "legal_hold", "tags")


def _matches(match: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    for key, want in match.items():
        got = params.get(key)
        if isinstance(want, str):
            if not isinstance(got, str) or want.lower() not in got.lower():
                return False
        elif got != want:
            return False
    return True


class FixtureBackend:
    """``ReadBackend`` поверх фикстур кейса: ``input.fixtures[tool] = [{match, response}]``."""

    def __init__(self, case: EvalCase, tenant_id: str = EVAL_TENANT) -> None:
        self._tenant = tenant_id
        self._assets = {a["asset_id"]: a for a in case.input.get("assets", [])}
        self._fixtures: dict[str, list[dict[str, Any]]] = dict(case.input.get("fixtures", {}))
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def asset_exists(self, tenant_id: str, asset_id: str) -> bool:
        return tenant_id == self._tenant and asset_id in self._assets

    def fetch(self, tool: str, tenant_id: str, params: dict[str, Any]) -> ToolOutput:
        if tenant_id != self._tenant:
            raise ToolBackendError("unknown tenant")
        self.calls.append((tool, dict(params)))
        if tool == "logs.search":
            return self._search_logs(params)
        for entry in self._fixtures.get(tool, []):
            if _matches(entry.get("match", {}), params):
                return ToolOutput(data=dict(entry["response"]))
        if tool == "asset.get" and params.get("asset_id") in self._assets:
            a = self._assets[params["asset_id"]]
            return ToolOutput(data={k: a[k] for k in _ASSET_FIELDS if k in a})
        if tool == "topology.blast_radius" and params.get("asset_id") in self._assets:
            nodes = [{"asset_id": k, "name": v.get("name", ""), "type": v.get("type", "unknown"),
                      "depth": 1} for k, v in self._assets.items() if k != params["asset_id"]]
            return ToolOutput(data={"asset_id": params["asset_id"], "nodes": nodes, "edges": []})
        raise ToolBackendError(f"no fixture for '{tool}'")

    def _search_logs(self, params: dict[str, Any]) -> ToolOutput:
        """Явная фикстура с ``match.query`` — как задано; иначе поиск подстроки
        (``a|b`` — любая из) по всем строкам журнала актива из фикстур кейса."""
        entries = self._fixtures.get("logs.search", [])
        for entry in entries:
            if "query" in entry.get("match", {}) and _matches(entry["match"], params):
                return ToolOutput(data=dict(entry["response"]))
        asset = params.get("asset_id")
        tokens = [t for t in str(params.get("query", "")).lower().split("|") if t]
        found: list[dict[str, Any]] = []
        for entry in entries:
            want = entry.get("match", {}).get("asset_id")
            if asset is not None and want is not None and want != asset:
                continue
            for line in entry.get("response", {}).get("entries", []):
                text = str(line.get("line", "")).lower()
                if any(t in text for t in tokens) and line not in found:
                    found.append(line)
        return ToolOutput(data={"entries": found[: int(params.get("limit", 500))]})


def _mock_core() -> tuple[httpx.Client, httpx.AsyncClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/v1/changes":
            body = json.loads(request.content)
            return httpx.Response(202, json={"id": f"chg-{len(seen)}",
                                             "status": "waiting_approval",
                                             "runbook_id": body.get("runbook_id")})
        return httpx.Response(202, json={})

    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport), httpx.AsyncClient(transport=transport), seen


def make_runtime(case: EvalCase, *, profile: str | None, offline_fake: bool,
                 registry: ProfileRegistry | None = None,
                 ai_config: str | None = None) -> Runtime:
    settings = ServiceSettings(dev_insecure=True, core_url="http://core.eval",
                               offline_fake=offline_fake and registry is None,
                               ai_config=ai_config)
    http, ahttp, _ = _mock_core()
    return build_runtime(settings, registry=registry, backend=FixtureBackend(case),
                         core_http=http, core_async=ahttp, bus=InProcessBus(),
                         agent_profile_override=profile)


def _tool_calls_to_correct(task_context: dict[str, Any], result: dict[str, Any],
                           correct: frozenset[str]) -> int | None:
    index: dict[str, dict[str, Any]] = task_context.get("evidence_index", {})
    base = int(task_context.get("context_calls", 0))
    for h in result.get("hypotheses", []):
        if h.get("cause") not in correct:
            continue
        counts: list[int] = []
        for ref in h.get("supporting", []):
            info = index.get(ref.get("evidence_id", ""))
            if info is None:
                continue
            if info.get("agent") == "ai-commander":
                counts.append(int(info.get("call_index", 1)))
            else:
                counts.append(base + int(info.get("call_index", 1)))
        return max(counts) if counts else None
    return None


async def predict_case(case: EvalCase, *, profile: str | None = None, offline_fake: bool = True,
                       registry: ProfileRegistry | None = None, ai_config: str | None = None,
                       timeout_s: float = 120.0) -> tuple[Prediction, dict[str, Any]]:
    runtime = make_runtime(case, profile=profile, offline_fake=offline_fake, registry=registry,
                           ai_config=ai_config)
    orch = runtime.orchestrator
    await orch.start()
    try:
        alert = case.input.get("alert", {})
        task = orch.manager.create(
            tenant_id=EVAL_TENANT, kind="rca", objective=str(alert.get("summary", case.title)),
            incident_id=str(uuid.uuid5(_NS, case.case_id)),
            asset_ids=list(case.input.get("scope", [])), requested_by="eval")
        orch.manager.start(task)
        deadline = asyncio.get_running_loop().time() + timeout_s
        answered = False
        while not task.terminal and asyncio.get_running_loop().time() < deadline:
            if task.state is TaskState.WAITING_INPUT and not answered:
                orch.manager.provide_input(task, str(alert.get("type", "")))
                answered = True
            elif task.state is TaskState.BLOCKED:
                break
            await asyncio.sleep(0.005)
        result = task.result or {}
        hyps = [RankedCause(cause=h["cause"], confidence=float(h["confidence"]))
                for h in result.get("hypotheses", [])]
        refused = not hyps or result.get("status") == "failed" or task.state in (
            TaskState.BLOCKED, TaskState.FAILED, TaskState.CANCELLED, TaskState.TIMED_OUT)
        pred = Prediction(case_id=case.case_id, hypotheses=hyps, refused=refused,
                          tool_calls_to_correct=_tool_calls_to_correct(
                              task.context, result, case.expected.correct))
        info = {"case_id": case.case_id, "state": task.state.value,
                "status": result.get("status"), "agents": list(task.agents),
                "cost_usd": task.cost_usd, "conclusion": result.get("conclusion"),
                "uncertainty_check": result.get("uncertainty_check"),
                "proposed_changes": result.get("proposed_changes", [])}
        if task.state is TaskState.BLOCKED:
            info["reason"] = task.reason
        if not task.terminal:
            await orch.manager.cancel(task, reason="eval timeout", actor="eval")
        return pred, info
    finally:
        await orch.close()


async def predict_all(cases: list[EvalCase], **kw: Any
                      ) -> tuple[list[Prediction], list[dict[str, Any]]]:
    preds: list[Prediction] = []
    infos: list[dict[str, Any]] = []
    for case in cases:
        p, info = await predict_case(case, **kw)
        preds.append(p)
        infos.append(info)
    return preds, infos
