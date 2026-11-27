"""``ScriptedDiagnostician`` — детерминированная офлайн-«модель» (LLMProvider).

Используется в CI (``python -m admintwin_ai.evals.run --offline-fake``),
тестах сервиса и dev-режиме ``ADMINTWIN_AI_OFFLINE_FAKE=true``. Реальные LLM
не вызываются никогда. Модель видит ровно то же, что видела бы настоящая:
системный промпт агента, контекст Commander и обёрнутые ответы инструментов,
и действует по сценарию:

* специалист: шаг 1 — план read-вызовов по своим инструментам и активам
  контекста; шаг 2 — при уверенной причине, устранимой runbook, —
  ``change.propose`` (только для агентов с этим инструментом); затем —
  JSON findings, построенный правилами ``evals.rules``;
* ``mode: adjudicate`` — пересчёт confidence двух лидеров по результату
  разделяющей проверки;
* ``mode: chat`` — один вызов ``events.list`` и краткий ответ.

Инструкции внутри данных модель игнорирует (как и требует промпт); тесты
prompt-injection используют отдельную «доверчивую» модель.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Sequence
from typing import Any

from admintwin_ai.evals.rules import Observation, aggregate, evaluate, family_of
from admintwin_ai.providers.base import (
    CompletionRequest,
    CompletionResult,
    ConnectionMode,
    EmbeddingResult,
    HealthStatus,
    ProviderCapabilities,
    StreamEvent,
    TokenCount,
    ToolCall,
    Usage,
    estimate_tokens,
)
from admintwin_ai.tools.wrapping import NOTICE

FAKE_CAPS = ProviderCapabilities(tool_calling=True, structured_output=True, streaming=True,
                                 embeddings=True, max_context=200_000)

_HEADER = re.compile(r"AdminTwin agent_id: (?P<agent>[a-z0-9-]+); mode: (?P<mode>[a-z_]+)")
_BLOCK = re.compile(
    r"<<<ADMINTWIN_TOOL_OUTPUT id=(?P<id>[0-9a-f]{16}) tool=(?P<tool>[a-z0-9_.]+) "
    r"data_class=[a-z]+ untrusted=true suspected_injection=(?:true|false)>>>\n"
    + re.escape(NOTICE) + r"\n(?P<body>.*?)\n<<<END_ADMINTWIN_TOOL_OUTPUT id=(?P=id)>>>",
    re.DOTALL)
_TRAILER = re.compile(r"\[AdminTwin evidence_id=(?P<eid>ev-[a-z0-9-]+)\]")

_RESTARTABLE = {"upstream_container_oom", "upstream_container_stopped", "container_oom_killed",
                "manual_stop", "container_crash"}


def wrapped_blocks(text: str) -> list[tuple[str, dict[str, Any] | None]]:
    out: list[tuple[str, dict[str, Any] | None]] = []
    for m in _BLOCK.finditer(text):
        body = m.group("body").replace("‹‹‹", "<<<").replace("›››", ">>>")
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        out.append((m.group("tool"), data if isinstance(data, dict) else None))
    return out


class ScriptedDiagnostician:
    """Фейковый провайдер; ``is_external`` настраивается (для проверки маскирования)."""

    kind = "fake"

    def __init__(self, provider_id: str = "offline-fake", *, external: bool = False,
                 caps: ProviderCapabilities = FAKE_CAPS) -> None:
        self._provider_id = provider_id
        self.is_external = external
        self._caps = caps
        self.requests: list[CompletionRequest] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def mode(self) -> ConnectionMode:
        return ConnectionMode.API_KEY if self.is_external else ConnectionMode.OPENAI_COMPATIBLE

    def capabilities(self) -> ProviderCapabilities:
        return self._caps

    # --- LLMProvider ---------------------------------------------------------------

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        m = _HEADER.search(request.system or "")
        agent = m.group("agent") if m else "unknown"
        mode = m.group("mode") if m else "rca"
        if mode == "adjudicate":
            result = self._adjudicate(request)
        elif mode == "chat":
            result = self._chat(request)
        else:
            result = self._specialist(agent, request)
        usage = Usage(input_tokens=estimate_tokens(request),
                      output_tokens=max(1, (len(result.text) + 40 * len(result.tool_calls)) // 4))
        return result.model_copy(update={"usage": usage, "model": request.model,
                                          "provider": self._provider_id})

    def tool_call(self, request: CompletionRequest) -> CompletionResult:
        return self.complete(request)

    def stream(self, request: CompletionRequest) -> Iterator[StreamEvent]:
        yield StreamEvent(type="final", result=self.complete(request))

    def embed(self, texts: Sequence[str], *, model: str) -> EmbeddingResult:
        from admintwin_ai.orchestrator.cases import hash_embedding

        return EmbeddingResult(vectors=[hash_embedding(t, 64) for t in texts], model=model,
                               usage=Usage(input_tokens=sum(len(t) // 4 for t in texts)))

    def count_tokens(self, request: CompletionRequest) -> TokenCount:
        return TokenCount(tokens=estimate_tokens(request), exact=False)

    def health(self, model: str | None = None) -> HealthStatus:
        return HealthStatus(ok=True, provider=self._provider_id, detail="scripted offline model")

    # --- специалист -------------------------------------------------------------------

    @staticmethod
    def _context(request: CompletionRequest) -> dict[str, Any]:
        for msg in request.messages:
            if msg.role != "user":
                continue
            for tool, data in wrapped_blocks(msg.content):
                if tool == "incident.context" and data is not None:
                    return data
        return {}

    @staticmethod
    def _observations(request: CompletionRequest) -> list[Observation]:
        args: dict[str, tuple[str, dict[str, Any]]] = {}
        for msg in request.messages:
            for tc in msg.tool_calls:
                args[tc.id] = (tc.name, dict(tc.arguments))
        out: list[Observation] = []
        for msg in request.messages:
            if msg.role != "tool" or msg.is_error:
                continue
            trailer = _TRAILER.search(msg.content)
            blocks = wrapped_blocks(msg.content)
            if trailer is None or not blocks or blocks[0][1] is None:
                continue
            name, params = args.get(msg.tool_call_id or "", (blocks[0][0], {}))
            data = blocks[0][1] or {}
            out.append(Observation(evidence_id=trailer.group("eid"), tool=name, params=params,
                                   data=data))
        return out

    def _plan(self, agent: str, ctx: dict[str, Any], tools: set[str]) -> list[ToolCall]:
        family = family_of(ctx.get("alert_type"))
        assets = list(ctx.get("assets", []))
        calls: list[tuple[str, dict[str, Any]]] = []

        def tags(a: dict[str, Any], key: str) -> list[str]:
            raw = str((a.get("tags") or {}).get(key, ""))
            return [x.strip() for x in raw.split(",") if x.strip()]

        for a in assets:
            aid, typ = a.get("asset_id"), str(a.get("type", ""))
            if agent == "network-engineer":
                if typ in ("firewall", "fortigate"):
                    calls.append(("fortigate.policy.status", {"asset_id": aid}))
                if typ in ("load_balancer", "linux_host", "reverse_proxy"):
                    calls.append(("logs.search", {"asset_id": aid, "query": "upstream",
                                                  "window": "30m"}))
            elif agent == "devops-engineer":
                if typ == "docker_host":
                    for c in tags(a, "containers"):
                        calls.append(("docker.container.inspect", {"asset_id": aid,
                                                                   "container": c}))
                        calls.append(("logs.search", {"asset_id": aid, "query": c,
                                                      "window": "1h"}))
            elif agent == "dba-engineer":
                if typ in ("database", "postgres"):
                    calls.append(("postgres.activity", {"asset_id": aid}))
                    calls.append(("logs.search", {"asset_id": aid,
                                                  "query": "FATAL|ERROR|archive",
                                                  "window": "30m"}))
                    if family == "disk":
                        calls.append(("linux.disk.usage", {"asset_id": aid}))
            elif agent == "linux-admin" and typ in ("linux_host", "vm", "server",
                                                    "docker_host"):
                if family in ("disk", "container"):
                    calls.append(("linux.disk.usage", {"asset_id": aid}))
                if family == "container":
                    calls.append(("metrics.query", {"asset_id": aid,
                                                    "metric": "node_memory_used_percent",
                                                    "window": "1h"}))
                calls.append(("logs.search", {"asset_id": aid,
                                              "query": "error|logrotate"
                                              if family == "disk" else "error",
                                              "window": "1h"}))
                for unit in tags(a, "units"):
                    calls.append(("linux.service.status", {"asset_id": aid, "unit": unit}))
        seen: set[str] = set()
        out: list[ToolCall] = []
        for name, params in calls:
            key = json.dumps([name, params], sort_keys=True)
            if name in tools and key not in seen:
                seen.add(key)
                out.append(ToolCall(id=f"call-{len(out) + 1}", name=name, arguments=params))
        return out

    def _specialist(self, agent: str, request: CompletionRequest) -> CompletionResult:
        tools = {t.name for t in request.tools}
        ctx = self._context(request)
        family = family_of(ctx.get("alert_type"))
        tool_msgs = [m for m in request.messages if m.role == "tool"]
        if not tool_msgs:
            plan = self._plan(agent, ctx, tools)
            if plan:
                return CompletionResult(tool_calls=plan, finish_reason="tool_calls")
        observations = self._observations(request)
        db_asset = next((a.get("asset_id") for a in ctx.get("assets", [])
                         if a.get("type") in ("database", "postgres")), None)
        causes = aggregate(observations, family, db_asset=db_asset)
        ranked = sorted(causes.values(), key=lambda c: (-c.confidence, c.cause))
        proposed = any(tc.name == "change.propose" for m in request.messages
                       for tc in m.tool_calls)
        if (not proposed and "change.propose" in tools and ranked
                and ranked[0].cause in _RESTARTABLE and ranked[0].confidence >= 0.8):
            call = self._restart_proposal(ranked[0].supporting, observations)
            if call is not None:
                return CompletionResult(tool_calls=[call], finish_reason="tool_calls")
        facts = [{"evidence_id": o.evidence_id,
                  "statement": f"{o.tool}: {json.dumps(o.data, ensure_ascii=False)[:160]}"}
                 for o in observations]
        hypotheses = [{"cause": c.cause, "statement": "; ".join(c.statements)[:900],
                       "confidence": round(c.confidence, 4) if c.supporting else 0.0,
                       "supporting": c.supporting, "refuting": c.refuting,
                       "checks": c.checks[:3]}
                      for c in ranked if c.supporting or c.refuting]
        excluded = [c.cause for c in ranked if not c.supporting]
        findings = {"summary": f"{agent}: {len(observations)} проверок, "
                               f"{len(hypotheses)} гипотез",
                    "facts": facts, "hypotheses": hypotheses, "excluded_causes": excluded}
        return CompletionResult(text=json.dumps(findings, ensure_ascii=False))

    @staticmethod
    def _restart_proposal(supporting: list[str], obs: list[Observation]) -> ToolCall | None:
        for o in obs:
            if o.evidence_id in supporting and o.tool == "docker.container.inspect":
                cid = str(o.params.get("container", ""))
                if re.fullmatch(r"[a-f0-9]{12,64}", cid):
                    return ToolCall(id="call-propose", name="change.propose", arguments={
                        "runbook_id": "docker.container.restart",
                        "asset_id": o.params.get("asset_id"),
                        "params": {"container_id": cid},
                        "reason": f"контейнер {cid} остановлен; перезапуск по evidence "
                                  f"{o.evidence_id}"})
        return None

    # --- Commander: разрешение противоречия ---------------------------------------------

    def _adjudicate(self, request: CompletionRequest) -> CompletionResult:
        text = "\n".join(m.content for m in request.messages if m.role == "user")
        summary: dict[str, Any] = {}
        check_tool, check_data = "", None
        for tool, data in wrapped_blocks(text):
            if tool == "agents.summary" and data is not None:
                summary = data
            elif data is not None:
                check_tool, check_data = tool, data
        eid_match = _TRAILER.search(text)
        hyps = [h for h in summary.get("hypotheses", [])
                if h.get("cause") not in set(summary.get("excluded_causes", []))]
        top = sorted(hyps, key=lambda h: -float(h.get("confidence", 0)))[:2]
        if not top or check_data is None or eid_match is None:
            return CompletionResult(text=json.dumps({"hypotheses": [], "conclusion":
                                                     "проверка не различает гипотезы"}))
        eid = eid_match.group("eid")
        m = re.search(r"Разделяющая проверка: (\S+) (\{.*?\}) —", text)
        params: dict[str, Any] = {}
        if m:
            try:
                params = json.loads(m.group(2))
            except ValueError:
                params = {}
        signals = []
        for family in ("web", "container", "disk"):
            signals.extend(evaluate(Observation(evidence_id=eid, tool=check_tool or
                                                (m.group(1) if m else ""), params=params,
                                                data=check_data), family))
        support = {s.cause for s in signals if s.supports and s.confidence > 0}
        refute = {s.cause for s in signals if not s.supports}
        out = []
        for h in top:
            cause = str(h["cause"])
            conf = float(h.get("confidence", 0))
            if cause in support:
                out.append({"cause": cause, "confidence": round(min(0.95, conf + 0.25), 4),
                            "supporting": [eid]})
            elif cause in refute or (support and cause not in support):
                out.append({"cause": cause, "confidence": round(max(0.05, conf - 0.3), 4),
                            "refuting": [eid]})
        causes = {str(h["cause"]) for h in top}
        if support & causes:
            conclusion = "проверка подтвердила: " + ", ".join(sorted(support & causes))
        elif refute & causes:
            conclusion = "проверка опровергла: " + ", ".join(sorted(refute & causes))
        else:
            conclusion = "проверка не различает гипотезы"
        return CompletionResult(text=json.dumps({"hypotheses": out, "conclusion": conclusion},
                                                ensure_ascii=False))

    # --- чат --------------------------------------------------------------------------------

    def _chat(self, request: CompletionRequest) -> CompletionResult:
        last_user = next((m.content for m in reversed(request.messages) if m.role == "user"), "")
        tool_msgs = [m for m in request.messages if m.role == "tool"]
        if len(last_user.strip()) < 4 and not tool_msgs:
            return CompletionResult(text="NEED_INPUT: уточните, какой актив или инцидент вас "
                                         "интересует?")
        last_is_tool = bool(request.messages) and request.messages[-1].role == "tool"
        if not last_is_tool and "events.list" in {t.name for t in request.tools}:
            return CompletionResult(tool_calls=[ToolCall(id=f"chat-{len(tool_msgs) + 1}",
                                                         name="events.list",
                                                         arguments={"window": "1h"})],
                                    finish_reason="tool_calls")
        events = 0
        for m in tool_msgs[-1:]:
            for tool, data in wrapped_blocks(m.content):
                if tool == "events.list" and data:
                    events = len(data.get("events", []))
        return CompletionResult(text=f"За последний час событий: {events}. Запрос: "
                                     f"{last_user[:200]}")
