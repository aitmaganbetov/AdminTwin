"""Структурированные итоги агентов (``contracts/agent-findings.schema.json``).

Модель обязана завершить работу JSON-объектом по схеме. Оркестратор не
доверяет ему слепо (``sanitize``):

* ссылки на evidence, которых нет в задаче, отбрасываются (галлюцинации и
  «evidence», подсказанные данными инструментов, не принимаются);
* гипотеза без подтверждающих evidence получает confidence ≤ 0.5 —
  первопричина не утверждается без доказательств (§9);
* предлагаемые проверки — только существующие read tools.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any

import jsonschema
from pydantic import BaseModel, Field

from admintwin_ai.orchestrator.commander import Check, Hypothesis
from admintwin_ai.resources import load_json

NO_EVIDENCE_CONFIDENCE_CAP = 0.5


class Fact(BaseModel):
    evidence_id: str
    statement: str


class Findings(BaseModel):
    summary: str = ""
    facts: list[Fact] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    excluded_causes: list[str] = Field(default_factory=list)
    suggested_agents: list[str] = Field(default_factory=list)
    conclusion: str = ""
    dropped_evidence_refs: int = 0


@lru_cache(maxsize=1)
def findings_schema() -> dict[str, Any]:
    return load_json("contracts", "agent-findings.schema.json")


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(findings_schema())


_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def extract_json(text: str) -> dict[str, Any] | None:
    """Первый JSON-объект в тексте (в т.ч. внутри ```json ...```)."""
    candidates: list[str] = [m.group(1) for m in _FENCE.finditer(text)]
    start = text.find("{")
    while start != -1 and len(candidates) < 20:
        end = _balanced_end(text, start)
        if end is None:
            start = text.find("{", start + 1)
            continue
        candidates.append(text[start:end + 1])
        start = text.find("{", end + 1)
    for c in candidates:
        try:
            value = json.loads(c)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _balanced_end(text: str, start: int) -> int | None:
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def parse_findings(text: str, *, agent_id: str) -> Findings | None:
    """None — итог не является валидным JSON по схеме findings."""
    raw = extract_json(text)
    if raw is None:
        return None
    if list(_validator().iter_errors(raw)):
        return None
    hyps = [
        Hypothesis(
            cause=h["cause"], statement=h.get("statement", ""),
            confidence=float(h["confidence"]), proposed_by=[agent_id],
            supporting=list(h.get("supporting", [])), refuting=list(h.get("refuting", [])),
            checks=[Check(tool=c["tool"], description=c["description"],
                          params=dict(c.get("params", {}))) for c in h.get("checks", [])],
        )
        for h in raw.get("hypotheses", [])
    ]
    return Findings(
        summary=raw.get("summary", ""),
        facts=[Fact(**f) for f in raw.get("facts", [])],
        hypotheses=hyps,
        excluded_causes=list(raw.get("excluded_causes", [])),
        suggested_agents=list(raw.get("suggested_agents", [])),
        conclusion=raw.get("conclusion", ""),
    )


def sanitize(findings: Findings, *, known_evidence: set[str],
             read_tools: set[str]) -> Findings:
    dropped = 0

    def keep(ids: list[str]) -> list[str]:
        nonlocal dropped
        out = [i for i in dict.fromkeys(ids) if i in known_evidence]
        dropped += len(ids) - len(out)
        return out

    hyps: list[Hypothesis] = []
    for h in findings.hypotheses:
        supporting = keep(h.supporting)
        refuting = keep(h.refuting)
        confidence = h.confidence
        if not supporting:
            confidence = min(confidence, NO_EVIDENCE_CONFIDENCE_CAP)
        checks = [c for c in h.checks if c.tool in read_tools]
        hyps.append(h.model_copy(update={"supporting": supporting, "refuting": refuting,
                                         "confidence": round(confidence, 4),
                                         "checks": checks}))
    facts = [f for f in findings.facts if f.evidence_id in known_evidence]
    dropped += len(findings.facts) - len(facts)
    return findings.model_copy(update={"hypotheses": hyps, "facts": facts,
                                       "dropped_evidence_refs": dropped})
