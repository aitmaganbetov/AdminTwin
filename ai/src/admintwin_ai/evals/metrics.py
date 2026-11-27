"""Скелет AI Evaluation (M22, §6.10): формат golden dataset и метрики.

Метрики:

* ``precision@1`` / ``precision@3`` — доля кейсов, где верная причина
  (``root_cause`` или ``acceptable_causes``) в top-1 / top-3 гипотез;
* ``false_confident_rate`` — доля кейсов, где top-1 неверна при
  confidence > 0.8 (знаменатель — все кейсы датасета);
* ``mean_tool_calls_to_correct`` — среднее число tool calls до верной гипотезы;
* ``unjustified_refusal_rate`` — доля кейсов без ответа (у golden-кейса
  причина известна, поэтому любой отказ необоснован).

Блокирующий порог (§6.10, §21): precision@1 ≥ 0.70 для primary, падение
precision@1 относительно baseline не более 5 п.п., ложно-уверенных < 5%.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema
from pydantic import BaseModel, Field

from admintwin_ai.resources import data_path, load_json

FALSE_CONFIDENT_THRESHOLD = 0.8


class EvalExpected(BaseModel):
    root_cause: str
    acceptable_causes: list[str] = Field(default_factory=list)
    evidence: list[str]
    expected_checks: list[str]
    excluded_causes: list[str] = Field(default_factory=list)

    @property
    def correct(self) -> frozenset[str]:
        return frozenset([self.root_cause, *self.acceptable_causes])


class EvalCase(BaseModel):
    case_id: str
    scenario: str
    title: str
    input: dict[str, Any]
    expected: EvalExpected
    tags: list[str] = Field(default_factory=list)


class RankedCause(BaseModel):
    cause: str
    confidence: float = Field(ge=0.0, le=1.0)


class Prediction(BaseModel):
    case_id: str
    hypotheses: list[RankedCause] = Field(default_factory=list)
    tool_calls_to_correct: int | None = None
    refused: bool = False

    def ranked(self) -> list[RankedCause]:
        return sorted(self.hypotheses, key=lambda h: -h.confidence)


class CaseResult(BaseModel):
    case_id: str
    hit_at_1: bool
    hit_at_3: bool
    false_confident: bool
    refused: bool
    top_cause: str | None = None
    top_confidence: float | None = None


class EvalReport(BaseModel):
    cases: int
    precision_at_1: float
    precision_at_3: float
    false_confident_rate: float
    unjustified_refusal_rate: float
    mean_tool_calls_to_correct: float | None
    results: list[CaseResult]


class GateResult(BaseModel):
    passed: bool
    failures: list[str] = Field(default_factory=list)


@lru_cache(maxsize=1)
def _case_validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(load_json("evals", "eval-case.schema.json"))


def parse_case(raw: dict[str, Any]) -> EvalCase:
    errors = list(_case_validator().iter_errors(raw))
    if errors:
        raise ValueError(f"invalid eval case {raw.get('case_id', '?')}: {errors[0].message}")
    return EvalCase.model_validate(raw)


def load_dataset(path: str | Path | None = None) -> list[EvalCase]:
    path = Path(path) if path is not None else data_path("evals", "golden", "mvp-v1.jsonl")
    cases: list[EvalCase] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            case = parse_case(json.loads(line))
            if case.case_id in seen:
                raise ValueError(f"{path}:{lineno}: duplicate case_id {case.case_id}")
            seen.add(case.case_id)
            cases.append(case)
    return cases


def load_predictions(path: str | Path) -> list[Prediction]:
    with Path(path).open(encoding="utf-8") as fh:
        return [Prediction.model_validate_json(line) for line in fh if line.strip()]


def evaluate(cases: Sequence[EvalCase], predictions: Iterable[Prediction]) -> EvalReport:
    by_id = {p.case_id: p for p in predictions}
    results: list[CaseResult] = []
    tool_calls: list[int] = []
    for case in cases:
        pred = by_id.get(case.case_id)
        ranked = pred.ranked() if pred is not None else []
        refused = pred is None or pred.refused or not ranked
        correct = case.expected.correct
        top = ranked[0] if ranked else None
        hit1 = top is not None and top.cause in correct
        hit3 = any(h.cause in correct for h in ranked[:3])
        false_conf = (top is not None and not hit1
                      and top.confidence > FALSE_CONFIDENT_THRESHOLD)
        if pred is not None and hit3 and pred.tool_calls_to_correct is not None:
            tool_calls.append(pred.tool_calls_to_correct)
        results.append(CaseResult(case_id=case.case_id, hit_at_1=hit1, hit_at_3=hit3,
                                  false_confident=false_conf, refused=refused,
                                  top_cause=top.cause if top else None,
                                  top_confidence=top.confidence if top else None))
    n = len(results)

    def rate(flag: Callable[[CaseResult], bool]) -> float:
        return round(sum(1 for r in results if flag(r)) / n, 4) if n else 0.0

    return EvalReport(
        cases=n,
        precision_at_1=rate(lambda r: r.hit_at_1),
        precision_at_3=rate(lambda r: r.hit_at_3),
        false_confident_rate=rate(lambda r: r.false_confident),
        unjustified_refusal_rate=rate(lambda r: r.refused),
        mean_tool_calls_to_correct=round(sum(tool_calls) / len(tool_calls), 3)
        if tool_calls else None,
        results=results,
    )


def run_eval(cases: Sequence[EvalCase], predictor: Callable[[EvalCase], Prediction]) -> EvalReport:
    return evaluate(cases, [predictor(c) for c in cases])


def check_gate(report: EvalReport, *, baseline: EvalReport | None = None,
               min_precision_at_1: float = 0.70, max_drop_pp: float = 5.0,
               max_false_confident_rate: float = 0.05) -> GateResult:
    failures: list[str] = []
    if report.precision_at_1 < min_precision_at_1:
        failures.append(f"precision@1 {report.precision_at_1:.2%} < {min_precision_at_1:.0%}")
    if report.false_confident_rate >= max_false_confident_rate:
        failures.append(f"false_confident_rate {report.false_confident_rate:.2%} "
                        f">= {max_false_confident_rate:.0%}")
    if baseline is not None:
        drop_pp = round((baseline.precision_at_1 - report.precision_at_1) * 100, 6)
        if drop_pp > max_drop_pp:
            failures.append(f"precision@1 dropped {drop_pp:.1f} pp (> {max_drop_pp:.1f} pp)")
    return GateResult(passed=not failures, failures=failures)
