"""Eval skeleton (§6.10): формат датасета и метрики."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from admintwin_ai.evals import (
    EvalCase,
    Prediction,
    RankedCause,
    check_gate,
    evaluate,
    load_dataset,
    load_predictions,
    run_eval,
)
from admintwin_ai.evals.metrics import parse_case


@pytest.fixture
def cases() -> list[EvalCase]:
    return load_dataset()


def _p(case_id: str, *ranked: tuple[str, float], calls: int | None = None) -> Prediction:
    return Prediction(case_id=case_id, tool_calls_to_correct=calls,
                      hypotheses=[RankedCause(cause=c, confidence=x) for c, x in ranked])


def test_golden_dataset_has_three_mvp_scenarios(cases: list[EvalCase]) -> None:
    assert {c.scenario for c in cases} == {"http_502", "disk_exhaustion", "container_stop"}
    for c in cases:
        assert c.expected.evidence and c.expected.expected_checks


def test_perfect_predictions(cases: list[EvalCase]) -> None:
    preds = [_p(c.case_id, (c.expected.root_cause, 0.9), calls=3) for c in cases]
    r = evaluate(cases, preds)
    assert r.precision_at_1 == 1.0 and r.precision_at_3 == 1.0
    assert r.false_confident_rate == 0.0 and r.unjustified_refusal_rate == 0.0
    assert r.mean_tool_calls_to_correct == 3.0
    assert check_gate(r).passed


def test_mixed_predictions_metrics(cases: list[EvalCase]) -> None:
    c502, cdisk, ccont = cases
    preds = [
        # верная причина вторая → p@1 промах, p@3 попадание; top-1 уверен (0.85) → ложно-уверенный
        _p(c502.case_id, ("db_connections_exhausted", 0.85),
           ("upstream_container_stopped", 0.6), calls=5),
        # acceptable_causes засчитывается; порядок — по confidence, а не по списку
        _p(cdisk.case_id, ("database_bloat", 0.3), ("application_log_growth", 0.7), calls=2),
        # нет предсказания для третьего кейса → необоснованный отказ
    ]
    r = evaluate(cases, preds)
    assert r.precision_at_1 == round(1 / 3, 4)
    assert r.precision_at_3 == round(2 / 3, 4)
    assert r.false_confident_rate == round(1 / 3, 4)
    assert r.unjustified_refusal_rate == round(1 / 3, 4)
    assert r.mean_tool_calls_to_correct == 3.5
    by_id = {x.case_id: x for x in r.results}
    assert by_id[ccont.case_id].refused and not by_id[ccont.case_id].hit_at_3
    assert by_id[c502.case_id].false_confident


def test_wrong_but_not_confident_is_not_false_confident(cases: list[EvalCase]) -> None:
    preds = [_p(c.case_id, ("wrong_cause", 0.8)) for c in cases]  # ровно 0.8 — не «> 0.8»
    r = evaluate(cases, preds)
    assert r.precision_at_1 == 0.0 and r.false_confident_rate == 0.0


def test_gate_thresholds_and_regression(cases: list[EvalCase]) -> None:
    good = evaluate(cases, [_p(c.case_id, (c.expected.root_cause, 0.7)) for c in cases])
    two_of_three = evaluate(cases, [_p(c.case_id, (c.expected.root_cause, 0.7))
                                    for c in cases[:2]] + [_p(cases[2].case_id, ("x", 0.95))])
    gate = check_gate(two_of_three, baseline=good)
    assert not gate.passed
    assert any("precision@1" in f and "<" in f for f in gate.failures)  # 66.7% < 70%
    assert any("dropped" in f for f in gate.failures)  # −33 п.п. > 5 п.п.
    assert any("false_confident_rate" in f for f in gate.failures)
    assert check_gate(good, baseline=good).passed


def test_run_eval_and_prediction_files(cases: list[EvalCase], tmp_path: Path) -> None:
    report = run_eval(cases, lambda c: _p(c.case_id, (c.expected.root_cause, 0.9)))
    assert report.cases == 3 and report.precision_at_1 == 1.0
    path = tmp_path / "preds.jsonl"
    path.write_text("\n".join(_p(c.case_id, ("x", 0.1)).model_dump_json() for c in cases) + "\n",
                    encoding="utf-8")
    assert len(load_predictions(path)) == 3


def test_invalid_case_rejected(cases: list[EvalCase], tmp_path: Path) -> None:
    raw = cases[0].model_dump()
    raw["expected"]["evidence"] = []
    with pytest.raises(ValueError, match="invalid eval case"):
        parse_case(raw)
    dup = tmp_path / "dup.jsonl"
    line = json.dumps(cases[0].model_dump(), ensure_ascii=False)
    dup.write_text(line + "\n" + line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_dataset(dup)
