"""Golden dataset ≥ 30 кейсов, офлайн-прогон через полный путь оркестратора, CI gate (§6.10)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from admintwin_ai.evals import gate, run
from admintwin_ai.evals.harness import FixtureBackend, predict_case
from admintwin_ai.evals.metrics import EvalReport, check_gate, evaluate, load_dataset
from admintwin_ai.resources import data_path

DATASET = data_path("evals", "golden", "mvp-v2.jsonl")
BASELINE = data_path("evals", "baselines", "offline-fake.json")


def test_golden_dataset_size_and_offline_fixtures() -> None:
    cases = load_dataset(DATASET)
    assert len(cases) >= 30
    per = Counter(c.scenario for c in cases)
    assert all(per[s] >= 10 for s in ("http_502", "disk_exhaustion", "container_stop")), per
    for c in cases:
        assert c.input["assets"] and c.input["scope"] and c.input["fixtures"]
        assert c.expected.evidence and c.expected.expected_checks
        # каждый ответ фикстуры валиден по output-схеме контракта инструмента
        import jsonschema

        from admintwin_ai.tools import load_contracts

        contracts = load_contracts()
        for tool, entries in c.input["fixtures"].items():
            schema = contracts[tool].output_schema
            for e in entries:
                errs = list(jsonschema.Draft202012Validator(schema).iter_errors(e["response"]))
                assert not errs, (c.case_id, tool, errs[0].message)
    assert any("conflict" in c.tags for c in cases)


def test_fixture_backend_log_search_semantics() -> None:
    case = next(c for c in load_dataset(DATASET) if c.case_id == "container-host-oom-004")
    b = FixtureBackend(case, "t")
    aid = case.input["scope"][0]
    out = b.fetch("logs.search", "t", {"asset_id": aid, "query": "out of memory: killed",
                                       "window": "1h"})
    assert out.data["entries"]
    # явная фикстура с match.query имеет приоритет (пустой ответ целевого поиска)
    out = b.fetch("logs.search", "t", {"asset_id": aid, "query": "memory cgroup out of memory",
                                       "window": "1h"})
    assert out.data["entries"] == []
    assert not b.asset_exists("other-tenant", aid)


async def test_offline_eval_meets_mvp_thresholds() -> None:
    cases = load_dataset(DATASET)
    preds = []
    for c in cases:
        p, info = await predict_case(c, profile="offline", offline_fake=True)
        assert info["state"] in ("completed", "failed"), info
        preds.append(p)
    report = evaluate(cases, preds)
    assert report.precision_at_1 >= 0.70
    assert report.false_confident_rate < 0.05
    assert report.unjustified_refusal_rate < 0.05
    assert report.mean_tool_calls_to_correct is not None
    baseline = EvalReport.model_validate_json(BASELINE.read_text(encoding="utf-8"))
    assert check_gate(report, baseline=baseline).passed


async def test_conflict_case_uses_separating_check() -> None:
    case = next(c for c in load_dataset(DATASET) if c.case_id == "container-host-oom-004")
    pred, info = await predict_case(case, profile="offline", offline_fake=True)
    assert pred.ranked()[0].cause == "host_out_of_memory"
    assert "разделяющая проверка выполнена" in info["conclusion"]


def test_cli_and_gate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "report.json"
    preds = tmp_path / "preds.jsonl"
    ids = ["http502-upstream-oom-002", "disk-wal-archiving-007", "container-image-pull-007"]
    argv = ["--profile", "offline", "--offline-fake", "--output", str(out),
            "--predictions-out", str(preds)]
    for i in ids:
        argv += ["--case", i]
    assert run.main(argv) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["cases"] == 3 and report["precision_at_1"] == 1.0
    assert len(preds.read_text(encoding="utf-8").splitlines()) == 3
    assert "precision@1=100.00%" in capsys.readouterr().err

    baseline = tmp_path / "baseline.json"
    assert gate.main(["--report", str(out), "--baseline", str(baseline),
                      "--update-baseline"]) == 0
    assert gate.main(["--report", str(out), "--baseline", str(baseline)]) == 0
    # падение precision@1 > 5 п.п. к baseline блокирует
    worse = dict(report, precision_at_1=0.9)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(worse), encoding="utf-8")
    assert gate.main(["--report", str(bad), "--baseline", str(baseline)]) == 1
    assert "dropped" in capsys.readouterr().out
    assert gate.main(["--report", str(out), "--baseline", str(tmp_path / "nope.json")]) == 2


def test_real_provider_run_requires_config() -> None:
    with pytest.raises(SystemExit, match="ADMINTWIN_AI_CONFIG"):
        run.run(run.build_parser().parse_args(["--profile", "claude-primary"]))
