"""CI gate регрессии AI (§6.10): сравнение отчёта с baseline.

Блокирует (exit 1), если precision@1 упала более чем на ``--max-drop-pp``
процентных пунктов к baseline, precision@1 ниже ``--min-precision``
или доля ложно-уверенных ≥ ``--max-false-confident``.

Примеры::

    # прогнать офлайн-оценку и сравнить с baseline (CI)
    python -m admintwin_ai.evals.gate --run --profile offline --offline-fake \\
        --baseline evals/baselines/offline-fake.json

    # сравнить готовый отчёт
    python -m admintwin_ai.evals.gate --report claude.json --baseline evals/baselines/claude.json

    # обновить baseline (осознанно, после ревью)
    python -m admintwin_ai.evals.gate --run --profile offline --offline-fake \\
        --baseline evals/baselines/offline-fake.json --update-baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from admintwin_ai.evals.metrics import EvalReport, check_gate


def _load_report(path: Path) -> EvalReport:
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    fields = set(EvalReport.model_fields)
    return EvalReport.model_validate({k: v for k, v in raw.items() if k in fields})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="admintwin-eval-gate", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--report", type=Path, help="отчёт admintwin-eval (JSON)")
    src.add_argument("--run", action="store_true", help="прогнать оценку перед сравнением")
    p.add_argument("--profile", default="offline")
    p.add_argument("--offline-fake", action="store_true")
    p.add_argument("--dataset", type=Path, default=None)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--max-drop-pp", type=float, default=5.0)
    p.add_argument("--min-precision", type=float, default=0.70)
    p.add_argument("--max-false-confident", type=float, default=0.05)
    p.add_argument("--update-baseline", action="store_true",
                   help="записать текущий отчёт как baseline (только осознанно)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.run:
        from admintwin_ai.evals.run import build_parser as run_parser
        from admintwin_ai.evals.run import run

        run_args = ["--profile", args.profile]
        if args.offline_fake:
            run_args.append("--offline-fake")
        if args.dataset:
            run_args += ["--dataset", str(args.dataset)]
        report, _ = run(run_parser().parse_args(run_args))
    else:
        report = _load_report(args.report)
    if args.update_baseline:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(json.dumps(report.model_dump(mode="json"), ensure_ascii=False,
                                            indent=2) + "\n", encoding="utf-8")
        print(f"baseline updated: {args.baseline}", file=sys.stderr)
        return 0
    baseline = _load_report(args.baseline) if args.baseline.exists() else None
    if baseline is None:
        print(f"baseline {args.baseline} not found", file=sys.stderr)
        return 2
    gate = check_gate(report, baseline=baseline, min_precision_at_1=args.min_precision,
                      max_drop_pp=args.max_drop_pp,
                      max_false_confident_rate=args.max_false_confident)
    print(json.dumps({"passed": gate.passed, "failures": gate.failures,
                      "precision_at_1": report.precision_at_1,
                      "baseline_precision_at_1": baseline.precision_at_1,
                      "false_confident_rate": report.false_confident_rate,
                      "unjustified_refusal_rate": report.unjustified_refusal_rate},
                     ensure_ascii=False))
    return 0 if gate.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
