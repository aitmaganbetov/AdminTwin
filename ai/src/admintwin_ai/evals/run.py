"""CLI прогона golden dataset: ``python -m admintwin_ai.evals.run``.

Примеры::

    # CI: офлайн, детерминированная модель, без сети
    python -m admintwin_ai.evals.run --profile offline --offline-fake --output report.json

    # реальный провайдер (ключи — через env, см. config/model-profiles.example.yaml)
    ADMINTWIN_AI_CONFIG=config/model-profiles.yaml ANTHROPIC_API_KEY=... \\
        python -m admintwin_ai.evals.run --profile claude-primary --output claude.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from admintwin_ai.evals.harness import predict_all
from admintwin_ai.evals.metrics import EvalReport, evaluate, load_dataset
from admintwin_ai.resources import data_path

DEFAULT_DATASET = ("evals", "golden", "mvp-v2.jsonl")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="admintwin-eval", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", required=True,
                   help="Model Profile для всех агентов (с --offline-fake — любое имя)")
    p.add_argument("--offline-fake", action="store_true",
                   help="детерминированная офлайн-модель вместо реальных LLM (CI)")
    p.add_argument("--dataset", type=Path, default=None, help="JSONL golden dataset")
    p.add_argument("--config", default=os.environ.get("ADMINTWIN_AI_CONFIG"),
                   help="конфигурация провайдеров (по умолчанию ADMINTWIN_AI_CONFIG)")
    p.add_argument("--output", type=Path, default=None, help="куда записать отчёт JSON")
    p.add_argument("--predictions-out", type=Path, default=None,
                   help="куда записать предсказания JSONL")
    p.add_argument("--case", action="append", default=[], help="прогнать только эти case_id")
    p.add_argument("--timeout-s", type=float, default=180.0, help="лимит на кейс")
    return p


def run(args: argparse.Namespace) -> tuple[EvalReport, list[dict[str, object]]]:
    dataset = args.dataset or data_path(*DEFAULT_DATASET)
    cases = load_dataset(dataset)
    if args.case:
        cases = [c for c in cases if c.case_id in set(args.case)]
    if not args.offline_fake and not args.config:
        raise SystemExit("real-provider run needs --config or ADMINTWIN_AI_CONFIG "
                         "(or use --offline-fake)")
    preds, infos = asyncio.run(predict_all(
        cases, profile=args.profile, offline_fake=args.offline_fake,
        ai_config=None if args.offline_fake else args.config, timeout_s=args.timeout_s))
    report = evaluate(cases, preds)
    if args.predictions_out:
        args.predictions_out.write_text("\n".join(p.model_dump_json() for p in preds) + "\n",
                                        encoding="utf-8")
    return report, infos


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report, infos = run(args)
    payload = {"profile": args.profile, "offline_fake": args.offline_fake,
               "dataset": str(args.dataset or "/".join(DEFAULT_DATASET)),
               **report.model_dump(mode="json"), "runs": infos}
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    summary = (f"cases={report.cases} precision@1={report.precision_at_1:.2%} "
               f"precision@3={report.precision_at_3:.2%} "
               f"false_confident={report.false_confident_rate:.2%} "
               f"unjustified_refusals={report.unjustified_refusal_rate:.2%} "
               f"tool_calls_to_correct={report.mean_tool_calls_to_correct}")
    print(summary, file=sys.stderr)
    if not args.output:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
