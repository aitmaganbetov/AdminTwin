"""Проверка совместимости локальной LLM (§6.9) с AdminTwin.

Проверяет OpenAI-совместимый endpoint (vLLM, Ollama, llama.cpp server,
LM Studio, TGI) через тот же адаптер ``LocalProvider``, что использует
платформа:

1. ``models`` — endpoint обслуживает закреплённую модель (pinning, §18.6);
2. ``tool_calling`` — модель вызывает инструмент с аргументами, валидными по
   JSON Schema (формат AdminTwin → OpenAI ``tools``);
3. ``structured_output`` — ответ по ``response_format=json_schema``
   разбирается и проходит валидацию схемы;
4. ``context`` — запрос размером ≥ ``--min-context`` токенов (по умолчанию
   32k, оценка ≈4 символа/токен) обрабатывается, а «иголка» из начала
   контекста возвращается в ответе.

Результат — JSON-отчёт и рекомендуемый блок ``declared_capabilities`` для
``config/model-profiles*.yaml``. Код выхода 0 — все обязательные проверки
пройдены.

Пример::

    python -m admintwin_ai.providers.compat_check \\
        --base-url http://llm.admintwin.internal:8000/v1 --model Qwen/Qwen3-32B
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from typing import Any

import jsonschema
from pydantic import BaseModel, Field

from admintwin_ai.providers.base import (
    ChatMessage,
    CompletionRequest,
    ProviderCapabilities,
    ToolSpec,
)
from admintwin_ai.providers.local.adapter import LocalProvider

MIN_CONTEXT = 32_768

TOOL = ToolSpec(
    name="metrics.query",
    description="Query a metric time series for an asset (read-only).",
    input_schema={
        "type": "object", "additionalProperties": False,
        "required": ["asset_id", "metric", "window"],
        "properties": {
            "asset_id": {"type": "string",
                         "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                                    "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"},
            "metric": {"type": "string", "pattern": "^[a-zA-Z_:][a-zA-Z0-9_:]{0,199}$"},
            "window": {"type": "string", "pattern": "^[1-9][0-9]{0,3}[smhd]$"},
        },
    },
)
TOOL_ASSET = "a0000000-0000-4000-8000-000000000002"

STRUCTURED_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["cause", "confidence", "evidence_ids"],
    "properties": {
        "cause": {"type": "string", "enum": ["disk_full", "container_oom", "network_block"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
    },
}


class CheckResult(BaseModel):
    ok: bool
    detail: str = ""
    latency_ms: float = 0.0


class CompatReport(BaseModel):
    endpoint: str
    model: str
    checks: dict[str, CheckResult] = Field(default_factory=dict)
    min_context: int = MIN_CONTEXT
    passed: bool = False
    declared_capabilities: dict[str, Any] = Field(default_factory=dict)


def _provider(base_url: str, api_key: str | None, timeout_s: float,
              client: Any | None) -> LocalProvider:
    caps = ProviderCapabilities(tool_calling=True, structured_output=True, streaming=True,
                                embeddings=False, max_context=10_000_000)
    return LocalProvider("compat-check", base_url=base_url, allowed_endpoints=[base_url],
                         declared_capabilities=caps, api_key=api_key, timeout_s=timeout_s,
                         max_retries=0, client=client)


def _timed(fn: Any) -> tuple[Any, float]:
    started = time.monotonic()
    value = fn()
    return value, round((time.monotonic() - started) * 1000, 1)


def check_models(p: LocalProvider, model: str) -> CheckResult:
    h = p.health(model)
    return CheckResult(ok=h.ok, detail=h.detail or "model is served", latency_ms=h.latency_ms)


def check_tool_calling(p: LocalProvider, model: str) -> CheckResult:
    req = CompletionRequest(
        model=model, max_tokens=512, tools=[TOOL],
        system="You are a diagnostic agent. Use tools to fetch data; never answer from memory.",
        messages=[ChatMessage(role="user", content=(
            f"Fetch metric node_disk_used_percent for asset {TOOL_ASSET} over the last 15m. "
            "Call the tool now."))])
    try:
        res, ms = _timed(lambda: p.tool_call(req))
    except Exception as exc:
        return CheckResult(ok=False, detail=f"{type(exc).__name__}: {str(exc)[:200]}")
    if not res.tool_calls:
        return CheckResult(ok=False, detail="model answered without a tool call", latency_ms=ms)
    call = res.tool_calls[0]
    if call.name != TOOL.name or call.malformed:
        return CheckResult(ok=False, detail=f"unexpected call {call.name!r} "
                                            f"(malformed={call.malformed})", latency_ms=ms)
    errors = list(jsonschema.Draft202012Validator(TOOL.input_schema).iter_errors(call.arguments))
    if errors:
        return CheckResult(ok=False, detail=f"arguments invalid: {errors[0].message}",
                           latency_ms=ms)
    return CheckResult(ok=True, detail=f"arguments={json.dumps(call.arguments)}", latency_ms=ms)


def check_structured_output(p: LocalProvider, model: str) -> CheckResult:
    req = CompletionRequest(
        model=model, max_tokens=256, response_schema=STRUCTURED_SCHEMA,
        messages=[ChatMessage(role="user", content=(
            "Evidence ev-1: '/var 99% used'. Evidence ev-2: 'no space left on device'. "
            "Return the most likely cause as JSON."))])
    try:
        res, ms = _timed(lambda: p.complete(req))
    except Exception as exc:
        return CheckResult(ok=False, detail=f"{type(exc).__name__}: {str(exc)[:200]}")
    try:
        value = json.loads(res.text)
    except ValueError:
        return CheckResult(ok=False, detail="response is not JSON", latency_ms=ms)
    errors = list(jsonschema.Draft202012Validator(STRUCTURED_SCHEMA).iter_errors(value))
    if errors:
        return CheckResult(ok=False, detail=f"schema violation: {errors[0].message}",
                           latency_ms=ms)
    return CheckResult(ok=True, detail=f"cause={value['cause']}", latency_ms=ms)


def check_context(p: LocalProvider, model: str, min_context: int) -> CheckResult:
    needle = f"NEEDLE-{secrets.token_hex(4).upper()}"
    filler_line = "log: 2026-11-09T05:00:00Z web01 nginx upstream response ok status=200\n"
    target_chars = min_context * 4
    filler = filler_line * (target_chars // len(filler_line) + 1)
    content = (f"The secret marker is {needle}. Remember it.\n" + filler +
               "\nQuestion: what is the secret marker mentioned at the very beginning? "
               "Answer with the marker only.")
    req = CompletionRequest(model=model, max_tokens=64,
                            messages=[ChatMessage(role="user", content=content)])
    try:
        res, ms = _timed(lambda: p.complete(req))
    except Exception as exc:
        return CheckResult(ok=False, detail=f"{type(exc).__name__}: {str(exc)[:200]}")
    if needle not in res.text:
        return CheckResult(ok=False, detail="marker from the start of the context was not "
                                            "recalled", latency_ms=ms)
    used = res.usage.input_tokens
    if used and used < min_context * 0.8:
        return CheckResult(ok=False, detail=f"endpoint reported only {used} prompt tokens",
                           latency_ms=ms)
    return CheckResult(ok=True, detail=f"~{len(content) // 4} tokens, recalled marker",
                       latency_ms=ms)


def run_checks(base_url: str, model: str, *, api_key: str | None = None,
               min_context: int = MIN_CONTEXT, timeout_s: float = 300.0,
               client: Any | None = None, skip_context: bool = False) -> CompatReport:
    p = _provider(base_url, api_key, timeout_s, client)
    report = CompatReport(endpoint=base_url, model=model, min_context=min_context)
    report.checks["models"] = check_models(p, model)
    report.checks["tool_calling"] = check_tool_calling(p, model)
    report.checks["structured_output"] = check_structured_output(p, model)
    if not skip_context:
        report.checks["context"] = check_context(p, model, min_context)
    report.passed = all(c.ok for c in report.checks.values())
    ctx_ok = report.checks.get("context")
    report.declared_capabilities = {
        "tool_calling": report.checks["tool_calling"].ok,
        "structured_output": report.checks["structured_output"].ok,
        "streaming": True,
        "embeddings": False,
        "max_context": min_context if ctx_ok and ctx_ok.ok else 0,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="admintwin-llm-compat", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", required=True, help="OpenAI-совместимый endpoint, .../v1")
    ap.add_argument("--model", required=True, help="закреплённая модель")
    ap.add_argument("--api-key", default=None, help="ключ endpoint, если требуется")
    ap.add_argument("--min-context", type=int, default=MIN_CONTEXT)
    ap.add_argument("--timeout-s", type=float, default=300.0)
    ap.add_argument("--skip-context", action="store_true", help="пропустить проверку контекста")
    args = ap.parse_args(argv)
    report = run_checks(args.base_url, args.model, api_key=args.api_key,
                        min_context=args.min_context, timeout_s=args.timeout_s,
                        skip_context=args.skip_context)
    print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
