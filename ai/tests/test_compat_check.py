"""Скрипт проверки совместимости локальной LLM (§6.9) против фейкового
OpenAI-совместимого сервера (настоящий HTTP на loopback, без внешней сети)."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest

from admintwin_ai.providers.compat_check import main, run_checks

MODEL = "Qwen/Qwen3-32B"


class FakeOpenAI(BaseHTTPRequestHandler):
    behaviour: ClassVar[dict[str, Any]] = {}
    seen: ClassVar[list[dict[str, Any]]] = []

    def log_message(self, *args: Any) -> None:
        return None

    def _send(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path.endswith("/models"):
            self._send(200, {"object": "list", "data": [{"id": m, "object": "model"}
                                                        for m in self.behaviour["models"]]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        self.seen.append(body)
        b = self.behaviour
        msg: dict[str, Any] = {"role": "assistant", "content": None}
        finish = "stop"
        prompt = body["messages"][-1]["content"]
        prompt_tokens = len(json.dumps(body["messages"])) // 4
        if body.get("tools"):
            if b["tools"]:
                msg["tool_calls"] = [{"id": "c1", "type": "function", "function": {
                    "name": body["tools"][0]["function"]["name"],
                    "arguments": json.dumps({"asset_id": "a0000000-0000-4000-8000-000000000002",
                                             "metric": "node_disk_used_percent",
                                             "window": "15m"})}}]
                finish = "tool_calls"
            else:
                msg["content"] = "The disk is fine."
        elif body.get("response_format"):
            msg["content"] = json.dumps({"cause": "disk_full", "confidence": 0.9,
                                         "evidence_ids": ["ev-1", "ev-2"]}) \
                if b["structured"] else "disk_full, probably"
        else:
            ctx_limit = b["context"]
            if prompt_tokens > ctx_limit:
                self._send(400, {"error": {"message": "maximum context length exceeded",
                                           "type": "invalid_request_error"}})
                return
            m = re.search(r"NEEDLE-[0-9A-F]{8}", prompt)
            msg["content"] = m.group(0) if m else "?"
        self._send(200, {"id": "x", "object": "chat.completion", "model": body["model"],
                         "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                         "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 5,
                                   "total_tokens": prompt_tokens + 5}})


@pytest.fixture
def server() -> Iterator[str]:
    FakeOpenAI.behaviour = {"models": [MODEL], "tools": True, "structured": True,
                            "context": 200_000}
    FakeOpenAI.seen = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAI)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/v1"
    httpd.shutdown()


def test_compatible_model_passes(server: str) -> None:
    report = run_checks(server, MODEL, timeout_s=30)
    assert report.passed, report.model_dump()
    assert set(report.checks) == {"models", "tool_calling", "structured_output", "context"}
    assert report.declared_capabilities == {"tool_calling": True, "structured_output": True,
                                            "streaming": True, "embeddings": False,
                                            "max_context": 32768}
    # проверка контекста реально отправила ≥ 32k токенов (оценка 4 символа/токен)
    longest = max(len(json.dumps(b["messages"])) for b in FakeOpenAI.seen)
    assert longest // 4 >= 32768
    # инструмент передан в формате OpenAI с кодированием точки в имени
    tool_req = next(b for b in FakeOpenAI.seen if b.get("tools"))
    assert tool_req["tools"][0]["function"]["name"] == "metrics__query"


def test_incompatible_model_fails_each_check(server: str) -> None:
    FakeOpenAI.behaviour.update(tools=False, structured=False, context=8192)
    report = run_checks(server, MODEL, timeout_s=30)
    assert not report.passed
    assert not report.checks["tool_calling"].ok
    assert not report.checks["structured_output"].ok
    assert not report.checks["context"].ok
    assert report.declared_capabilities["max_context"] == 0


def test_model_pinning_and_cli_exit_code(server: str,
                                         capsys: pytest.CaptureFixture[str]) -> None:
    FakeOpenAI.behaviour.update(models=["some/other-model"])
    assert main(["--base-url", server, "--model", MODEL, "--skip-context",
                 "--timeout-s", "30"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["checks"]["models"]["ok"] is False
    assert "not served" in out["checks"]["models"]["detail"]
    FakeOpenAI.behaviour.update(models=[MODEL])
    assert main(["--base-url", server, "--model", MODEL, "--timeout-s", "30"]) == 0
