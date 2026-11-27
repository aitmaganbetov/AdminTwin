"""Общая реализация для OpenAI Chat Completions и OpenAI-совместимых endpoint.

Используется адаптерами ``openai`` (внешний провайдер) и ``local``
(vLLM / Ollama / llama.cpp / LM Studio / TGI через ``base_url``).
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

import openai

from admintwin_ai.errors import (
    ProviderConfigError,
    ProviderError,
    ProviderRateLimitedError,
    ProviderRequestError,
    ProviderUnavailableError,
)
from admintwin_ai.providers.base import (
    ChatMessage,
    CompletionRequest,
    CompletionResult,
    ConnectionMode,
    EmbeddingResult,
    FinishReason,
    HealthStatus,
    ProviderCapabilities,
    StreamEvent,
    TokenCount,
    ToolCall,
    Usage,
    estimate_tokens,
)
from admintwin_ai.providers.tool_format import (
    clean_schema,
    name_mapping,
    parse_openai_arguments,
    to_native_name,
    to_openai_tools,
)

_FINISH: dict[str, FinishReason] = {
    "stop": "stop",
    "tool_calls": "tool_calls",
    "function_call": "tool_calls",
    "length": "length",
    "content_filter": "refusal",
}

_ALLOWED_PARAMS = ("reasoning_effort",)


class OpenAICompatibleProvider:
    """Базовый адаптер поверх ``openai.OpenAI().chat.completions``."""

    kind = "openai_compatible"
    is_external = True
    #: имя параметра лимита вывода: OpenAI — max_completion_tokens,
    #: локальные серверы стабильно понимают max_tokens
    max_tokens_param = "max_completion_tokens"

    def __init__(
        self,
        provider_id: str,
        *,
        mode: ConnectionMode,
        capabilities: ProviderCapabilities,
        client: Any,
    ) -> None:
        self._provider_id = provider_id
        self._mode = mode
        self._capabilities = capabilities
        self._client = client

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def mode(self) -> ConnectionMode:
        return self._mode

    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    # --- вызовы -----------------------------------------------------------

    def complete(self, request: CompletionRequest) -> CompletionResult:
        kwargs, mapping = self._build_kwargs(request)
        with self._translate_errors():
            resp = self._client.chat.completions.create(**kwargs)
        return self._parse(resp, mapping)

    def tool_call(self, request: CompletionRequest) -> CompletionResult:
        if not request.tools:
            raise ProviderRequestError("tool_call() requires at least one tool",
                                       provider=self._provider_id)
        return self.complete(request)

    def stream(self, request: CompletionRequest) -> Iterator[StreamEvent]:
        kwargs, mapping = self._build_kwargs(request)
        texts: list[str] = []
        pending: dict[int, dict[str, str]] = {}
        finish: FinishReason = "stop"
        usage = Usage()
        model = request.model
        with self._translate_errors():
            chunks = self._client.chat.completions.create(
                **kwargs, stream=True, stream_options={"include_usage": True}
            )
            for chunk in chunks:
                model = getattr(chunk, "model", None) or model
                if getattr(chunk, "usage", None):
                    usage = _usage(chunk.usage)
                for choice in chunk.choices or []:
                    delta = choice.delta
                    if getattr(delta, "content", None):
                        texts.append(delta.content)
                        yield StreamEvent(type="text_delta", text=delta.content)
                    for tc in getattr(delta, "tool_calls", None) or []:
                        slot = pending.setdefault(tc.index, {"id": "", "name": "", "args": ""})
                        if tc.id:
                            slot["id"] = tc.id
                        fn = getattr(tc, "function", None)
                        if fn is not None:
                            slot["name"] += fn.name or ""
                            slot["args"] += fn.arguments or ""
                    if choice.finish_reason:
                        finish = _FINISH.get(choice.finish_reason, "stop")
        calls = [
            parse_openai_arguments(s["id"], s["name"], s["args"], mapping)
            for _, s in sorted(pending.items())
        ]
        yield StreamEvent(type="final", result=CompletionResult(
            text="".join(texts), tool_calls=calls, finish_reason=finish, usage=usage,
            model=str(model), provider=self._provider_id,
        ))

    def embed(self, texts: Sequence[str], *, model: str) -> EmbeddingResult:
        with self._translate_errors():
            resp = self._client.embeddings.create(model=model, input=list(texts))
        vectors = [list(d.embedding) for d in resp.data]
        tokens = int(getattr(getattr(resp, "usage", None), "prompt_tokens", 0) or 0)
        return EmbeddingResult(vectors=vectors, model=str(getattr(resp, "model", model)),
                               usage=Usage(input_tokens=tokens))

    def count_tokens(self, request: CompletionRequest) -> TokenCount:
        return TokenCount(tokens=estimate_tokens(request), exact=False)

    def health(self, model: str | None = None) -> HealthStatus:
        started = time.monotonic()
        try:
            served = {m.id for m in self._client.models.list()}
        except Exception as exc:  # health() никогда не бросает
            return HealthStatus(ok=False, provider=self._provider_id, detail=type(exc).__name__,
                                latency_ms=(time.monotonic() - started) * 1000)
        latency = (time.monotonic() - started) * 1000
        if model and model not in served:
            # pinning модели (§18.6): endpoint не обслуживает ожидаемую модель
            return HealthStatus(ok=False, provider=self._provider_id,
                                detail=f"model '{model}' is not served", latency_ms=latency)
        return HealthStatus(ok=True, provider=self._provider_id, latency_ms=latency)

    # --- трансляция -------------------------------------------------------

    def _build_kwargs(self, request: CompletionRequest) -> tuple[dict[str, Any], dict[str, str]]:
        if not request.model:
            raise ProviderConfigError("model is not set: it must come from a Model Profile")
        unknown = set(request.params) - set(_ALLOWED_PARAMS)
        if unknown:
            raise ProviderConfigError(
                f"unsupported {self.kind} profile params: {sorted(unknown)}"
            )
        mapping = name_mapping(request.tools)
        kwargs: dict[str, Any] = {
            "model": request.model,
            "messages": to_openai_messages(request.system, request.messages),
            self.max_tokens_param: request.max_tokens,
        }
        if request.tools:
            kwargs["tools"] = to_openai_tools(request.tools)
        if request.response_schema is not None:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "response",
                    "schema": clean_schema(request.response_schema),
                    "strict": True,
                },
            }
        kwargs.update(request.params)
        return kwargs, mapping

    def _parse(self, resp: Any, mapping: dict[str, str]) -> CompletionResult:
        if not resp.choices:
            raise ProviderUnavailableError("empty choices in response", provider=self._provider_id)
        choice = resp.choices[0]
        msg = choice.message
        calls: list[ToolCall] = [
            parse_openai_arguments(tc.id, tc.function.name, tc.function.arguments, mapping)
            for tc in (getattr(msg, "tool_calls", None) or [])
        ]
        finish: FinishReason = _FINISH.get(choice.finish_reason or "", "stop")
        if getattr(msg, "refusal", None):
            finish = "refusal"
        return CompletionResult(
            text=msg.content or "",
            tool_calls=calls,
            finish_reason=finish,
            usage=_usage(getattr(resp, "usage", None)),
            model=str(getattr(resp, "model", "")),
            provider=self._provider_id,
            raw_stop_reason=choice.finish_reason,
        )

    @contextmanager
    def _translate_errors(self) -> Iterator[None]:
        pid = self._provider_id
        try:
            yield
        except ProviderError:
            raise
        except openai.RateLimitError as exc:
            raise ProviderRateLimitedError(str(exc), provider=pid,
                                           retry_after_s=_retry_after(exc)) from exc
        except openai.APIConnectionError as exc:  # включает APITimeoutError
            raise ProviderUnavailableError(str(exc), provider=pid) from exc
        except openai.APIStatusError as exc:
            if exc.status_code >= 500 or exc.status_code in (408, 409):
                raise ProviderUnavailableError(str(exc), provider=pid,
                                               status_code=exc.status_code) from exc
            raise ProviderRequestError(str(exc), provider=pid,
                                       status_code=exc.status_code) from exc


def to_openai_messages(system: str | None, messages: list[ChatMessage]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if system:
        out.append({"role": "system", "content": system})
    for m in messages:
        if m.role == "tool":
            out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
        elif m.role == "assistant":
            item: dict[str, Any] = {"role": "assistant", "content": m.content or None}
            if m.tool_calls:
                item["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": to_native_name(tc.name),
                            "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                        },
                    }
                    for tc in m.tool_calls
                ]
            out.append(item)
        else:
            out.append({"role": "user", "content": m.content})
    return out


def _usage(raw: Any) -> Usage:
    if raw is None:
        return Usage()
    return Usage(
        input_tokens=int(getattr(raw, "prompt_tokens", 0) or 0),
        output_tokens=int(getattr(raw, "completion_tokens", 0) or 0),
    )


def _retry_after(exc: openai.APIStatusError) -> float | None:
    try:
        value = exc.response.headers.get("retry-after")
        return float(value) if value is not None else None
    except (AttributeError, ValueError):
        return None
