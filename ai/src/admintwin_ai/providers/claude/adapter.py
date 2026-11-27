"""Адаптер Anthropic Claude (официальный SDK ``anthropic``).

Идентификаторы моделей берутся только из Model Profile (конфигурация);
адаптер не содержит значений по умолчанию для модели.

Особенности текущего API, учтённые в адаптере:

* sampling-параметры (``temperature``/``top_p``/``top_k``) не отправляются —
  API-версия 2026-10-21 (SDK ``anthropic`` 2.x) их отклоняет;
* глубина рассуждений задаётся ``output_config.effort`` (параметр профиля);
* forced ``tool_choice`` не используется (на актуальных моделях даёт 400) —
  только ``auto``;
* ``stop_reason == "refusal"`` транслируется в ``finish_reason="refusal"``;
* опционально — server-side fallback при отказе модели
  (``server_side_fallback: true`` в конфиге провайдера, beta
  ``server-side-fallback-2026-07-01``, ``fallbacks="default"``). Фактическая
  модель ответа попадает в аудит из ``response.model``.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

import anthropic

from admintwin_ai.errors import (
    CapabilityNotSupportedError,
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
)
from admintwin_ai.providers.tool_format import (
    clean_schema,
    from_native_name,
    name_mapping,
    to_anthropic_tools,
    to_native_name,
)

SERVER_SIDE_FALLBACK_BETA = "server-side-fallback-2026-07-01"

#: supported_capabilities по режимам. Подписочный канал (Claude Agent SDK)
#: не даёт единого tool-calling формата AdminTwin и закрыт release gate ADR-007.
CLAUDE_MODE_CAPABILITIES: dict[ConnectionMode, ProviderCapabilities] = {
    ConnectionMode.API_KEY: ProviderCapabilities(
        tool_calling=True,
        structured_output=True,
        streaming=True,
        embeddings=False,
        max_context=1_000_000,
    ),
    ConnectionMode.SUBSCRIPTION: ProviderCapabilities(
        tool_calling=False,
        structured_output=False,
        streaming=True,
        embeddings=False,
        max_context=200_000,
    ),
}

_ALLOWED_PARAMS = ("effort", "thinking")

_STOP_REASONS: dict[str, FinishReason] = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "pause_turn": "stop",
    "tool_use": "tool_calls",
    "max_tokens": "length",
    "refusal": "refusal",
}


class ClaudeProvider:
    """``LLMProvider`` поверх ``anthropic.Anthropic``."""

    kind = "claude"
    is_external = True

    def __init__(
        self,
        provider_id: str,
        *,
        mode: ConnectionMode = ConnectionMode.API_KEY,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_s: float = 120.0,
        max_retries: int = 2,
        server_side_fallback: bool = False,
        client: Any | None = None,
    ) -> None:
        if mode is not ConnectionMode.API_KEY:
            raise ProviderConfigError(
                f"Claude mode '{mode}' is not available in Stage 0: subscription channel "
                "is gated by ADR-007 (Enterprise only, customer's own account)"
            )
        self._provider_id = provider_id
        self._mode = mode
        self._server_side_fallback = server_side_fallback
        if client is None:
            client = anthropic.Anthropic(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout_s,
                max_retries=max_retries,
            )
        self._client = client

    # --- метаданные -----------------------------------------------------

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def mode(self) -> ConnectionMode:
        return self._mode

    def capabilities(self) -> ProviderCapabilities:
        return CLAUDE_MODE_CAPABILITIES[self._mode]

    # --- вызовы -----------------------------------------------------------

    def complete(self, request: CompletionRequest) -> CompletionResult:
        kwargs, mapping = self._build_kwargs(request)
        with self._translate_errors():
            response = self._create(kwargs)
        return self._parse(response, mapping)

    def tool_call(self, request: CompletionRequest) -> CompletionResult:
        if not request.tools:
            raise ProviderRequestError("tool_call() requires at least one tool",
                                       provider=self._provider_id)
        return self.complete(request)

    def stream(self, request: CompletionRequest) -> Iterator[StreamEvent]:
        kwargs, mapping = self._build_kwargs(request)
        with self._translate_errors():
            if self._server_side_fallback:
                manager = self._client.beta.messages.stream(
                    **kwargs, betas=[SERVER_SIDE_FALLBACK_BETA], fallbacks="default"
                )
            else:
                manager = self._client.messages.stream(**kwargs)
            with manager as stream:
                for text in stream.text_stream:
                    yield StreamEvent(type="text_delta", text=text)
                final = stream.get_final_message()
        yield StreamEvent(type="final", result=self._parse(final, mapping))

    def embed(self, texts: Sequence[str], *, model: str) -> EmbeddingResult:
        raise CapabilityNotSupportedError(
            "Anthropic API has no embeddings endpoint; route embeddings to Local",
            provider=self._provider_id,
        )

    def count_tokens(self, request: CompletionRequest) -> TokenCount:
        kwargs, _ = self._build_kwargs(request)
        kwargs.pop("max_tokens", None)
        with self._translate_errors():
            resp = self._client.messages.count_tokens(**kwargs)
        return TokenCount(tokens=int(resp.input_tokens), exact=True)

    def health(self, model: str | None = None) -> HealthStatus:
        started = time.monotonic()
        try:
            if model:
                self._client.models.retrieve(model)
            else:
                self._client.models.list(limit=1)
        except Exception as exc:  # health() никогда не бросает
            return HealthStatus(ok=False, provider=self._provider_id, detail=type(exc).__name__,
                                latency_ms=(time.monotonic() - started) * 1000)
        return HealthStatus(ok=True, provider=self._provider_id,
                            latency_ms=(time.monotonic() - started) * 1000)

    # --- трансляция -------------------------------------------------------

    def _create(self, kwargs: dict[str, Any]) -> Any:
        if self._server_side_fallback:
            return self._client.beta.messages.create(
                **kwargs, betas=[SERVER_SIDE_FALLBACK_BETA], fallbacks="default"
            )
        return self._client.messages.create(**kwargs)

    def _build_kwargs(self, request: CompletionRequest) -> tuple[dict[str, Any], dict[str, str]]:
        if not request.model:
            raise ProviderConfigError("model is not set: it must come from a Model Profile")
        mapping = name_mapping(request.tools)
        kwargs: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": to_anthropic_messages(request.messages),
        }
        if request.system:
            kwargs["system"] = request.system
        if request.tools:
            kwargs["tools"] = to_anthropic_tools(request.tools)
        output_config: dict[str, Any] = {}
        if request.params.get("effort"):
            output_config["effort"] = request.params["effort"]
        if request.response_schema is not None:
            output_config["format"] = {
                "type": "json_schema",
                "schema": clean_schema(request.response_schema),
            }
        if output_config:
            kwargs["output_config"] = output_config
        if request.params.get("thinking"):
            kwargs["thinking"] = request.params["thinking"]
        unknown = set(request.params) - set(_ALLOWED_PARAMS)
        if unknown:
            raise ProviderConfigError(f"unsupported Claude profile params: {sorted(unknown)}")
        return kwargs, mapping

    def _parse(self, response: Any, mapping: dict[str, str]) -> CompletionResult:
        texts: list[str] = []
        calls: list[ToolCall] = []
        for block in response.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                texts.append(block.text)
            elif btype == "tool_use":
                args = block.input if isinstance(block.input, dict) else {}
                calls.append(ToolCall(
                    id=block.id,
                    name=from_native_name(block.name, mapping),
                    arguments=args,
                    malformed=not isinstance(block.input, dict),
                ))
        stop = getattr(response, "stop_reason", None)
        finish: FinishReason = _STOP_REASONS.get(stop or "", "stop")
        usage = response.usage
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        input_tokens += int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        input_tokens += int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        return CompletionResult(
            text="".join(texts),
            tool_calls=calls,
            finish_reason=finish,
            usage=Usage(input_tokens=input_tokens,
                        output_tokens=int(getattr(usage, "output_tokens", 0) or 0)),
            model=str(getattr(response, "model", "")),
            provider=self._provider_id,
            raw_stop_reason=stop,
        )

    @contextmanager
    def _translate_errors(self) -> Iterator[None]:
        pid = self._provider_id
        try:
            yield
        except ProviderError:
            raise
        except anthropic.RateLimitError as exc:
            retry_after = _retry_after(exc)
            raise ProviderRateLimitedError(str(exc), provider=pid,
                                           retry_after_s=retry_after) from exc
        except anthropic.APIConnectionError as exc:  # включает APITimeoutError
            raise ProviderUnavailableError(str(exc), provider=pid) from exc
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500 or exc.status_code in (408, 409):
                raise ProviderUnavailableError(str(exc), provider=pid,
                                               status_code=exc.status_code) from exc
            raise ProviderRequestError(str(exc), provider=pid,
                                       status_code=exc.status_code) from exc


def to_anthropic_messages(messages: list[ChatMessage]) -> list[dict[str, Any]]:
    """Единый формат → Messages API. Результаты инструментов одного хода
    собираются в одно user-сообщение (так модель не теряет параллельные вызовы)."""
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "tool":
            block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": m.tool_call_id,
                "content": m.content,
            }
            if m.is_error:
                block["is_error"] = True
            last = out[-1] if out else None
            if (last is not None and last["role"] == "user" and isinstance(last["content"], list)
                    and all(b.get("type") == "tool_result" for b in last["content"])):
                last["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        elif m.role == "assistant":
            content: list[dict[str, Any]] = []
            if m.content:
                content.append({"type": "text", "text": m.content})
            for tc in m.tool_calls:
                content.append({
                    "type": "tool_use",
                    "id": tc.id,
                    "name": to_native_name(tc.name),
                    "input": tc.arguments,
                })
            out.append({"role": "assistant", "content": content})
        else:
            out.append({"role": "user", "content": m.content})
    return out


def _retry_after(exc: anthropic.APIStatusError) -> float | None:
    try:
        value = exc.response.headers.get("retry-after")
        return float(value) if value is not None else None
    except (AttributeError, ValueError):
        return None
