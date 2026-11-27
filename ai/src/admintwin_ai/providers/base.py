"""Интерфейс ``LLMProvider`` и единый формат запросов/ответов (§6.3 ТЗ).

Все адаптеры (Claude, OpenAI, Local) принимают и возвращают одни и те же
типы. Формат tool-calling — JSON Schema (``ToolSpec``); каждый адаптер
транслирует его в нативный формат провайдера и обратно.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class Capability(StrEnum):
    """Возможности провайдера×режима, которые проверяются при выборе профиля."""

    TOOL_CALLING = "tool_calling"
    STRUCTURED_OUTPUT = "structured_output"
    STREAMING = "streaming"
    EMBEDDINGS = "embeddings"


class ConnectionMode(StrEnum):
    """Режим подключения (§6.2). Режимы не взаимозаменяемы автоматически."""

    API_KEY = "api_key"
    SUBSCRIPTION = "subscription"  # Claude Agent SDK / Codex CLI; release gate ADR-007
    OPENAI_COMPATIBLE = "openai_compatible"  # локальный endpoint (vLLM/Ollama/llama.cpp)


class ProviderCapabilities(BaseModel):
    """``supported_capabilities`` провайдера×режима."""

    model_config = ConfigDict(frozen=True)

    tool_calling: bool = False
    structured_output: bool = False
    streaming: bool = False
    embeddings: bool = False
    max_context: int = Field(default=0, ge=0)

    def supported(self) -> frozenset[Capability]:
        return frozenset(c for c in Capability if getattr(self, c.value))

    def intersect(self, other: ProviderCapabilities) -> ProviderCapabilities:
        """Эффективные возможности — пересечение (профиль не может заявить больше режима)."""
        # 0 означает «не объявлено»: берём объявленное значение другой стороны.
        if self.max_context and other.max_context:
            ctx = min(self.max_context, other.max_context)
        else:
            ctx = self.max_context or other.max_context
        return ProviderCapabilities(
            tool_calling=self.tool_calling and other.tool_calling,
            structured_output=self.structured_output and other.structured_output,
            streaming=self.streaming and other.streaming,
            embeddings=self.embeddings and other.embeddings,
            max_context=ctx,
        )


# --- Сообщения и инструменты -----------------------------------------------


class ToolSpec(BaseModel):
    """Единое описание инструмента для LLM (JSON Schema параметров)."""

    model_config = ConfigDict(frozen=True)

    name: str  # каноническое имя AdminTwin, например "metrics.query"
    description: str
    input_schema: dict[str, Any]


class ToolCall(BaseModel):
    """Вызов инструмента, запрошенный моделью (каноническое имя)."""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    # True, если аргументы пришли невалидным JSON — Tool Layer отклонит вызов.
    malformed: bool = False


Role = Literal["user", "assistant", "tool"]


class ChatMessage(BaseModel):
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)  # для role=assistant
    tool_call_id: str | None = None  # для role=tool
    is_error: bool = False  # для role=tool


class CompletionRequest(BaseModel):
    """Запрос к провайдеру. ``model`` подставляется из Model Profile."""

    model: str = ""
    system: str | None = None
    messages: list[ChatMessage]
    tools: list[ToolSpec] = Field(default_factory=list)
    max_tokens: int = Field(default=4096, gt=0)
    # JSON Schema ожидаемого ответа (structured output); None — свободный текст
    response_schema: dict[str, Any] | None = None
    # Параметры профиля (например {"effort": "high"} для Claude)
    params: dict[str, Any] = Field(default_factory=dict)
    prompt_version: str = "unversioned"


FinishReason = Literal["stop", "tool_calls", "length", "refusal", "error"]


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


class CompletionResult(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    finish_reason: FinishReason = "stop"
    usage: Usage = Field(default_factory=Usage)
    # Модель, фактически обслужившая запрос (может отличаться при server-side fallback)
    model: str = ""
    provider: str = ""
    raw_stop_reason: str | None = None


class StreamEvent(BaseModel):
    type: Literal["text_delta", "final"]
    text: str = ""
    result: CompletionResult | None = None


class EmbeddingResult(BaseModel):
    vectors: list[list[float]]
    model: str
    usage: Usage = Field(default_factory=Usage)


class TokenCount(BaseModel):
    tokens: int
    exact: bool  # False — оценка (у OpenAI-совместимых endpoint нет count API)


class HealthStatus(BaseModel):
    ok: bool
    provider: str
    detail: str = ""
    latency_ms: float = 0.0


@runtime_checkable
class LLMProvider(Protocol):
    """Интерфейс адаптера провайдера (§6.3)."""

    @property
    def provider_id(self) -> str: ...

    @property
    def kind(self) -> str: ...

    @property
    def mode(self) -> ConnectionMode: ...

    @property
    def is_external(self) -> bool: ...

    def capabilities(self) -> ProviderCapabilities: ...

    def complete(self, request: CompletionRequest) -> CompletionResult: ...

    def stream(self, request: CompletionRequest) -> Iterator[StreamEvent]: ...

    def tool_call(self, request: CompletionRequest) -> CompletionResult: ...

    def embed(self, texts: Sequence[str], *, model: str) -> EmbeddingResult: ...

    def count_tokens(self, request: CompletionRequest) -> TokenCount: ...

    def health(self, model: str | None = None) -> HealthStatus: ...


def estimate_tokens(request: CompletionRequest) -> int:
    """Грубая оценка (≈4 символа на токен) для провайдеров без count API."""
    chars = len(request.system or "")
    for m in request.messages:
        chars += len(m.content)
        for tc in m.tool_calls:
            chars += len(tc.name) + len(str(tc.arguments))
    for t in request.tools:
        chars += len(t.name) + len(t.description) + len(str(t.input_schema))
    return max(1, chars // 4)
