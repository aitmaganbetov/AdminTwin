"""Фейки SDK-клиентов и провайдеров. Тесты не делают сетевых вызовов."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from types import SimpleNamespace
from typing import Any

from admintwin_ai.errors import ProviderError
from admintwin_ai.profiles import ModelProfile, Pricing, ProfileRegistry
from admintwin_ai.providers.base import (
    CompletionRequest,
    CompletionResult,
    ConnectionMode,
    EmbeddingResult,
    HealthStatus,
    ProviderCapabilities,
    StreamEvent,
    TokenCount,
    ToolCall,
    Usage,
)

FULL_CAPS = ProviderCapabilities(tool_calling=True, structured_output=True, streaming=True,
                                 embeddings=True, max_context=200_000)

# --- Anthropic SDK fake ---------------------------------------------------------


def anthropic_message(*, text: str = "", tool_uses: Sequence[tuple[str, str, Any]] = (),
                      stop_reason: str = "end_turn", model: str = "claude-test-model",
                      input_tokens: int = 10, output_tokens: int = 5) -> SimpleNamespace:
    content: list[Any] = []
    if text:
        content.append(SimpleNamespace(type="text", text=text))
    for tid, name, args in tool_uses:
        content.append(SimpleNamespace(type="tool_use", id=tid, name=name, input=args))
    return SimpleNamespace(
        content=content, stop_reason=stop_reason, model=model,
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens,
                              cache_creation_input_tokens=0, cache_read_input_tokens=0),
    )


class _FakeAnthropicStream:
    def __init__(self, chunks: list[str], final: Any) -> None:
        self.text_stream = iter(chunks)
        self._final = final

    def __enter__(self) -> _FakeAnthropicStream:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_final_message(self) -> Any:
        return self._final


class _FakeAnthropicMessages:
    def __init__(self, owner: FakeAnthropicClient) -> None:
        self._owner = owner

    def create(self, **kwargs: Any) -> Any:
        self._owner.calls.append(("messages.create", kwargs))
        return self._owner.next_response()

    def stream(self, **kwargs: Any) -> _FakeAnthropicStream:
        self._owner.calls.append(("messages.stream", kwargs))
        final = self._owner.next_response()
        return _FakeAnthropicStream(["Hel", "lo"], final)

    def count_tokens(self, **kwargs: Any) -> Any:
        self._owner.calls.append(("messages.count_tokens", kwargs))
        return SimpleNamespace(input_tokens=123)


class _FakeAnthropicBetaMessages(_FakeAnthropicMessages):
    def create(self, **kwargs: Any) -> Any:
        self._owner.calls.append(("beta.messages.create", kwargs))
        return self._owner.next_response()


class FakeAnthropicClient:
    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.messages = _FakeAnthropicMessages(self)
        self.beta = SimpleNamespace(messages=_FakeAnthropicBetaMessages(self))
        self.models = SimpleNamespace(
            retrieve=lambda model_id: SimpleNamespace(id=model_id),
            list=lambda **kw: [SimpleNamespace(id="m")],
        )

    def next_response(self) -> Any:
        item = self.responses.pop(0) if self.responses else anthropic_message(text="ok")
        if isinstance(item, Exception):
            raise item
        return item


# --- OpenAI SDK fake --------------------------------------------------------------


def openai_completion(*, text: str | None = "", tool_calls: Sequence[tuple[str, str, str]] = (),
                      finish_reason: str = "stop", model: str = "gpt-test",
                      prompt_tokens: int = 11, completion_tokens: int = 7,
                      refusal: str | None = None) -> SimpleNamespace:
    calls = [SimpleNamespace(id=cid, type="function",
                             function=SimpleNamespace(name=name, arguments=args))
             for cid, name, args in tool_calls]
    msg = SimpleNamespace(content=text, tool_calls=calls or None, refusal=refusal)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=msg, finish_reason=finish_reason)], model=model,
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


class FakeOpenAIClient:
    def __init__(self, responses: list[Any] | None = None,
                 served_models: Sequence[str] = ("gpt-test",)) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[str, dict[str, Any]]] = []
        outer = self

        class _Completions:
            def create(self, **kwargs: Any) -> Any:
                outer.calls.append(("chat.completions.create", kwargs))
                item = outer.responses.pop(0) if outer.responses else openai_completion(text="ok")
                if isinstance(item, Exception):
                    raise item
                return item

        class _Embeddings:
            def create(self, **kwargs: Any) -> Any:
                outer.calls.append(("embeddings.create", kwargs))
                return SimpleNamespace(
                    data=[SimpleNamespace(embedding=[0.1, 0.2]) for _ in kwargs["input"]],
                    model=kwargs["model"], usage=SimpleNamespace(prompt_tokens=3))

        self.chat = SimpleNamespace(completions=_Completions())
        self.embeddings = _Embeddings()
        self.models = SimpleNamespace(list=lambda: [SimpleNamespace(id=m) for m in served_models])


# --- Fake LLMProvider ---------------------------------------------------------------

Responder = Callable[[CompletionRequest], CompletionResult]


class FakeProvider:
    """Провайдер-фейк: записывает каждый полученный запрос (маркерные тесты)."""

    def __init__(self, provider_id: str, *, external: bool, kind: str = "fake",
                 mode: ConnectionMode = ConnectionMode.API_KEY,
                 caps: ProviderCapabilities = FULL_CAPS,
                 responder: Responder | None = None,
                 errors: list[ProviderError] | None = None) -> None:
        self._provider_id = provider_id
        self.is_external = external
        self.kind = kind
        self._mode = mode
        self._caps = caps
        self.responder = responder or (lambda req: CompletionResult(
            text=f"answer from {provider_id}", usage=Usage(input_tokens=100, output_tokens=50),
            model=req.model, provider=provider_id))
        self.errors = list(errors or [])
        self.requests: list[CompletionRequest] = []
        self.embedded: list[list[str]] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def mode(self) -> ConnectionMode:
        return self._mode

    def capabilities(self) -> ProviderCapabilities:
        return self._caps

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        if self.errors:
            raise self.errors.pop(0)
        return self.responder(request)

    def tool_call(self, request: CompletionRequest) -> CompletionResult:
        return self.complete(request)

    def stream(self, request: CompletionRequest) -> Iterator[StreamEvent]:
        yield StreamEvent(type="final", result=self.complete(request))

    def embed(self, texts: Sequence[str], *, model: str) -> EmbeddingResult:
        self.embedded.append(list(texts))
        return EmbeddingResult(vectors=[[0.0] for _ in texts], model=model,
                               usage=Usage(input_tokens=len(texts)))

    def count_tokens(self, request: CompletionRequest) -> TokenCount:
        return TokenCount(tokens=1, exact=False)

    def health(self, model: str | None = None) -> HealthStatus:
        return HealthStatus(ok=True, provider=self._provider_id)

    def all_text(self) -> str:
        """Всё, что провайдер когда-либо получил (для поиска утечек)."""
        parts: list[str] = []
        for r in self.requests:
            parts.append(r.system or "")
            for m in r.messages:
                parts.append(m.content)
                parts.extend(str(tc.arguments) for tc in m.tool_calls)
        for batch in self.embedded:
            parts.extend(batch)
        return "\n".join(parts)


def tool_call_result(*calls: ToolCall, text: str = "") -> CompletionResult:
    return CompletionResult(text=text, tool_calls=list(calls), finish_reason="tool_calls",
                            usage=Usage(input_tokens=10, output_tokens=10))


def make_registry(*, claude: FakeProvider | None = None, openai: FakeProvider | None = None,
                  local: FakeProvider | None = None) -> ProfileRegistry:
    providers = {
        "claude": claude or FakeProvider("claude", external=True, kind="claude"),
        "openai": openai or FakeProvider("openai", external=True, kind="openai"),
        "local": local or FakeProvider("local", external=False, kind="local"),
    }
    profiles = [
        ModelProfile(id="claude-primary", provider="claude", model="claude-model-from-config",
                     pricing=Pricing(input_per_mtok=4.0, output_per_mtok=20.0),
                     downgrade_to="claude-economy"),
        ModelProfile(id="claude-economy", provider="claude", model="claude-economy-model",
                     pricing=Pricing(input_per_mtok=2.0, output_per_mtok=10.0),
                     downgrade_to="local-default"),
        ModelProfile(id="openai-secondary", provider="openai", model="openai-model-from-config",
                     downgrade_to="local-default"),
        ModelProfile(id="local-default", provider="local", model="local-model",
                     embedding_model="local-embed"),
    ]
    return ProfileRegistry(profiles, providers)
