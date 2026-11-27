"""Адаптеры Claude / OpenAI / Local на фейках SDK-клиентов (без сети)."""

from __future__ import annotations

import json

import anthropic
import httpx
import openai
import pytest
from fakes import FakeAnthropicClient, FakeOpenAIClient, anthropic_message, openai_completion

from admintwin_ai.errors import (
    CapabilityNotSupportedError,
    ProviderConfigError,
    ProviderRateLimitedError,
    ProviderRequestError,
    ProviderUnavailableError,
)
from admintwin_ai.providers import (
    Capability,
    ChatMessage,
    CompletionRequest,
    ConnectionMode,
    LLMProvider,
    ProviderCapabilities,
    ToolCall,
    ToolSpec,
)
from admintwin_ai.providers.claude import CLAUDE_MODE_CAPABILITIES, ClaudeProvider
from admintwin_ai.providers.local import LocalProvider
from admintwin_ai.providers.openai import OPENAI_MODE_CAPABILITIES, OpenAIProvider
from admintwin_ai.providers.tool_format import from_native_name, to_native_name

METRICS_TOOL = ToolSpec(
    name="metrics.query",
    description="query metrics",
    input_schema={"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                  "properties": {"asset_id": {"type": "string"}}, "required": ["asset_id"],
                  "additionalProperties": False},
)
LOCAL_CAPS = ProviderCapabilities(tool_calling=True, structured_output=False, streaming=True,
                                  embeddings=True, max_context=32768)


def _req(**kw: object) -> CompletionRequest:
    base: dict[str, object] = {"model": "model-from-profile", "system": "sys",
                               "messages": [ChatMessage(role="user", content="hi")]}
    base.update(kw)
    return CompletionRequest.model_validate(base)


def _http_response(status: int, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers or {},
                          request=httpx.Request("POST", "https://api.test/v1"))


# --- общие свойства ------------------------------------------------------------


def test_all_adapters_satisfy_protocol() -> None:
    providers = [
        ClaudeProvider("c", client=FakeAnthropicClient()),
        OpenAIProvider("o", client=FakeOpenAIClient()),
        LocalProvider("l", base_url="http://llm:8000/v1", allowed_endpoints=["http://llm:8000/v1"],
                      declared_capabilities=LOCAL_CAPS, client=FakeOpenAIClient()),
    ]
    for p in providers:
        assert isinstance(p, LLMProvider)
    assert [p.is_external for p in providers] == [True, True, False]


def test_capabilities_are_declared_per_provider_and_mode() -> None:
    claude = CLAUDE_MODE_CAPABILITIES[ConnectionMode.API_KEY]
    assert Capability.TOOL_CALLING in claude.supported()
    assert Capability.EMBEDDINGS not in claude.supported()
    # подписочные режимы не взаимозаменяемы с API-ключом
    assert CLAUDE_MODE_CAPABILITIES[ConnectionMode.SUBSCRIPTION].tool_calling is False
    assert OPENAI_MODE_CAPABILITIES[ConnectionMode.API_KEY].embeddings is True
    assert OPENAI_MODE_CAPABILITIES[ConnectionMode.SUBSCRIPTION].tool_calling is False


def test_subscription_modes_are_gated() -> None:
    with pytest.raises(ProviderConfigError, match="ADR-007"):
        ClaudeProvider("c", mode=ConnectionMode.SUBSCRIPTION, client=FakeAnthropicClient())
    with pytest.raises(ProviderConfigError, match="ADR-007"):
        OpenAIProvider("o", mode=ConnectionMode.SUBSCRIPTION, client=FakeOpenAIClient())


def test_tool_name_translation_roundtrip() -> None:
    assert to_native_name("docker.container.inspect") == "docker__container__inspect"
    mapping = {"docker__container__inspect": "docker.container.inspect"}
    assert from_native_name("docker__container__inspect", mapping) == "docker.container.inspect"
    # неизвестное имя всё равно декодируется: решение принимает Tool Layer
    assert from_native_name("shell__exec", {}) == "shell.exec"
    with pytest.raises(ProviderRequestError):
        to_native_name("bad name with spaces")


def test_model_must_come_from_profile() -> None:
    p = ClaudeProvider("c", client=FakeAnthropicClient())
    with pytest.raises(ProviderConfigError, match="Model Profile"):
        p.complete(_req(model=""))


# --- Claude ----------------------------------------------------------------------


def test_claude_translates_unified_request() -> None:
    client = FakeAnthropicClient([anthropic_message(
        tool_uses=[("tu_1", "metrics__query", {"asset_id": "a1"})], stop_reason="tool_use")])
    p = ClaudeProvider("claude-api", client=client)
    req = _req(
        tools=[METRICS_TOOL], params={"effort": "high"},
        response_schema={"type": "object", "properties": {}, "additionalProperties": False},
        messages=[
            ChatMessage(role="user", content="check"),
            ChatMessage(role="assistant", content="", tool_calls=[
                ToolCall(id="t0", name="asset.get", arguments={"asset_id": "a1"})]),
            ChatMessage(role="tool", tool_call_id="t0", content="data1"),
            ChatMessage(role="tool", tool_call_id="t9", content="err", is_error=True),
        ])
    result = p.tool_call(req)

    name, kwargs = client.calls[0]
    assert name == "messages.create"
    assert kwargs["model"] == "model-from-profile"
    assert kwargs["system"] == "sys"
    assert kwargs["tools"][0]["name"] == "metrics__query"
    assert "$schema" not in kwargs["tools"][0]["input_schema"]
    assert kwargs["output_config"]["effort"] == "high"
    assert kwargs["output_config"]["format"]["type"] == "json_schema"
    for forbidden in ("temperature", "top_p", "top_k", "tool_choice"):
        assert forbidden not in kwargs
    msgs = kwargs["messages"]
    assert msgs[1]["content"][0] == {"type": "tool_use", "id": "t0", "name": "asset__get",
                                     "input": {"asset_id": "a1"}}
    # результаты инструментов одного хода — в одном user-сообщении
    assert len(msgs) == 3
    assert [b["tool_use_id"] for b in msgs[2]["content"]] == ["t0", "t9"]
    assert msgs[2]["content"][1]["is_error"] is True

    assert result.finish_reason == "tool_calls"
    assert result.tool_calls[0].name == "metrics.query"
    assert result.tool_calls[0].arguments == {"asset_id": "a1"}
    assert result.usage.input_tokens == 10 and result.usage.output_tokens == 5
    assert result.model == "claude-test-model"


def test_claude_refusal_and_server_side_fallback() -> None:
    client = FakeAnthropicClient([anthropic_message(text="", stop_reason="refusal",
                                                    model="fallback-model")])
    p = ClaudeProvider("claude-api", client=client, server_side_fallback=True)
    result = p.complete(_req())
    name, kwargs = client.calls[0]
    assert name == "beta.messages.create"
    assert kwargs["betas"] == ["server-side-fallback-2026-07-01"]
    assert kwargs["fallbacks"] == "default"
    assert result.finish_reason == "refusal"
    assert result.model == "fallback-model"  # фактическая модель — в аудит


def test_claude_unknown_params_rejected() -> None:
    p = ClaudeProvider("c", client=FakeAnthropicClient())
    with pytest.raises(ProviderConfigError, match="temperature"):
        p.complete(_req(params={"temperature": 0.2}))


def test_claude_stream_count_tokens_health_embed() -> None:
    client = FakeAnthropicClient([anthropic_message(text="Hello")])
    p = ClaudeProvider("c", client=client)
    events = list(p.stream(_req()))
    assert [e.type for e in events] == ["text_delta", "text_delta", "final"]
    assert events[-1].result is not None and events[-1].result.text == "Hello"
    count = p.count_tokens(_req(max_tokens=100))
    assert count.tokens == 123 and count.exact
    assert "max_tokens" not in client.calls[-1][1]
    assert p.health("model-x").ok
    with pytest.raises(CapabilityNotSupportedError):
        p.embed(["x"], model="m")


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (anthropic.RateLimitError("rl", response=_http_response(429, {"retry-after": "7"}),
                                  body=None), ProviderRateLimitedError),
        (anthropic.InternalServerError("boom", response=_http_response(500), body=None),
         ProviderUnavailableError),
        (anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.test")),
         ProviderUnavailableError),
        (anthropic.BadRequestError("bad", response=_http_response(400), body=None),
         ProviderRequestError),
    ],
)
def test_claude_error_translation(exc: Exception, expected: type[Exception]) -> None:
    p = ClaudeProvider("c", client=FakeAnthropicClient([exc]))
    with pytest.raises(expected) as info:
        p.complete(_req())
    if isinstance(info.value, ProviderRateLimitedError):
        assert info.value.retry_after_s == 7.0


# --- OpenAI / Local --------------------------------------------------------------------


def test_openai_translates_unified_request() -> None:
    client = FakeOpenAIClient([openai_completion(
        text=None, tool_calls=[("call_1", "metrics__query", json.dumps({"asset_id": "a1"}))],
        finish_reason="tool_calls")])
    p = OpenAIProvider("openai-api", client=client)
    result = p.tool_call(_req(
        tools=[METRICS_TOOL], params={"reasoning_effort": "medium"},
        response_schema={"type": "object", "properties": {}, "additionalProperties": False},
        messages=[
            ChatMessage(role="user", content="check"),
            ChatMessage(role="assistant", tool_calls=[
                ToolCall(id="t0", name="asset.get", arguments={"asset_id": "a1"})]),
            ChatMessage(role="tool", tool_call_id="t0", content="data"),
        ]))
    _, kwargs = client.calls[0]
    assert kwargs["messages"][0] == {"role": "system", "content": "sys"}
    assert kwargs["messages"][2]["tool_calls"][0]["function"]["name"] == "asset__get"
    assert json.loads(kwargs["messages"][2]["tool_calls"][0]["function"]["arguments"]) == {
        "asset_id": "a1"}
    assert kwargs["messages"][3] == {"role": "tool", "tool_call_id": "t0", "content": "data"}
    assert kwargs["tools"][0]["function"]["name"] == "metrics__query"
    assert kwargs["max_completion_tokens"] == 4096
    assert kwargs["response_format"]["type"] == "json_schema"
    assert kwargs["reasoning_effort"] == "medium"
    assert result.tool_calls[0].name == "metrics.query"
    assert result.tool_calls[0].arguments == {"asset_id": "a1"}
    assert result.finish_reason == "tool_calls"
    assert result.usage.total == 18


def test_openai_malformed_arguments_are_flagged() -> None:
    client = FakeOpenAIClient([openai_completion(
        tool_calls=[("c1", "metrics__query", "{not json")], finish_reason="tool_calls")])
    result = OpenAIProvider("o", client=client).complete(_req(tools=[METRICS_TOOL]))
    assert result.tool_calls[0].malformed is True


def test_openai_refusal_and_errors() -> None:
    client = FakeOpenAIClient([
        openai_completion(text="", refusal="cannot help"),
        openai.RateLimitError("rl", response=_http_response(429), body=None),
    ])
    p = OpenAIProvider("o", client=client)
    assert p.complete(_req()).finish_reason == "refusal"
    with pytest.raises(ProviderRateLimitedError):
        p.complete(_req())


def test_local_endpoint_pinning_and_max_tokens_param() -> None:
    with pytest.raises(ProviderConfigError, match="allowed_endpoints"):
        LocalProvider("l", base_url="http://evil:8000/v1", allowed_endpoints=["http://llm:8000/v1"],
                      declared_capabilities=LOCAL_CAPS, client=FakeOpenAIClient())
    client = FakeOpenAIClient(served_models=["qwen-local"])
    p = LocalProvider("l", base_url="http://llm:8000/v1/", allowed_endpoints=["http://llm:8000/v1"],
                      declared_capabilities=LOCAL_CAPS, client=client)
    p.complete(_req(model="qwen-local"))
    _, kwargs = client.calls[0]
    assert kwargs["max_tokens"] == 4096 and "max_completion_tokens" not in kwargs
    assert p.capabilities() == LOCAL_CAPS
    assert p.health("qwen-local").ok
    bad = p.health("substituted-model")
    assert not bad.ok and "not served" in bad.detail
    assert not p.count_tokens(_req()).exact


def test_local_stream_and_embeddings() -> None:
    from types import SimpleNamespace as NS

    chunks = [
        NS(model="m", usage=None, choices=[NS(delta=NS(content="Hel", tool_calls=None),
                                              finish_reason=None)]),
        NS(model="m", usage=None, choices=[NS(delta=NS(content=None, tool_calls=[
            NS(index=0, id="c1", function=NS(name="metrics__query", arguments='{"asset_'))]),
            finish_reason=None)]),
        NS(model="m", usage=None, choices=[NS(delta=NS(content=None, tool_calls=[
            NS(index=0, id=None, function=NS(name=None, arguments='id": "a1"}'))]),
            finish_reason="tool_calls")]),
        NS(model="m", usage=NS(prompt_tokens=4, completion_tokens=2), choices=[]),
    ]
    client = FakeOpenAIClient([iter(chunks)])
    p = LocalProvider("l", base_url="http://llm:8000/v1", allowed_endpoints=["http://llm:8000/v1"],
                      declared_capabilities=LOCAL_CAPS, client=client)
    events = list(p.stream(_req(tools=[METRICS_TOOL])))
    final = events[-1].result
    assert events[0].text == "Hel"
    assert final is not None
    assert final.tool_calls[0].name == "metrics.query"
    assert final.tool_calls[0].arguments == {"asset_id": "a1"}
    assert final.usage.total == 6
    emb = p.embed(["a", "b"], model="embed-m")
    assert len(emb.vectors) == 2 and emb.usage.input_tokens == 3
