"""Адаптер локальной LLM через OpenAI-совместимый endpoint (§6.9).

vLLM, Ollama, llama.cpp server, LM Studio, TGI. Возможности зависят от
модели и сервера, поэтому объявляются в конфигурации (``declared_capabilities``)
и подтверждаются скриптом проверки совместимости (tool-calling, контекст
≥ 32k, structured output) до включения профиля.

Защита от подмены endpoint (§18.6): ``base_url`` обязан входить в
``allowed_endpoints`` (egress allowlist), а ``health(model)`` проверяет, что
endpoint действительно обслуживает закреплённую модель.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import openai

from admintwin_ai.errors import ProviderConfigError
from admintwin_ai.providers.base import ConnectionMode, ProviderCapabilities
from admintwin_ai.providers.openai_compat import OpenAICompatibleProvider

#: Минимум для RCA на локальной модели (§6.9).
MIN_RCA_CONTEXT = 32_768

_NO_KEY = "local-endpoint-no-key"


def _normalize(url: str) -> str:
    return url.rstrip("/")


class LocalProvider(OpenAICompatibleProvider):
    kind = "local"
    is_external = False
    max_tokens_param = "max_tokens"

    def __init__(
        self,
        provider_id: str,
        *,
        base_url: str,
        allowed_endpoints: Sequence[str],
        declared_capabilities: ProviderCapabilities,
        api_key: str | None = None,
        timeout_s: float = 300.0,
        max_retries: int = 1,
        client: Any | None = None,
    ) -> None:
        allowed = {_normalize(u) for u in allowed_endpoints}
        if _normalize(base_url) not in allowed:
            raise ProviderConfigError(
                f"local endpoint '{base_url}' is not in allowed_endpoints (egress allowlist)"
            )
        if client is None:
            client = openai.OpenAI(
                api_key=api_key or _NO_KEY,
                base_url=base_url,
                timeout=timeout_s,
                max_retries=max_retries,
            )
        self.base_url = _normalize(base_url)
        super().__init__(provider_id, mode=ConnectionMode.OPENAI_COMPATIBLE,
                         capabilities=declared_capabilities, client=client)
