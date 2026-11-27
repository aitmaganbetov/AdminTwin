"""Адаптер OpenAI (официальный SDK ``openai``, Chat Completions)."""

from __future__ import annotations

from typing import Any

import openai

from admintwin_ai.errors import ProviderConfigError
from admintwin_ai.providers.base import ConnectionMode, ProviderCapabilities
from admintwin_ai.providers.openai_compat import OpenAICompatibleProvider

#: supported_capabilities по режимам. Подписка ChatGPT/Codex (Codex CLI/SDK)
#: не даёт единого tool-calling формата и закрыта release gate ADR-007.
#: max_context = 0: зависит от модели и задаётся в Model Profile.
OPENAI_MODE_CAPABILITIES: dict[ConnectionMode, ProviderCapabilities] = {
    ConnectionMode.API_KEY: ProviderCapabilities(
        tool_calling=True,
        structured_output=True,
        streaming=True,
        embeddings=True,
        max_context=0,
    ),
    ConnectionMode.SUBSCRIPTION: ProviderCapabilities(
        tool_calling=False,
        structured_output=False,
        streaming=True,
        embeddings=False,
        max_context=0,
    ),
}


class OpenAIProvider(OpenAICompatibleProvider):
    kind = "openai"
    is_external = True
    max_tokens_param = "max_completion_tokens"

    def __init__(
        self,
        provider_id: str,
        *,
        mode: ConnectionMode = ConnectionMode.API_KEY,
        api_key: str | None = None,
        base_url: str | None = None,
        organization: str | None = None,
        timeout_s: float = 120.0,
        max_retries: int = 2,
        client: Any | None = None,
    ) -> None:
        if mode is not ConnectionMode.API_KEY:
            raise ProviderConfigError(
                f"OpenAI mode '{mode}' is not available in Stage 0: subscription channel "
                "is gated by ADR-007 (Enterprise only, customer's own account)"
            )
        if client is None:
            client = openai.OpenAI(
                api_key=api_key,
                base_url=base_url,
                organization=organization,
                timeout=timeout_s,
                max_retries=max_retries,
            )
        super().__init__(provider_id, mode=mode,
                         capabilities=OPENAI_MODE_CAPABILITIES[mode], client=client)
