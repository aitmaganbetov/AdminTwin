"""AI Provider Layer (M21): единый интерфейс LLMProvider и адаптеры."""

from admintwin_ai.providers.base import (
    Capability,
    ChatMessage,
    CompletionRequest,
    CompletionResult,
    ConnectionMode,
    EmbeddingResult,
    HealthStatus,
    LLMProvider,
    ProviderCapabilities,
    StreamEvent,
    TokenCount,
    ToolCall,
    ToolSpec,
    Usage,
)

__all__ = [
    "Capability",
    "ChatMessage",
    "CompletionRequest",
    "CompletionResult",
    "ConnectionMode",
    "EmbeddingResult",
    "HealthStatus",
    "LLMProvider",
    "ProviderCapabilities",
    "StreamEvent",
    "TokenCount",
    "ToolCall",
    "ToolSpec",
    "Usage",
]
