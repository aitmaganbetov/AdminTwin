"""Tool Layer (§3.3): read и propose инструменты с JSON Schema контрактами."""

from __future__ import annotations

from admintwin_ai.tools.invoker import AssetDirectory, ToolContext, ToolInvoker, ToolResult
from admintwin_ai.tools.propose import ChangeProposeHandler
from admintwin_ai.tools.read import READ_TOOLS, InMemoryReadBackend, ReadBackend, read_handlers
from admintwin_ai.tools.registry import (
    ToolBackendError,
    ToolContract,
    ToolDefinition,
    ToolHandler,
    ToolKind,
    ToolOutput,
    ToolRefusal,
    ToolRegistry,
    load_contracts,
    register_all,
)
from admintwin_ai.tools.wrapping import parse_wrapped, wrap_untrusted


def build_tool_registry(backend: ReadBackend, propose: ChangeProposeHandler) -> ToolRegistry:
    """Реестр MVP: 10 read tools + ``change.propose``."""
    handlers: dict[str, ToolHandler] = {**read_handlers(backend), "change.propose": propose}
    return register_all(ToolRegistry(), handlers)


__all__ = [
    "READ_TOOLS",
    "AssetDirectory",
    "ChangeProposeHandler",
    "InMemoryReadBackend",
    "ReadBackend",
    "ToolBackendError",
    "ToolContext",
    "ToolContract",
    "ToolDefinition",
    "ToolInvoker",
    "ToolKind",
    "ToolOutput",
    "ToolRefusal",
    "ToolRegistry",
    "ToolResult",
    "build_tool_registry",
    "load_contracts",
    "parse_wrapped",
    "read_handlers",
    "register_all",
    "wrap_untrusted",
]
