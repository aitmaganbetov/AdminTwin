"""Read tools MVP (§3.3). Обработчики — тонкие заглушки поверх внедряемого
backend; реальные коннекторы (VictoriaMetrics, Loki, CMDB, SSH/Docker/
PostgreSQL/FortiGate read-only) подключаются реализацией ``ReadBackend``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol, runtime_checkable

from admintwin_ai.tools.invoker import ToolContext
from admintwin_ai.tools.registry import ToolBackendError, ToolHandler, ToolOutput

READ_TOOLS = (
    "metrics.query",
    "logs.search",
    "events.list",
    "topology.blast_radius",
    "asset.get",
    "docker.container.inspect",
    "linux.service.status",
    "linux.disk.usage",
    "postgres.activity",
    "fortigate.policy.status",
)


class ReadBackend(Protocol):
    def asset_exists(self, tenant_id: str, asset_id: str) -> bool: ...

    def fetch(self, tool: str, tenant_id: str, params: dict[str, Any]) -> ToolOutput: ...


@runtime_checkable
class AgentAwareReadBackend(ReadBackend, Protocol):
    """Backend, вызывающий источник от имени конкретного агента (HTTP к ядру)."""

    def fetch_as(self, tool: str, tenant_id: str, agent_id: str,
                 params: dict[str, Any]) -> ToolOutput: ...


Fixture = dict[str, Any] | ToolOutput | Callable[[dict[str, Any]], dict[str, Any] | ToolOutput]


class InMemoryReadBackend:
    """Backend на фикстурах: ``fixtures[tenant_id][tool] = dict | ToolOutput | callable``.

    Данные строго разделены по tenant: чужой tenant не видит ни активов, ни
    фикстур (T-TENANT-001 на уровне Tool Layer).
    """

    def __init__(self, fixtures: Mapping[str, Mapping[str, Fixture]] | None = None,
                 assets: Mapping[str, set[str]] | None = None) -> None:
        self._fixtures = {t: dict(v) for t, v in (fixtures or {}).items()}
        self._assets = {t: set(v) for t, v in (assets or {}).items()}

    def add_asset(self, tenant_id: str, asset_id: str) -> None:
        self._assets.setdefault(tenant_id, set()).add(asset_id)

    def set_fixture(self, tenant_id: str, tool: str, fixture: Fixture) -> None:
        self._fixtures.setdefault(tenant_id, {})[tool] = fixture

    def asset_exists(self, tenant_id: str, asset_id: str) -> bool:
        return asset_id in self._assets.get(tenant_id, set())

    def fetch(self, tool: str, tenant_id: str, params: dict[str, Any]) -> ToolOutput:
        fixture = self._fixtures.get(tenant_id, {}).get(tool)
        if fixture is None:
            raise ToolBackendError(f"no data source configured for '{tool}'")
        value = fixture(params) if callable(fixture) else fixture
        return value if isinstance(value, ToolOutput) else ToolOutput(data=dict(value))


def read_handlers(backend: ReadBackend) -> dict[str, ToolHandler]:
    def make(tool: str) -> ToolHandler:
        def handler(ctx: ToolContext, params: dict[str, Any]) -> ToolOutput:
            # tenant берётся только из контекста вызова, никогда из параметров модели
            if isinstance(backend, AgentAwareReadBackend):
                return backend.fetch_as(tool, ctx.tenant_id, ctx.agent.id, params)
            return backend.fetch(tool, ctx.tenant_id, params)
        return handler

    return {tool: make(tool) for tool in READ_TOOLS}
