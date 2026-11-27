from __future__ import annotations

import pytest

from admintwin_ai.agents import AgentDefinition, load_agents
from admintwin_ai.audit import InMemoryAuditSink
from admintwin_ai.tools import (
    ChangeProposeHandler,
    InMemoryReadBackend,
    ToolInvoker,
    ToolRegistry,
    build_tool_registry,
)

from support import (
    ASSET_B_ONLY,
    ASSET_DB,
    ASSET_WEB,
    CORE_URL,
    TENANT_A,
    TENANT_B,
    CoreRecorder,
    default_fixtures,
)


@pytest.fixture
def audit() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def agents() -> dict[str, AgentDefinition]:
    return {a.id: a for a in load_agents()}


@pytest.fixture
def backend() -> InMemoryReadBackend:
    return InMemoryReadBackend(
        fixtures={TENANT_A: default_fixtures(), TENANT_B: default_fixtures()},
        assets={TENANT_A: {ASSET_WEB, ASSET_DB}, TENANT_B: {ASSET_B_ONLY}},
    )


@pytest.fixture
def core() -> CoreRecorder:
    return CoreRecorder()


@pytest.fixture
def tool_registry(backend: InMemoryReadBackend, core: CoreRecorder) -> ToolRegistry:
    return build_tool_registry(backend, ChangeProposeHandler(CORE_URL, client=core.client()))


@pytest.fixture
def invoker(tool_registry: ToolRegistry, audit: InMemoryAuditSink,
            backend: InMemoryReadBackend) -> ToolInvoker:
    return ToolInvoker(tool_registry, audit, assets=backend)
