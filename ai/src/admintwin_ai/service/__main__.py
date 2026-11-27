"""Точка входа: ``python -m admintwin_ai.service`` / ``admintwin-orchestrator``."""

from __future__ import annotations

import logging
import sys

import uvicorn

from admintwin_ai.service.app import create_app
from admintwin_ai.service.runtime import build_runtime
from admintwin_ai.service.settings import ConfigurationError, ServiceSettings


def main() -> int:
    try:
        settings = ServiceSettings.from_env()
    except ConfigurationError as exc:
        print(f"admintwin-orchestrator: configuration error: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(level=settings.log_level.upper(),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if not settings.auth_enabled:
        logging.getLogger("admintwin").warning(
            "ADMINTWIN_DEV_INSECURE=true: service token check is DISABLED (development only)")
    try:
        runtime = build_runtime(settings)
    except ConfigurationError as exc:
        print(f"admintwin-orchestrator: configuration error: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(create_app(runtime), host=settings.host, port=settings.port,
                log_level=settings.log_level.lower(), proxy_headers=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
