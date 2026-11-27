"""Поиск файлов-контрактов (JSON Schema, агенты, golden dataset).

Данные лежат в раскладке ТЗ (§22): ``ai/tools/{read,propose}``, ``ai/contracts``,
``ai/agents``, ``ai/evals``, ``ai/config``. В wheel они копируются в
``admintwin_ai/_data``; при editable-установке читаются напрямую из ``ai/``.
Переопределение — переменная окружения ``ADMINTWIN_AI_DATA_DIR``.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

_PACKAGE_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def data_root() -> Path:
    override = os.environ.get("ADMINTWIN_AI_DATA_DIR")
    if override:
        return Path(override)
    packaged = _PACKAGE_DIR / "_data"
    if packaged.is_dir():
        return packaged
    # src/admintwin_ai -> src -> ai
    return _PACKAGE_DIR.parent.parent


def data_path(*parts: str) -> Path:
    return data_root().joinpath(*parts)


def load_json(*parts: str) -> dict[str, Any]:
    with data_path(*parts).open(encoding="utf-8") as fh:
        return cast(dict[str, Any], json.load(fh))
