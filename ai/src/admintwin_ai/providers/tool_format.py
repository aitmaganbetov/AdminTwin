"""Трансляция единого формата tool-calling (JSON Schema) в нативные форматы.

Канонические имена инструментов AdminTwin содержат точки (``metrics.query``),
а Anthropic и OpenAI допускают только ``[a-zA-Z0-9_-]{1,64}``. Точка
кодируется как ``__``; обратное отображение строится из списка инструментов
запроса. Имя, которого нет в запросе, всё равно декодируется — решение о
допуске принимает Tool Layer, а не адаптер.
"""

from __future__ import annotations

import json
import re
from typing import Any

from admintwin_ai.errors import ProviderRequestError
from admintwin_ai.providers.base import ToolCall, ToolSpec

_NATIVE_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_SCHEMA_META_KEYS = ("$schema", "$id", "title")


def to_native_name(name: str) -> str:
    native = name.replace(".", "__")
    if not _NATIVE_NAME.match(native):
        raise ProviderRequestError(f"tool name '{name}' cannot be expressed natively")
    return native


def from_native_name(native: str, mapping: dict[str, str]) -> str:
    return mapping.get(native, native.replace("__", "."))


def name_mapping(tools: list[ToolSpec]) -> dict[str, str]:
    return {to_native_name(t.name): t.name for t in tools}


def clean_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Убирает мета-ключи JSON Schema, которые провайдеры не принимают."""
    cleaned = {k: v for k, v in schema.items() if k not in _SCHEMA_META_KEYS}
    cleaned.setdefault("type", "object")
    return cleaned


def to_anthropic_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "name": to_native_name(t.name),
            "description": t.description,
            "input_schema": clean_schema(t.input_schema),
        }
        for t in tools
    ]


def to_openai_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": to_native_name(t.name),
                "description": t.description,
                "parameters": clean_schema(t.input_schema),
            },
        }
        for t in tools
    ]


def parse_openai_arguments(call_id: str, native_name: str, raw: str | None,
                           mapping: dict[str, str]) -> ToolCall:
    """OpenAI возвращает аргументы строкой JSON; невалидный JSON не исполняется."""
    name = from_native_name(native_name, mapping)
    try:
        args = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return ToolCall(id=call_id, name=name, arguments={}, malformed=True)
    if not isinstance(args, dict):
        return ToolCall(id=call_id, name=name, arguments={}, malformed=True)
    return ToolCall(id=call_id, name=name, arguments=args)
