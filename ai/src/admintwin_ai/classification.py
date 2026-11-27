"""Общие типы AI-слоя: классы данных и классы задач (§6.4 ТЗ)."""

from __future__ import annotations

from enum import StrEnum


class DataClass(StrEnum):
    """Класс данных. ``UNKNOWN`` — классификация не определена (fail closed)."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    SECRET = "secret"  # noqa: S105 - класс данных, не пароль
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Порядок чувствительности; UNKNOWN считается самым строгим."""
        return _DATA_CLASS_RANK[self]

    @property
    def is_perimeter_bound(self) -> bool:
        """Данные не могут покидать периметр в немаскированном виде (§6.4 п.1)."""
        return self in (DataClass.PII, DataClass.SECRET, DataClass.UNKNOWN)

    def exceeds(self, other: DataClass) -> bool:
        return self.rank > other.rank

    @staticmethod
    def max_of(*classes: DataClass) -> DataClass:
        if not classes:
            return DataClass.UNKNOWN
        return max(classes, key=lambda c: c.rank)


_DATA_CLASS_RANK: dict[DataClass, int] = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.PII: 3,
    DataClass.SECRET: 4,
    DataClass.UNKNOWN: 5,
}


class TaskClass(StrEnum):
    """Класс задачи для маршрутизации (§6.4 п.2)."""

    CLASSIFY = "classify"
    SUMMARIZE = "summarize"
    EXTRACT = "extract"
    PLAN = "plan"
    RCA = "rca"
    MULTI_STEP = "multi_step"
    CODE_ANALYSIS = "code_analysis"
    EMBED = "embed"

    @property
    def prefers_local(self) -> bool:
        return self in (
            TaskClass.CLASSIFY,
            TaskClass.SUMMARIZE,
            TaskClass.EXTRACT,
            TaskClass.EMBED,
        )
