"""Память подтверждённых RCA-кейсов (§5.3): top-k похожих из того же tenant.

Хранилище в памяти процесса (MVP). Векторы — через ``AIGateway.embed``
(маршрутизация по классу данных, Local первым); если embeddings недоступны —
детерминированный fallback (feature hashing токенов), чтобы поиск работал
офлайн и без провайдера. Кейсы строго разделены по tenant (T-TENANT-001).
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from pydantic import BaseModel, Field

HASH_DIM = 256
_TOKEN = re.compile(r"[a-zа-яёәғқңөұүһі0-9_]{2,}", re.IGNORECASE)

Embedder = Callable[[Sequence[str]], list[list[float]] | None]


def hash_embedding(text: str, dim: int = HASH_DIM) -> list[float]:
    vec = [0.0] * dim
    for token in _TOKEN.findall(text.lower()):
        h = hashlib.sha256(token.encode("utf-8")).digest()
        idx = int.from_bytes(h[:4], "big") % dim
        vec[idx] += 1.0 if h[4] & 1 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class RcaCase(BaseModel):
    tenant_id: str
    incident_id: str
    cause: str
    summary: str
    confirmed: bool = False
    alert_type: str | None = None
    asset_type: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    vector: list[float] = Field(default_factory=list, exclude=True)
    vector_kind: str = "hash"

    @property
    def text(self) -> str:
        return " ".join(filter(None, [self.alert_type, self.asset_type, self.cause,
                                      self.summary]))


class SimilarCase(BaseModel):
    incident_id: str
    cause: str
    summary: str
    score: float


class CaseStore:
    def __init__(self, embedder: Embedder | None = None) -> None:
        self._embedder = embedder
        self._cases: dict[str, dict[str, RcaCase]] = {}
        self._lock = threading.Lock()

    def _embed(self, texts: Sequence[str]) -> tuple[list[list[float]], str]:
        if self._embedder is not None:
            try:
                vectors = self._embedder(texts)
            except Exception:
                vectors = None
            if vectors and len(vectors) == len(texts) and all(vectors):
                return vectors, "provider"
        return [hash_embedding(t) for t in texts], "hash"

    def upsert(self, case: RcaCase) -> RcaCase:
        vectors, kind = self._embed([case.text])
        stored = case.model_copy(update={"vector": vectors[0], "vector_kind": kind})
        with self._lock:
            self._cases.setdefault(case.tenant_id, {})[case.incident_id] = stored
        return stored

    def confirm(self, tenant_id: str, incident_id: str, *, correct: bool,
                actual_cause: str | None = None) -> RcaCase | None:
        with self._lock:
            case = self._cases.get(tenant_id, {}).get(incident_id)
        if case is None:
            return None
        update: dict[str, object] = {"confirmed": correct or bool(actual_cause)}
        if actual_cause:
            update["cause"] = actual_cause
        return self.upsert(case.model_copy(update=update))

    def get(self, tenant_id: str, incident_id: str) -> RcaCase | None:
        with self._lock:
            return self._cases.get(tenant_id, {}).get(incident_id)

    def similar(self, tenant_id: str, text: str, *, k: int = 3,
                exclude_incident: str | None = None, min_score: float = 0.05
                ) -> list[SimilarCase]:
        with self._lock:
            pool = [c for c in self._cases.get(tenant_id, {}).values()
                    if c.confirmed and c.incident_id != exclude_incident]
        if not pool:
            return []
        # разные пространства векторов несравнимы: при смешении — hash для всех
        kinds = {c.vector_kind for c in pool}
        if kinds == {"provider"}:
            query, kind = self._embed([text])
            if kind != "provider":
                query = [hash_embedding(text)]
                pool_vecs = [hash_embedding(c.text) for c in pool]
            else:
                pool_vecs = [c.vector for c in pool]
        else:
            query = [hash_embedding(text)]
            pool_vecs = [c.vector if c.vector_kind == "hash" else hash_embedding(c.text)
                         for c in pool]
        scored = sorted(((cosine(query[0], v), c) for v, c in zip(pool_vecs, pool, strict=True)),
                        key=lambda s: (-s[0], s[1].incident_id))
        return [SimilarCase(incident_id=c.incident_id, cause=c.cause, summary=c.summary,
                            score=round(s, 4)) for s, c in scored[:k] if s >= min_score]
