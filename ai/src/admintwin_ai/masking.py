"""Детерминированный препроцессор маскирования (§6.5). Без LLM.

Заменяет IP (v4/v6), hostnames/FQDN, логины (типовые формы журналов),
email, токены/API-ключи/JWT/пароли, серийные номера и имена AD
(``DOMAIN\\user``) стабильными плейсхолдерами вида ``<IP_1>``.

* Обратная карта хранится только в ``MaskingSession`` — объекте памяти
  задачи; она не сериализуется в аудит и не покидает процесс.
* Секреты (``<SECRET_n>``) маскируются **необратимо**: исходное значение не
  хранится даже в обратной карте (только SHA-256 для стабильности
  плейсхолдера), и ``unmask`` их не восстанавливает — агент никогда не
  получает секрет (§23 п.10).
* Маскирование не гарантирует удаление всех ПДн/секретов: оно дополняется
  классификацией данных Tool Layer и fail-closed маршрутизацией.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class MaskKind(StrEnum):
    IP = "IP"
    HOST = "HOST"
    USER = "USER"
    EMAIL = "EMAIL"
    AD_USER = "AD_USER"
    SERIAL = "SERIAL"
    SECRET = "SECRET"

    @property
    def reversible(self) -> bool:
        return self is not MaskKind.SECRET


_KINDS_ALT = "|".join(k.value for k in MaskKind)
PLACEHOLDER_RE = re.compile(rf"<({_KINDS_ALT})_(\d+)>")


class MaskingSession:
    """Стабильные плейсхолдеры и обратная карта в памяти задачи."""

    def __init__(self) -> None:
        self._forward: dict[tuple[MaskKind, str], str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: Counter[MaskKind] = Counter()

    def placeholder(self, kind: MaskKind, value: str) -> str:
        key_value = _normalize(kind, value)
        if not kind.reversible:
            key_value = hashlib.sha256(key_value.encode()).hexdigest()
        key = (kind, key_value)
        existing = self._forward.get(key)
        if existing is not None:
            return existing
        self._counters[kind] += 1
        token = f"<{kind.value}_{self._counters[kind]}>"
        self._forward[key] = token
        if kind.reversible:
            self._reverse[token] = value
        return token

    def unmask(self, text: str) -> str:
        return PLACEHOLDER_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    def unmask_obj(self, obj: Any) -> Any:
        """Рекурсивно для аргументов вызовов инструментов (dict/list/str)."""
        if isinstance(obj, str):
            return self.unmask(obj)
        if isinstance(obj, list):
            return [self.unmask_obj(v) for v in obj]
        if isinstance(obj, dict):
            return {k: self.unmask_obj(v) for k, v in obj.items()}
        return obj

    @property
    def size(self) -> int:
        return len(self._forward)

    def __repr__(self) -> str:  # не раскрываем карту в логах
        return f"MaskingSession(entries={self.size})"


def _normalize(kind: MaskKind, value: str) -> str:
    if kind is MaskKind.IP:
        try:
            return ipaddress.ip_address(value.split("%")[0]).compressed
        except ValueError:
            return value.lower()
    if kind is MaskKind.AD_USER:
        return value.replace("\\\\", "\\").lower()
    if kind in (MaskKind.HOST, MaskKind.EMAIL):
        return value.lower().rstrip(".")
    return value


# --- детекторы ---------------------------------------------------------------


def _valid_ipv4(v: str) -> bool:
    try:
        ipaddress.IPv4Address(v)
    except ValueError:
        return False
    return True


def _valid_ipv6(v: str) -> bool:
    try:
        ipaddress.IPv6Address(v.split("%")[0])
    except ValueError:
        return False
    return True


_FILE_SUFFIXES = frozenset({
    "service", "socket", "timer", "mount", "target", "slice", "scope", "path", "device",
    "conf", "cfg", "ini", "yaml", "yml", "json", "toml", "xml", "log", "txt", "md", "csv",
    "py", "go", "js", "ts", "sh", "rb", "java", "rs", "c", "h", "cpp", "sql", "pid", "sock",
    "lock", "tmp", "bak", "old", "gz", "tgz", "zip", "tar", "xz", "bz2", "jar", "so", "d",
    "html", "htm", "css", "png", "jpg", "svg", "pem", "crt", "key", "csr", "deb", "rpm",
    "exe", "dll", "msi", "ps1", "bat", "env", "status", "query", "inspect", "usage",
    "activity", "list", "get", "propose", "search", "radius", "restart", "cleanup",
})

_TLDS = frozenset({
    "com", "net", "org", "io", "ai", "dev", "app", "cloud", "info", "biz", "edu", "gov", "mil",
    "kz", "ru", "uz", "kg", "by", "ua", "de", "uk", "us", "eu", "fr", "nl", "cn", "jp", "tr",
    "local", "lan", "corp", "internal", "intra", "intranet", "home", "localdomain", "domain",
    "ad", "prod", "test", "example", "invalid", "arpa",
})

_PUBLIC_DOMAINS = frozenset({
    "docker.io", "ghcr.io", "quay.io", "gcr.io", "registry.k8s.io", "github.com",
    "gitlab.com", "ubuntu.com", "debian.org", "postgresql.org", "kernel.org",
    "admintwin.io", "errors.admintwin.io", "schemas.admintwin.io",
})


@dataclass(frozen=True)
class _Detector:
    pattern: re.Pattern[str]
    groups: tuple[tuple[int, MaskKind], ...]
    validate: Callable[[str], bool] | None = None


_U = r"[A-Za-z0-9_][A-Za-z0-9_.$-]{0,63}"  # логин в журналах

_SECRET_DETECTORS: tuple[_Detector, ...] = (
    _Detector(re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
              ((0, MaskKind.SECRET),)),
    _Detector(re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
              ((0, MaskKind.SECRET),)),
    _Detector(re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://([^\s:/@\"']+:[^\s@/\"']+)@"),
              ((1, MaskKind.SECRET),)),
    _Detector(re.compile(
        r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}"
        r"|github_pat_[A-Za-z0-9_]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}"
        r"|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})"), ((0, MaskKind.SECRET),)),
    _Detector(re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{12,})"),
              ((1, MaskKind.SECRET),)),
    _Detector(re.compile(
        r"(?i)(?:\b(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key"
        r"|secret[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|credentials?)"
        r"|пароль|құпиясөз)[\"']?\s*[:=]\s*[\"']?([^\s\"',;&}<>]+)"),
        ((1, MaskKind.SECRET),)),
)

_PII_DETECTORS: tuple[_Detector, ...] = (
    _Detector(re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b"),
              ((0, MaskKind.EMAIL),)),
    # DOMAIN\user (в JSON-тексте обратный слэш удвоен). NetBIOS-домен — заглавными.
    # Одиночный «\» перед n/t/r/b/f/u считается JSON-escape, а не DOMAIN\user.
    _Detector(re.compile(
        r"\b[A-Z][A-Z0-9-]{1,14}(?:\\\\|\\(?![ntrbfu]))[A-Za-z][A-Za-z0-9._$-]{0,63}"),
        ((0, MaskKind.AD_USER),)),
    _Detector(re.compile(r"\b([a-z_][a-z0-9_.-]{0,31})@([A-Za-z0-9][A-Za-z0-9-]{0,62})\b(?![.@])"),
              ((1, MaskKind.USER), (2, MaskKind.HOST))),
    _Detector(re.compile(
        rf"(?i)\b(?:failed|accepted)\s+(?:password|publickey|keyboard-interactive(?:/pam)?)\s+for"
        rf"\s+(?:invalid\s+user\s+)?({_U})"), ((1, MaskKind.USER),)),
    _Detector(re.compile(rf"(?i)\b(?:invalid\s+user|for\s+user|by\s+user)\s+({_U})"),
              ((1, MaskKind.USER),)),
    _Detector(re.compile(r"\bsudo:\s+([a-z_][a-z0-9_-]{0,31})\s*:"), ((1, MaskKind.USER),)),
    _Detector(re.compile(r"\buid=\d+\(([a-z_][a-z0-9_-]{0,31})\)"), ((1, MaskKind.USER),)),
    _Detector(re.compile(
        rf"(?i)\b(?:user(?:name)?|usename|login|logname|r?user|account|owner|usr)[\"']?\s*[=:]"
        rf"\s*[\"']?({_U})"), ((1, MaskKind.USER),)),
    # Common Log Format: ip - user [date]
    _Detector(re.compile(r"(?m)(?:^|(?<=\"))\S+ \S+ ([^\s\[\]\"-][^\s\[\]\"]*) \["),
              ((1, MaskKind.USER),)),
    _Detector(re.compile(
        r"(?i)\b(?:serial(?:[ _-]?(?:number|no|num))?|s/n|sn)\b[\"']?\s*[:=#]?\s*[\"']?"
        r"([A-Z0-9][A-Z0-9-]{5,31})\b"), ((1, MaskKind.SERIAL),)),
    _Detector(re.compile(r"\bF[GWAS][A-Z0-9]{12,14}\b"), ((0, MaskKind.SERIAL),)),
)

_NETWORK_DETECTORS: tuple[_Detector, ...] = (
    _Detector(re.compile(
        r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|\d{1,3}(?:\.\d{1,3}){3})"
        r"(?:%[A-Za-z0-9]+)?(?![\w:])"), ((0, MaskKind.IP),), _valid_ipv6),
    _Detector(re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)"),
              ((0, MaskKind.IP),), _valid_ipv4),
    # syslog-заголовок: "<pri>Mon DD HH:MM:SS host prog[pid]:" / RFC 5424 timestamp host
    _Detector(re.compile(
        r"(?m)(?:^|(?<=\"))(?:<\d{1,3}>\d?\s?)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
        r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"([A-Za-z0-9][A-Za-z0-9._-]{0,253})\s"), ((1, MaskKind.HOST),)),
    # хост в URL (IP уже пойман детекторами выше)
    _Detector(re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^\s/@\"']+@)?([A-Za-z0-9][A-Za-z0-9.-]*)"),
              ((1, MaskKind.HOST),), lambda v: not _valid_ipv4(v)),
    _Detector(re.compile(
        r"(?i)\b(?:host(?:name)?|server|node|fqdn|dst_?host|src_?host|devname|instance)[\"']?"
        r"\s*[:=]\s*[\"']?([A-Za-z0-9][A-Za-z0-9._-]{0,253})"), ((1, MaskKind.HOST),)),
)

_FQDN_RE = re.compile(
    r"(?<![\w./-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}\b"
    r"(?![\w-])"
)

_SECRET_KEY_RE = re.compile(
    r"(?i)^(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|secret[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|credentials?"
    r"|authorization|cookie|set-cookie)$|(?:_password|_secret|_token|_api_?key)$"
)
_USER_KEYS = frozenset({"user", "username", "usename", "login", "logname", "owner", "account",
                        "ruser", "user_name"})
_HOST_KEYS = frozenset({"host", "hostname", "fqdn", "server", "node", "devname"})
_NEUTRALIZE_RE = re.compile(rf"<(({_KINDS_ALT})_\d+)>")


@dataclass
class MaskResult:
    text: str
    counts: Counter[MaskKind] = field(default_factory=Counter)

    @property
    def masked(self) -> bool:
        return sum(self.counts.values()) > 0


class Masker:
    """Маскировщик. ``secrets_only=True`` — режим Tool Layer (только секреты)."""

    def __init__(
        self,
        *,
        known_hosts: Iterable[str] = (),
        known_users: Iterable[str] = (),
        preserve_terms: Iterable[str] = (),
        secrets_only: bool = False,
    ) -> None:
        self._preserve = {t.lower() for t in preserve_terms} | _PUBLIC_DOMAINS
        self._secrets_only = secrets_only
        detectors: list[_Detector] = list(_SECRET_DETECTORS)
        if not secrets_only:
            known: list[_Detector] = []
            hosts = sorted({h for h in known_hosts if h}, key=len, reverse=True)
            users = sorted({u for u in known_users if u}, key=len, reverse=True)
            if hosts:
                known.append(_Detector(
                    re.compile(r"(?i)(?<![\w.-])(?:" + "|".join(map(re.escape, hosts))
                               + r")(?![\w-])"), ((0, MaskKind.HOST),)))
            if users:
                known.append(_Detector(
                    re.compile(r"(?<![\w.-])(?:" + "|".join(map(re.escape, users))
                               + r")(?![\w-])"), ((0, MaskKind.USER),)))
            detectors += list(_PII_DETECTORS[:2]) + known + list(_PII_DETECTORS[2:])
            detectors += list(_NETWORK_DETECTORS)
            detectors.append(_Detector(_FQDN_RE, ((0, MaskKind.HOST),), self._is_hostname))
        self._detectors = tuple(detectors)

    def _is_hostname(self, value: str) -> bool:
        low = value.lower().rstrip(".")
        if low in self._preserve:
            return False
        labels = low.split(".")
        last = labels[-1]
        if last in _FILE_SUFFIXES or last.isdigit():
            return False
        if all(lbl.isdigit() for lbl in labels[:-1]):  # версии вида 1.2.x
            return False
        return last in _TLDS or len(labels) >= 3

    def mask(self, text: str, session: MaskingSession) -> MaskResult:
        # Чужие «плейсхолдеры» во входе нейтрализуются, чтобы unmask их не подменил.
        text = _NEUTRALIZE_RE.sub(lambda m: f"‹{m.group(1)}›", text)
        spans: list[tuple[int, int, int, MaskKind, str]] = []
        for prio, det in enumerate(self._detectors):
            for m in det.pattern.finditer(text):
                for group, kind in det.groups:
                    start, end = m.span(group)
                    if start < 0 or start == end:
                        continue
                    value = m.group(group)
                    if kind is MaskKind.HOST and value.lower() in self._preserve:
                        continue
                    if det.validate is not None and not det.validate(value):
                        continue
                    spans.append((prio, start, end, kind, value))
        spans.sort(key=lambda s: (s[0], s[1]))
        chosen: list[tuple[int, int, MaskKind, str]] = []
        for _, start, end, kind, value in spans:
            if any(start < c_end and c_start < end for c_start, c_end, _, _ in chosen):
                continue
            chosen.append((start, end, kind, value))
        chosen.sort()
        counts: Counter[MaskKind] = Counter()
        out: list[str] = []
        pos = 0
        for start, end, kind, value in chosen:
            out.append(text[pos:start])
            out.append(session.placeholder(kind, value))
            counts[kind] += 1
            pos = end
        out.append(text[pos:])
        return MaskResult(text="".join(out), counts=counts)

    def mask_obj(self, obj: Any, session: MaskingSession) -> Any:
        """Рекурсивно маскирует строки в JSON-подобной структуре.

        Учитывает ключи: значение под ключом ``password``/``token``/... — секрет
        целиком; под ``user``/``usename``/... — логин; под ``host``/... — хост.
        Сами ключи не изменяются.
        """
        if isinstance(obj, str):
            return self.mask(obj, session).text
        if isinstance(obj, list):
            return [self.mask_obj(v, session) for v in obj]
        if isinstance(obj, dict):
            return {k: self._mask_value(str(k), v, session) for k, v in obj.items()}
        return obj

    def _mask_value(self, key: str, value: Any, session: MaskingSession) -> Any:
        if not isinstance(value, str) or not value:
            return self.mask_obj(value, session)
        low = key.lower()
        if _SECRET_KEY_RE.search(low):
            return session.placeholder(MaskKind.SECRET, value)
        if not self._secrets_only:
            if low in _USER_KEYS and not PLACEHOLDER_RE.fullmatch(value):
                return session.placeholder(MaskKind.USER, value)
            if low in _HOST_KEYS:
                res = self.mask(value, session)
                if res.masked or value.lower() in self._preserve:
                    return res.text
                return session.placeholder(MaskKind.HOST, value)
        return self.mask(value, session).text
