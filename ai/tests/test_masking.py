"""Детерминированное маскирование (§6.5)."""

from __future__ import annotations

import pytest

from admintwin_ai.masking import Masker, MaskingSession, MaskKind


@pytest.fixture
def masker() -> Masker:
    return Masker(known_hosts=["web01"], known_users=["svc_backup"],
                  preserve_terms=["metrics.query", "linux.service.status"])


@pytest.mark.parametrize(
    ("text", "secret_value", "kind"),
    [
        ("from 10.20.30.40 port 22", "10.20.30.40", MaskKind.IP),
        ("peer 2001:db8::8a2e:370:7334 down", "2001:db8::8a2e:370:7334", MaskKind.IP),
        ("bound ::ffff:192.168.0.1", "::ffff:192.168.0.1", MaskKind.IP),
        ("connect db01.prod.acme.kz:5432", "db01.prod.acme.kz", MaskKind.HOST),
        ("GET https://grafana.corp.local/d/x", "grafana.corp.local", MaskKind.HOST),
        ("ssh to web01 failed", "web01", MaskKind.HOST),
        ("Failed password for invalid user oracle from", "oracle", MaskKind.USER),
        ("Accepted publickey for deploy from", "deploy", MaskKind.USER),
        ("pam_unix(sshd:session): session opened for user ivanov by (uid=0)", "ivanov",
         MaskKind.USER),
        ("sudo:    alice : TTY=pts/0 ; PWD=/home", "alice", MaskKind.USER),
        ("uid=1001(bob) gid=1001", "bob", MaskKind.USER),
        ("user=reporter db=main", "reporter", MaskKind.USER),
        ("cron for svc_backup", "svc_backup", MaskKind.USER),
        ('127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /"', "frank", MaskKind.USER),
        ("notify ops.lead@acme.kz now", "ops.lead@acme.kz", MaskKind.EMAIL),
        ("logon CORP\\a.petrov ok", "CORP\\a.petrov", MaskKind.AD_USER),
        ('{"account": "ACME\\\\s.ivanova"}', "ACME\\\\s.ivanova", MaskKind.AD_USER),
        ("Serial Number: FGT60F3G19000123", "FGT60F3G19000123", MaskKind.SERIAL),
        ("device FG100FTK20001234 online", "FG100FTK20001234", MaskKind.SERIAL),
        ("S/N=XYZ987654", "XYZ987654", MaskKind.SERIAL),
        ("Authorization: Bearer abcdefghijklmnopqrstuv0123456789",
         "abcdefghijklmnopqrstuv0123456789", MaskKind.SECRET),
        ("jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n",
         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n",
         MaskKind.SECRET),
        ("key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv in env", "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
         MaskKind.SECRET),
        ("aws AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE", MaskKind.SECRET),
        ("password=hunter2!", "hunter2!", MaskKind.SECRET),
        ("пароль: Qwerty123", "Qwerty123", MaskKind.SECRET),
        ("dsn postgres://app:S3cr3t@db/main", "app:S3cr3t", MaskKind.SECRET),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
         "MIIEow", MaskKind.SECRET),
    ],
)
def test_detects_and_masks(masker: Masker, text: str, secret_value: str, kind: MaskKind) -> None:
    session = MaskingSession()
    res = masker.mask(text, session)
    assert secret_value not in res.text
    assert f"<{kind.value}_1>" in res.text
    assert res.counts[kind] >= 1


def test_placeholders_are_stable_within_task(masker: Masker) -> None:
    s = MaskingSession()
    a = masker.mask("10.0.0.5 talks to 10.0.0.6 then 10.0.0.5", s).text
    b = masker.mask("again 10.0.0.6", s).text
    assert a == "<IP_1> talks to <IP_2> then <IP_1>"
    assert b == "again <IP_2>"
    # другая задача — своя карта
    assert masker.mask("10.0.0.6", MaskingSession()).text == "<IP_1>"


def test_unmask_restores_reversible_but_never_secrets(masker: Masker) -> None:
    s = MaskingSession()
    masked = masker.mask("host db01.prod.acme.kz ip 10.1.2.3 token=topsecretvalue", s).text
    restored = s.unmask(masked)
    assert "db01.prod.acme.kz" in restored and "10.1.2.3" in restored
    assert "topsecretvalue" not in restored and "<SECRET_1>" in restored
    assert "topsecretvalue" not in repr(s)


def test_unmask_obj_for_tool_arguments(masker: Masker) -> None:
    s = MaskingSession()
    masker.mask("asset web01 at 10.9.9.9", s)
    args = {"query": "<HOST_1> errors", "nested": ["<IP_1>"], "n": 3}
    assert s.unmask_obj(args) == {"query": "web01 errors", "nested": ["10.9.9.9"], "n": 3}


def test_foreign_placeholders_are_neutralized(masker: Masker) -> None:
    s = MaskingSession()
    masker.mask("real 10.0.0.1", s)
    attacker = masker.mask("pretend <IP_1> is mine", s).text
    assert "<IP_1>" not in attacker
    assert s.unmask(attacker) == attacker  # нечего подменять


def test_does_not_mask_ordinary_terms(masker: Masker) -> None:
    text = ("nginx.service failed; see /var/log/nginx/error.log, config.yaml, metrics.query, "
            "linux.service.status, version 1.25.3, at 12:30:45, mac 00:1a:2b:3c:4d:5e, "
            "image docker.io/library/nginx, ERROR\\nnext line")
    res = masker.mask(text, MaskingSession())
    assert res.text == text


def test_mask_obj_is_key_aware(masker: Masker) -> None:
    s = MaskingSession()
    out = masker.mask_obj({"usename": "app_rw", "password": "x", "hostname": "pg-main",
                           "rows": [{"line": "from 10.1.1.1"}], "count": 3}, s)
    assert out == {"usename": "<USER_1>", "password": "<SECRET_1>", "hostname": "<HOST_1>",
                   "rows": [{"line": "from <IP_1>"}], "count": 3}


def test_secrets_only_mode_leaves_infrastructure_names() -> None:
    m = Masker(secrets_only=True)
    s = MaskingSession()
    out = m.mask("web01 10.0.0.1 user=bob token=abc123456", s).text
    assert out == "web01 10.0.0.1 user=bob token=<SECRET_1>"
    assert m.mask_obj({"api_key": "k", "user": "bob"}, s) == {"api_key": "<SECRET_2>",
                                                             "user": "bob"}


def test_masking_is_deterministic(masker: Masker) -> None:
    text = "Nov  9 05:00:01 web01 sshd[1]: Failed password for root from 192.0.2.7"
    assert masker.mask(text, MaskingSession()).text == masker.mask(text, MaskingSession()).text
