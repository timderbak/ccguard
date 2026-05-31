"""Suspicious network rules — host catalog (glob, regex, IP-as-host, private IP).

Покрывает:
* glob по hostname — pastebin.com → match, github.com → no match
* glob по host+path — discord.com/api/webhooks/* матчит webhook URL,
  не матчит обычный discord URL
* regex pattern — IP-as-host через спец-логику detect_ip_as_host
* private IP через ipaddress.is_private
* severity=block → deny
* severity=warn → allow + warning_signals
* дефолтные правила подгружаются factory'ём
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ccguard.agent.enforce import decide
from ccguard.schemas import (
    EnforceHookInput,
    NetworkPolicy,
    Policy,
    PolicyMeta,
)
from ccguard.schemas.policy import SuspiciousHostRule


def _policy(
    *,
    mode: str = "enforce",
    rules: list[SuspiciousHostRule] | None = None,
    keep_defaults: bool = False,
) -> Policy:
    if keep_defaults:
        net = NetworkPolicy()
        if rules:
            net.suspicious_host_rules = list(net.suspicious_host_rules) + list(rules)
    else:
        net = NetworkPolicy(suspicious_host_rules=rules or [])
    p = Policy(
        meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)),
        enforcement_mode=mode,  # type: ignore[arg-type]
        network=net,
    )
    return p


def _web(url: str) -> EnforceHookInput:
    return EnforceHookInput(
        hook_event_name="PreToolUse",
        tool_name="WebFetch",
        tool_input={"url": url},
    )


# --- default catalog --------------------------------------------------------


def test_defaults_loaded_by_factory() -> None:
    p = NetworkPolicy()
    ids = {r.id for r in p.suspicious_host_rules}
    # минимум этот набор должен быть в дефолтах
    expected = {
        "egress/pastebin",
        "egress/discord-webhook",
        "egress/raw-gist",
        "egress/telegram-bot",
        "egress/slack-webhook",
        "egress/ip-as-host",
        "egress/private-ip",
    }
    assert expected.issubset(ids), f"missing defaults: {expected - ids}"


def test_default_pastebin_blocks() -> None:
    p = _policy(keep_defaults=True)
    d = decide(_web("https://pastebin.com/raw/abc"), p)
    assert d.permission == "deny"
    assert d.rule_id and d.rule_id.startswith("network.suspicious.egress/pastebin")


def test_default_github_api_allowed() -> None:
    p = _policy(keep_defaults=True)
    d = decide(_web("https://api.github.com/repos/x/y"), p)
    assert d.permission == "allow"


# --- glob (hostname only) ---------------------------------------------------


def test_glob_hostname_match() -> None:
    rule = SuspiciousHostRule(
        id="egress/pastebin",
        pattern="*pastebin.com",
        type="glob",
        severity="block",
        title="Pastebin",
        reason="r",
        remediation="m",
    )
    p = _policy(rules=[rule])
    assert decide(_web("https://pastebin.com/raw/x"), p).permission == "deny"
    assert decide(_web("https://github.com/x/y"), p).permission == "allow"


# --- glob (hostname + path) -------------------------------------------------


def test_glob_with_path_matches_webhook_only() -> None:
    rule = SuspiciousHostRule(
        id="egress/discord-webhook",
        pattern="discord.com/api/webhooks/*",
        type="glob",
        severity="block",
        title="Discord",
        reason="r",
        remediation="m",
    )
    p = _policy(rules=[rule])
    d_webhook = decide(_web("https://discord.com/api/webhooks/123/abc"), p)
    assert d_webhook.permission == "deny", d_webhook
    d_regular = decide(_web("https://discord.com/channels/123"), p)
    assert d_regular.permission == "allow"


# --- IP-as-host (special handling) ------------------------------------------


def test_ip_as_host_warn() -> None:
    rule = SuspiciousHostRule(
        id="egress/ip-as-host",
        pattern="__detector__",  # ignored; special-cased by id
        type="regex",
        severity="warn",
        title="IP",
        reason="r",
        remediation="m",
    )
    p = _policy(rules=[rule])
    d = decide(_web("http://1.2.3.4/x"), p)
    assert d.permission == "allow"
    assert any("ip-as-host" in s for s in d.warning_signals), d.warning_signals
    # обычный домен — никакого warning
    d2 = decide(_web("https://example.com/"), p)
    assert d2.permission == "allow"
    assert not any("ip-as-host" in s for s in d2.warning_signals)


# --- Private IP -------------------------------------------------------------


def test_private_ip_warn() -> None:
    rule = SuspiciousHostRule(
        id="egress/private-ip",
        pattern="__detector__",
        type="regex",
        severity="warn",
        title="priv",
        reason="r",
        remediation="m",
    )
    p = _policy(rules=[rule])
    d = decide(_web("http://192.168.1.1/cnc"), p)
    assert d.permission == "allow"
    assert any("private-ip" in s for s in d.warning_signals)
    # публичный IP — не считается private
    d2 = decide(_web("http://8.8.8.8/"), p)
    assert not any("private-ip" in s for s in d2.warning_signals)


# --- severity=warn behaviour -----------------------------------------------


def test_warn_severity_allows_but_signals() -> None:
    rule = SuspiciousHostRule(
        id="egress/raw-gist",
        pattern="raw.githubusercontent.com",
        type="glob",
        severity="warn",
        title="Raw gist",
        reason="r",
        remediation="m",
    )
    p = _policy(rules=[rule])
    d = decide(_web("https://raw.githubusercontent.com/x/y/main/install.sh"), p)
    assert d.permission == "allow"
    assert any("raw-gist" in s for s in d.warning_signals)


def test_block_severity_denies() -> None:
    rule = SuspiciousHostRule(
        id="egress/telegram-bot",
        pattern="api.telegram.org/bot*",
        type="glob",
        severity="block",
        title="TG",
        reason="r",
        remediation="m",
    )
    p = _policy(rules=[rule])
    d = decide(_web("https://api.telegram.org/bot12345:abc/sendMessage"), p)
    assert d.permission == "deny"
    assert d.rule_id == "network.suspicious.egress/telegram-bot"


# --- precedence: denylist still wins ---------------------------------------


def test_denylist_still_wins_over_suspicious() -> None:
    rule = SuspiciousHostRule(
        id="egress/pastebin",
        pattern="*pastebin.com",
        type="glob",
        severity="warn",  # warn, but denylist is hard deny
        title="P",
        reason="r",
        remediation="m",
    )
    net = NetworkPolicy(
        denylist_hosts=["*pastebin.com"],
        suspicious_host_rules=[rule],
    )
    p = Policy(
        meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)),
        enforcement_mode="enforce",
        network=net,
    )
    d = decide(_web("https://pastebin.com/raw/x"), p)
    assert d.permission == "deny"
    assert d.rule_id == "network.denylist"
