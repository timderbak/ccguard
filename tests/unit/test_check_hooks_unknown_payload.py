"""Finding hooks.unknown: description содержит event/matcher/command/source.

UI на /admin/machines/<id> до фикса рендерил только "WARN hooks.unknown" — без
команды, без источника. Пользователь не понимал как откатить. Description теперь
несёт полный контекст для раскрываемой карточки.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ccguard.agent.check import check_inventory
from ccguard.schemas import (
    HookEntry,
    HooksPolicy,
    InventoryReport,
    PermissionsSnapshot,
    Policy,
    PolicyMeta,
)


def _inventory(**overrides):  # type: ignore[no-untyped-def]
    base = InventoryReport(
        machine_id="m",
        timestamp=datetime.now(UTC),
        agent_version="0.2.0",
        os="linux",
        permissions=PermissionsSnapshot(),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _policy(**overrides):  # type: ignore[no-untyped-def]
    p = Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)))
    for k, v in overrides.items():
        setattr(p, k, v)
    return p


def test_hooks_unknown_description_has_event_matcher_command_source() -> None:
    inv = _inventory(
        hooks=[
            HookEntry(
                event="PreToolUse",
                matcher="Bash",
                type="command",
                command="python /root/.foo/run.py",
                source="/root/.claude/settings.json",
            )
        ]
    )
    pol = _policy(hooks=HooksPolicy(deny_unknown=True))
    findings = check_inventory(inv, pol)
    assert len(findings) == 1
    desc = findings[0].description
    assert "PreToolUse" in desc
    assert "Bash" in desc
    assert "python /root/.foo/run.py" in desc
    assert "/root/.claude/settings.json" in desc


def test_hooks_unknown_recommendation_mentions_allowlist() -> None:
    inv = _inventory(
        hooks=[
            HookEntry(
                event="PostToolUse",
                matcher=None,
                type="command",
                command="/usr/local/bin/log",
                source="/etc/claude-code/managed-settings.json",
            )
        ]
    )
    pol = _policy(hooks=HooksPolicy(deny_unknown=True))
    findings = check_inventory(inv, pol)
    assert len(findings) == 1
    rec = findings[0].recommendation
    assert "allowlist" in rec or "удалить" in rec.lower()


def test_ccguard_owned_hook_not_flagged_when_allowlist_empty() -> None:
    """ccguard-собственные хуки — известны "по факту", и при пустом allowlist
    + deny_unknown=true их не флагуем (иначе ccguard сам себе создаёт WARN'ы)."""
    inv = _inventory(
        hooks=[
            HookEntry(
                event="PreToolUse",
                matcher="Bash",
                type="command",
                command="/root/.ccguard/bin/ccguard-enforce",
                source="/root/.claude/settings.json",
                is_ccguard_owned=True,
            )
        ]
    )
    pol = _policy(hooks=HooksPolicy(deny_unknown=True))
    findings = check_inventory(inv, pol)
    assert findings == []
