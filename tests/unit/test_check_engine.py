"""Policy engine для check: матрица правил."""

from __future__ import annotations

from datetime import UTC, datetime

from ccguard.agent.check import check_inventory, exit_code_for_findings
from ccguard.schemas import (
    Finding,
    HookEntry,
    HooksPolicy,
    InventoryReport,
    McpServerEntry,
    McpServersPolicy,
    PermissionsSnapshot,
    Policy,
    PolicyMeta,
    SkillEntry,
    SkillsPolicy,
)


def _policy(**overrides) -> Policy:  # type: ignore[no-untyped-def]
    p = Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)))
    for k, v in overrides.items():
        setattr(p, k, v)
    return p


def _inventory(**overrides) -> InventoryReport:  # type: ignore[no-untyped-def]
    base = InventoryReport(
        machine_id="m",
        timestamp=datetime.now(UTC),
        agent_version="0.1.0",
        os="linux",
        permissions=PermissionsSnapshot(),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def test_clean_when_no_rules() -> None:
    findings = check_inventory(_inventory(), _policy())
    assert findings == []
    assert exit_code_for_findings(findings) == 0


def test_mcp_denylist_by_name() -> None:
    inv = _inventory(
        mcp_servers=[
            McpServerEntry(name="evil", transport="stdio", command="x", source="/s")
        ]
    )
    pol = _policy(mcp_servers=McpServersPolicy(denylist_names=["evil"], severity="block"))
    findings = check_inventory(inv, pol)
    assert len(findings) == 1
    assert findings[0].rule_id == "mcp_servers.denylist"
    assert findings[0].severity == "block"
    assert exit_code_for_findings(findings) == 2


def test_mcp_unknown_in_whitelist_mode() -> None:
    inv = _inventory(
        mcp_servers=[
            McpServerEntry(name="random", transport="stdio", command="x", source="/s")
        ]
    )
    pol = _policy(
        mcp_servers=McpServersPolicy(
            allowlist_names=["safe"], deny_all_unknown=True, severity="warn"
        )
    )
    findings = check_inventory(inv, pol)
    assert len(findings) == 1
    assert findings[0].rule_id == "mcp_servers.unknown"
    assert exit_code_for_findings(findings) == 1


def test_mcp_allowlisted_passes() -> None:
    inv = _inventory(
        mcp_servers=[
            McpServerEntry(name="safe", transport="stdio", command="x", source="/s")
        ]
    )
    pol = _policy(
        mcp_servers=McpServersPolicy(allowlist_names=["safe"], deny_all_unknown=True)
    )
    assert check_inventory(inv, pol) == []


def test_mcp_url_http_blocked() -> None:
    inv = _inventory(
        mcp_servers=[
            McpServerEntry(
                name="x", transport="http", url="http://insecure.example.com", source="/s"
            )
        ]
    )
    pol = _policy(
        mcp_servers=McpServersPolicy(denylist_url_patterns=["http://*"], severity="warn")
    )
    findings = check_inventory(inv, pol)
    assert any(f.rule_id == "mcp_servers.url_denylist" for f in findings)


def test_mcp_url_glob_match() -> None:
    inv = _inventory(
        mcp_servers=[
            McpServerEntry(
                name="x", transport="http", url="https://foo.bad.com/v1", source="/s"
            )
        ]
    )
    pol = _policy(mcp_servers=McpServersPolicy(denylist_url_patterns=["*.bad.com"]))
    findings = check_inventory(inv, pol)
    assert any(f.rule_id == "mcp_servers.url_denylist" for f in findings)


def test_hooks_unknown_command() -> None:
    inv = _inventory(
        hooks=[
            HookEntry(
                event="PreToolUse",
                matcher="Bash",
                type="command",
                command="/tmp/random.sh",
                source="/s",
            )
        ]
    )
    pol = _policy(hooks=HooksPolicy(allowlist_commands=["/opt/ccguard/"], deny_unknown=True))
    findings = check_inventory(inv, pol)
    assert len(findings) == 1
    assert findings[0].rule_id == "hooks.unknown"


def test_hooks_allowlisted_passes() -> None:
    inv = _inventory(
        hooks=[
            HookEntry(
                event="PreToolUse",
                matcher="Bash",
                type="command",
                command="/opt/ccguard/bin/enforce",
                source="/s",
            )
        ]
    )
    pol = _policy(hooks=HooksPolicy(allowlist_commands=["/opt/ccguard/"]))
    assert check_inventory(inv, pol) == []


def test_skills_untrusted() -> None:
    inv = _inventory(
        skills=[
            SkillEntry(
                name="unknown",
                path="/p",
                origin="local",
                dir_hash="a" * 64,
                has_referenced_scripts=False,
            )
        ]
    )
    pol = _policy(
        skills=SkillsPolicy(allowlist_names=["trusted"], severity="warn")
    )
    findings = check_inventory(inv, pol)
    assert len(findings) == 1
    assert findings[0].rule_id == "skills.untrusted"


def test_skills_trusted_hash_passes() -> None:
    h = "f" * 64
    inv = _inventory(
        skills=[
            SkillEntry(
                name="anything", path="/p", origin="local", dir_hash=h, has_referenced_scripts=False
            )
        ]
    )
    pol = _policy(skills=SkillsPolicy(trusted_dir_hashes=[h]))
    assert check_inventory(inv, pol) == []


def test_dangerously_skip_block() -> None:
    inv = _inventory(permissions=PermissionsSnapshot(dangerously_skip_detected=True))
    findings = check_inventory(inv, _policy())
    assert any(f.rule_id == "permissions.dangerously_skip" for f in findings)
    assert exit_code_for_findings(findings) == 2


def test_exit_code_warn_only() -> None:
    findings = [
        Finding(rule_id="x", severity="warn", title="t", description="d", source="s", recommendation="r")
    ]
    assert exit_code_for_findings(findings) == 1
