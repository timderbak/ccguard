"""Policy engine для check: матрица правил."""

from __future__ import annotations

from datetime import UTC, datetime

from ccguard.agent.check import check_inventory, exit_code_for_findings
from ccguard.schemas import (
    AgentEntry,
    AgentsPolicy,
    EnvPolicy,
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


# ------- agents policy -------


def _agent(name: str, **kw: object) -> AgentEntry:
    return AgentEntry(
        name=name,
        path=f"/agents/{name}.md",
        file_hash=str(kw.get("file_hash") or "h" * 64),
        tools=kw.get("tools"),  # type: ignore[arg-type]
        model=kw.get("model"),  # type: ignore[arg-type]
    )


def test_agents_denylist_name() -> None:
    inv = _inventory(agents=[_agent("evil")])
    pol = _policy(agents=AgentsPolicy(denylist_names=["evil"]))
    findings = check_inventory(inv, pol)
    assert any(f.rule_id == "agents.denylist" for f in findings)


def test_agents_denylist_tool() -> None:
    """Если в tools агента есть Bash, и Bash в denylist_tools — finding."""
    inv = _inventory(agents=[_agent("a", tools=["Read", "Bash", "Grep"])])
    pol = _policy(agents=AgentsPolicy(denylist_tools=["Bash"]))
    findings = check_inventory(inv, pol)
    assert any(f.rule_id == "agents.forbidden_tool" for f in findings)


def test_agents_deny_all_unknown() -> None:
    inv = _inventory(agents=[_agent("a"), _agent("b")])
    pol = _policy(agents=AgentsPolicy(allowlist_names=["a"], deny_all_unknown=True))
    findings = check_inventory(inv, pol)
    names = [f.title for f in findings if f.rule_id == "agents.unknown"]
    assert any("b" in t for t in names)
    assert not any("a" in t for t in names)


def test_agents_trusted_file_hash_bypass() -> None:
    """Хэш в trusted_file_hashes снимает unknown-finding даже при whitelist-режиме."""
    inv = _inventory(agents=[_agent("a", file_hash="deadbeef" * 8)])
    pol = _policy(
        agents=AgentsPolicy(
            deny_all_unknown=True, trusted_file_hashes=["deadbeef" * 8]
        )
    )
    findings = [f for f in check_inventory(inv, pol) if f.rule_id.startswith("agents.")]
    assert findings == []


# ------- env policy -------


def test_env_denylist_regex() -> None:
    inv = _inventory(env_keys=["PATH", "OPENAI_API_KEY", "GITHUB_TOKEN", "HOME"])
    pol = _policy(env=EnvPolicy(denylist_patterns=[r".*_API_KEY$", r".*_TOKEN$"]))
    findings = [f for f in check_inventory(inv, pol) if f.rule_id == "env.denylist"]
    titles = {f.matched_value for f in findings}
    assert titles == {"OPENAI_API_KEY", "GITHUB_TOKEN"}


def test_env_allowlist_overrides_pattern() -> None:
    inv = _inventory(env_keys=["OPENAI_API_KEY"])
    pol = _policy(
        env=EnvPolicy(
            denylist_patterns=[r".*_API_KEY$"], allowlist_names=["OPENAI_API_KEY"]
        )
    )
    assert [f for f in check_inventory(inv, pol) if f.rule_id == "env.denylist"] == []
