"""policy_form: serialize Starlette form data → Policy YAML."""

from __future__ import annotations

from ccguard.server.web.policy_form import form_to_yaml


_ALL_SECTIONS_FORM = {
    "mcp_servers.severity": "warn",
    "mcp_servers.allowlist_names": "",
    "mcp_servers.denylist_names": "",
    "mcp_servers.allowlist_url_patterns": "",
    "mcp_servers.denylist_url_patterns": "",
    "network.severity": "warn",
    "network.allowlist_hosts": "",
    "network.denylist_hosts": "",
    "commands.severity": "warn",
    "commands.denylist_patterns": "",
    "commands.allowlist_patterns": "",
    "skills.severity": "warn",
    "skills.allowlist_names": "",
    "skills.trusted_dir_hashes": "",
    "hooks.severity": "warn",
    "hooks.allowlist_commands": "",
    "hooks.deny_unknown": "1",
    "agents.severity": "warn",
    "agents.allowlist_names": "",
    "agents.denylist_names": "",
    "agents.denylist_tools": "",
    "agents.trusted_file_hashes": "",
    "env.severity": "warn",
    "env.denylist_patterns": "",
    "env.allowlist_names": "",
}


def test_simple_form_roundtrip() -> None:
    form = dict(_ALL_SECTIONS_FORM)
    form.update({
        "mcp_servers.allowlist_names": "filesystem, memory",
        "mcp_servers.denylist_url_patterns": "http://*",
        "mcp_servers.deny_all_unknown": "",  # unchecked
        "hooks.allowlist_commands": "/opt/ccguard-enforce\n/root/.ccguard/bin/enforce",
        "hooks.deny_unknown": "1",
    })
    yaml_text = form_to_yaml(form, current_revision=1)
    assert "filesystem" in yaml_text
    assert "memory" in yaml_text
    assert "deny_all_unknown: false" in yaml_text
    assert "deny_unknown: true" in yaml_text
    assert "revision: 2" in yaml_text  # bumped


def test_empty_lists_become_empty_arrays() -> None:
    form = dict(_ALL_SECTIONS_FORM)
    yaml_text = form_to_yaml(form, current_revision=4)
    assert "revision: 5" in yaml_text


def test_form_preserves_baseline_block_fail_mode() -> None:
    baseline = {
        "meta": {
            "schema_version": 1,
            "revision": 4,
            "updated_at": "2026-01-01T00:00:00Z",
            "name": "prod",
        },
        "block_fail_mode": "closed",
        "mcp_servers": {
            "severity": "warn",
            "allowlist_names": [],
            "denylist_names": [],
            "allowlist_url_patterns": [],
            "denylist_url_patterns": [],
            "deny_all_unknown": False,
        },
        "skills": {
            "severity": "warn",
            "allowlist_names": [],
            "trusted_dir_hashes": [],
            "deny_all_unknown": False,
            "signature": {"sigstore": "value"},
        },
    }
    form = {
        "mcp_servers.severity": "warn",
        "mcp_servers.allowlist_names": "",
        "mcp_servers.denylist_names": "",
        "mcp_servers.allowlist_url_patterns": "",
        "mcp_servers.denylist_url_patterns": "",
        "network.severity": "warn",
        "network.allowlist_hosts": "",
        "network.denylist_hosts": "",
        "commands.severity": "warn",
        "commands.denylist_patterns": "",
        "commands.allowlist_patterns": "",
        "skills.severity": "warn",
        "skills.allowlist_names": "",
        "skills.trusted_dir_hashes": "",
        "hooks.severity": "warn",
        "hooks.allowlist_commands": "",
        "hooks.deny_unknown": "1",
        "agents.severity": "warn",
        "agents.allowlist_names": "",
        "agents.denylist_names": "",
        "agents.denylist_tools": "",
        "agents.trusted_file_hashes": "",
        "env.severity": "warn",
        "env.denylist_patterns": "",
        "env.allowlist_names": "",
    }
    import yaml
    yaml_text = form_to_yaml(form, current_revision=4, baseline=baseline)
    data = yaml.safe_load(yaml_text)
    assert data["block_fail_mode"] == "closed"
    assert data["meta"]["name"] == "prod"
    assert data["skills"]["signature"] == {"sigstore": "value"}
    assert data["meta"]["revision"] == 5
