"""policy_form: serialize Starlette form data → Policy YAML."""

from __future__ import annotations

from ccguard.server.web.policy_form import form_to_yaml


def test_simple_form_roundtrip() -> None:
    form = {
        "mcp_servers.severity": "warn",
        "mcp_servers.allowlist_names": "filesystem, memory",
        "mcp_servers.denylist_names": "",
        "mcp_servers.denylist_url_patterns": "http://*",
        "mcp_servers.deny_all_unknown": "",  # unchecked
        "hooks.severity": "warn",
        "hooks.allowlist_commands": "/opt/ccguard-enforce\n/root/.ccguard/bin/enforce",
        "hooks.deny_unknown": "1",
    }
    yaml_text = form_to_yaml(form, current_revision=1)
    assert "filesystem" in yaml_text
    assert "memory" in yaml_text
    assert "deny_all_unknown: false" in yaml_text
    assert "deny_unknown: true" in yaml_text
    assert "revision: 2" in yaml_text  # bumped


def test_empty_lists_become_empty_arrays() -> None:
    form = {
        "mcp_servers.severity": "warn",
        "mcp_servers.allowlist_names": "",
        "mcp_servers.denylist_names": "",
        "mcp_servers.denylist_url_patterns": "",
        "hooks.severity": "warn",
        "hooks.allowlist_commands": "",
        "hooks.deny_unknown": "1",
    }
    yaml_text = form_to_yaml(form, current_revision=4)
    assert "revision: 5" in yaml_text
