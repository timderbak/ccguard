"""MCP-merge tests for ccguard.agent.push_install._merge_mcp_servers."""

from __future__ import annotations

from ccguard.agent.push_install import _merge_mcp_servers


def test_removes_existing_managed_entries() -> None:
    existing = {
        "mcpServers": {
            "user-tool": {"command": "u"},
            "old-managed": {"_managed_by": "ccguard", "command": "x"},
        }
    }
    required = [{"name": "new-managed", "command": "y"}]
    out = _merge_mcp_servers(existing, required)
    assert "user-tool" in out["mcpServers"]
    assert out["mcpServers"]["user-tool"] == {"command": "u"}
    assert "old-managed" not in out["mcpServers"]
    assert "new-managed" in out["mcpServers"]
    assert out["mcpServers"]["new-managed"]["_managed_by"] == "ccguard"
    assert out["mcpServers"]["new-managed"]["command"] == "y"


def test_does_not_remove_user_entry_with_ccguard_prefix() -> None:
    """D-7: identify by `_managed_by` field, NOT by key prefix."""
    existing = {
        "mcpServers": {
            "ccguard-pretender": {"command": "innocent"},  # NO _managed_by
        }
    }
    out = _merge_mcp_servers(existing, [])
    assert "ccguard-pretender" in out["mcpServers"]
    assert out["mcpServers"]["ccguard-pretender"] == {"command": "innocent"}


def test_required_injects_managed_by_marker() -> None:
    out = _merge_mcp_servers({"mcpServers": {}}, [{"name": "x", "command": "c"}])
    assert out["mcpServers"]["x"]["_managed_by"] == "ccguard"


def test_required_preserves_extra_fields() -> None:
    out = _merge_mcp_servers(
        {"mcpServers": {}},
        [{"name": "x", "command": "c", "args": ["a", "b"], "env": {"K": "V"}}],
    )
    entry = out["mcpServers"]["x"]
    assert entry["command"] == "c"
    assert entry["args"] == ["a", "b"]
    assert entry["env"] == {"K": "V"}
    assert "name" not in entry  # name is the key, not a field


def test_missing_mcp_servers_key_treated_as_empty() -> None:
    out = _merge_mcp_servers({}, [{"name": "x", "command": "c"}])
    assert "mcpServers" in out
    assert "x" in out["mcpServers"]


def test_preserves_other_top_level_fields() -> None:
    existing = {"someUserField": 42, "mcpServers": {}}
    out = _merge_mcp_servers(existing, [{"name": "x", "command": "c"}])
    assert out["someUserField"] == 42
