"""MCP-серверы: extract_from_settings."""

from __future__ import annotations

import json
from pathlib import Path

from ccguard.agent.scan.mcp import extract_from_mcp_json, extract_from_settings
from ccguard.agent.scan.settings import parse_settings_file


def test_stdio_extracted(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                        "env": {"FS_ROOT": "/tmp", "SECRET_TOKEN": "shhh"},
                    }
                }
            }
        )
    )
    parsed = parse_settings_file(f, "user")
    servers = extract_from_settings([parsed])
    assert len(servers) == 1
    s = servers[0]
    assert s.name == "fs"
    assert s.transport == "stdio"
    assert s.command == "npx"
    assert s.args == ["-y", "@modelcontextprotocol/server-filesystem"]
    # Значения env НЕ должны попасть, только имена ключей.
    assert set(s.env_keys) == {"FS_ROOT", "SECRET_TOKEN"}
    assert "shhh" not in s.model_dump_json()


def test_http_extracted(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text(
        json.dumps(
            {"mcpServers": {"remote": {"url": "https://mcp.example.com/v1", "type": "http"}}}
        )
    )
    parsed = parse_settings_file(f, "user")
    servers = extract_from_settings([parsed])
    assert servers[0].transport == "http"
    assert servers[0].url == "https://mcp.example.com/v1"


def test_sse_extracted(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text(
        json.dumps({"mcpServers": {"sse": {"url": "https://x.example.com/sse", "type": "sse"}}})
    )
    parsed = parse_settings_file(f, "user")
    servers = extract_from_settings([parsed])
    assert servers[0].transport == "sse"


def test_no_mcp_section(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"permissions": {}}))
    parsed = parse_settings_file(f, "user")
    assert extract_from_settings([parsed]) == []


def test_dot_mcp_json(tmp_path: Path) -> None:
    proj = tmp_path
    (proj / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"fs2": {"command": "node", "args": ["server.js"]}}})
    )
    servers = extract_from_mcp_json(proj)
    assert len(servers) == 1
    assert servers[0].name == "fs2"
