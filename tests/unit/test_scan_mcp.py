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


def test_user_mcp_json(tmp_path: Path) -> None:
    """~/.claude/.mcp.json — per-user глобальный конфиг."""
    from ccguard.agent.scan.mcp import extract_from_user_mcp_json

    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    (claude_home / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"n8n": {"command": "npx", "args": ["-y", "supergateway"]}}})
    )
    servers = extract_from_user_mcp_json(claude_home)
    assert len(servers) == 1
    assert servers[0].name == "n8n"
    assert servers[0].source.endswith(".claude/.mcp.json")


def test_claude_json_top_level_and_projects(tmp_path: Path) -> None:
    """~/.claude.json: top-level mcpServers + projects[<path>].mcpServers."""
    from ccguard.agent.scan.mcp import extract_from_claude_json

    cj = tmp_path / ".claude.json"
    cj.write_text(
        json.dumps(
            {
                "mcpServers": {"airtable": {"command": "npx", "args": ["airtable-mcp"]}},
                "projects": {
                    "/Users/x/dev/Sales": {
                        "mcpServers": {"airtable": {"command": "npx", "args": ["airtable-mcp"]}}
                    },
                    "/Users/x/dev/Other": {
                        "mcpServers": {"shell": {"command": "/usr/bin/false"}}
                    },
                },
            }
        )
    )
    servers = extract_from_claude_json(cj)
    assert {s.name for s in servers} == {"airtable", "shell"}
    sources = {s.source for s in servers}
    assert any(":mcpServers" in s for s in sources)
    assert any(":projects[/Users/x/dev/Sales]" in s for s in sources)
    assert any(":projects[/Users/x/dev/Other]" in s for s in sources)


def test_claude_json_missing(tmp_path: Path) -> None:
    from ccguard.agent.scan.mcp import extract_from_claude_json

    assert extract_from_claude_json(tmp_path / "nope.json") == []


def test_claude_json_malformed(tmp_path: Path) -> None:
    from ccguard.agent.scan.mcp import extract_from_claude_json

    cj = tmp_path / ".claude.json"
    cj.write_text("not json {{{")
    assert extract_from_claude_json(cj) == []


def test_args_with_jwt_are_masked(tmp_path: Path) -> None:
    """JWT-токен в args MCP-сервера должен быть замаскирован до попадания в inventory."""
    f = tmp_path / "settings.json"
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    f.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "n8n": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "supergateway",
                            "--header",
                            f"authorization:Bearer {jwt}",
                        ],
                    }
                }
            }
        )
    )
    parsed = parse_settings_file(f, "user")
    servers = extract_from_settings([parsed])
    payload = servers[0].model_dump_json()
    assert "eyJh" not in payload
    assert "MASKED" in payload
