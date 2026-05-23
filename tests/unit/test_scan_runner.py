"""Полный scan: интеграция всех парсеров в InventoryReport."""

from __future__ import annotations

import json
from pathlib import Path

from ccguard.agent.scan import run_scan


def test_full_scan_assembles_report(tmp_path: Path) -> None:
    claude_home = tmp_path / "claude"
    project_dir = tmp_path / "proj"
    claude_home.mkdir()
    project_dir.mkdir()
    (project_dir / ".claude").mkdir()

    # user-уровень settings.json — один MCP + один hook + permissions
    (claude_home / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {"allow": ["Bash(git *)"], "deny": [], "ask": []},
                "mcpServers": {
                    "filesystem": {"command": "npx", "args": ["x"], "env": {"FS_ROOT": "/"}}
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "/bin/true"}],
                        }
                    ]
                },
            }
        )
    )

    # project-уровень — другой MCP, другие permissions
    (project_dir / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {"allow": [], "deny": ["Bash(rm -rf /)"], "ask": []},
                "mcpServers": {"memory": {"command": "node", "args": ["mem.js"]}},
            }
        )
    )

    # local-уровень — битый JSON (parse_error)
    (project_dir / ".claude" / "settings.local.json").write_text("{broken")

    # один скилл
    skills_dir = claude_home / "skills" / "my-skill"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("# my-skill\n")

    report = run_scan(claude_home, project_dir, machine_id="mid-test", machine_label=None)

    assert report.machine_id == "mid-test"
    assert report.os in ("linux", "macos", "windows", "other")

    # У нас в discovery 5 кандидатов: user, project, project_local, и 2 managed
    paths = [s.path for s in report.settings_sources]
    assert any("/claude/settings.json" in p for p in paths)
    assert any(".claude/settings.json" in p for p in paths)

    # parse_error на local
    local = next(
        s for s in report.settings_sources if s.path.endswith("settings.local.json")
    )
    assert local.parse_error is not None

    # MCP-серверы — два разных
    names = {m.name for m in report.mcp_servers}
    assert names == {"filesystem", "memory"}
    assert all("FS_ROOT" not in m.model_dump_json() or "FS_ROOT" in m.env_keys for m in report.mcp_servers)

    # hooks — один из user-уровня
    assert len(report.hooks) == 1
    assert report.hooks[0].event == "PreToolUse"

    # skills
    assert len(report.skills) == 1
    assert report.skills[0].name == "my-skill"

    # permissions агрегируются
    assert "Bash(git *)" in report.permissions.allow
    assert "Bash(rm -rf /)" in report.permissions.deny
