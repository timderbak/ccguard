"""scan_cursor_rules + extract_from_cursor_mcp_json + run_scan_cursor.

Cursor — второй агент на фундаменте agent_kind (только видимость). Проверяем, что
сканер находит все документированные носители правил Cursor, MCP-обёртка ложится
на существующий парсер (remote url→http даром), а runner собирает Cursor-инвентарь
с пустыми Claude-полями.
"""
from __future__ import annotations

from pathlib import Path

from ccguard.agent.scan.cursor_rules import scan_cursor_rules
from ccguard.agent.scan.mcp import extract_from_cursor_mcp_json
from ccguard.agent.scan.runner import run_scan_cursor


def _mk(p: Path, text: str = "x") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# --- scan_cursor_rules -----------------------------------------------------


def test_finds_mdc_rules(tmp_path: Path):
    _mk(tmp_path / ".cursor" / "rules" / "style.mdc", "---\nalwaysApply: true\n---\nUse tabs")
    out = scan_cursor_rules(tmp_path)
    assert len(out) == 1
    assert out[0].scope == "cursor_rules"
    assert out[0].content_hash
    assert Path(out[0].path).name == "style.mdc"


def test_finds_rule_md_folder_format(tmp_path: Path):
    _mk(tmp_path / ".cursor" / "rules" / "db" / "RULE.md", "db rules")
    out = scan_cursor_rules(tmp_path)
    assert any(p.scope == "cursor_rules" and Path(p.path).name == "RULE.md" for p in out)


def test_finds_nested_cursor_rules(tmp_path: Path):
    # Вложенный .cursor/rules/ в подкаталоге проекта.
    _mk(tmp_path / "backend" / ".cursor" / "rules" / "api.mdc", "api rules")
    out = scan_cursor_rules(tmp_path)
    assert any("backend" in p.path and p.scope == "cursor_rules" for p in out)


def test_finds_legacy_cursorrules_and_agents_md(tmp_path: Path):
    _mk(tmp_path / ".cursorrules", "legacy")
    _mk(tmp_path / "AGENTS.md", "agents")
    _mk(tmp_path / "svc" / "AGENTS.md", "nested agents")
    out = scan_cursor_rules(tmp_path)
    scopes = {p.scope for p in out}
    assert "cursor_legacy" in scopes
    assert "agents_md" in scopes
    assert sum(1 for p in out if p.scope == "agents_md") == 2  # root + nested


def test_skips_vendored_dirs(tmp_path: Path):
    _mk(tmp_path / "node_modules" / "pkg" / ".cursor" / "rules" / "x.mdc", "vendored")
    _mk(tmp_path / "node_modules" / "pkg" / "AGENTS.md", "vendored agents")
    assert scan_cursor_rules(tmp_path) == []


def test_no_content_only_hash(tmp_path: Path):
    _mk(tmp_path / ".cursorrules", "secret internal instructions")
    out = scan_cursor_rules(tmp_path)
    # Содержимое НЕ утекает в MemoryEntry — только hash/size.
    dumped = out[0].model_dump()
    assert "secret" not in str(dumped)
    assert set(dumped) == {"path", "scope", "content_hash", "size_bytes", "imported_by"}


def test_empty_project_is_empty(tmp_path: Path):
    assert scan_cursor_rules(tmp_path) == []


# --- extract_from_cursor_mcp_json ------------------------------------------


def test_cursor_mcp_project_and_user(tmp_path: Path):
    proj = tmp_path / "proj"
    home = tmp_path / "cursorhome"
    _mk(proj / ".cursor" / "mcp.json",
        '{"mcpServers": {"remote": {"url": "https://mcp.x.io/sse"}, "local": {"command": "node", "args": ["s.js"]}}}')
    _mk(home / "mcp.json", '{"mcpServers": {"userwide": {"url": "https://u.io"}}}')
    out = extract_from_cursor_mcp_json(proj, home)
    by_name = {s.name: s for s in out}
    assert by_name["remote"].transport == "http"   # url без type → http даром
    assert by_name["remote"].scope == "project"
    assert by_name["local"].transport == "stdio"
    assert by_name["userwide"].scope == "user"


def test_cursor_mcp_absent_is_empty(tmp_path: Path):
    assert extract_from_cursor_mcp_json(tmp_path / "p", tmp_path / "h") == []


# --- run_scan_cursor -------------------------------------------------------


def test_run_scan_cursor_leaves_claude_fields_empty(tmp_path: Path):
    proj = tmp_path / "proj"
    _mk(proj / ".cursorrules", "rules")
    _mk(proj / ".cursor" / "mcp.json", '{"mcpServers": {"r": {"url": "https://x.io"}}}')
    inv = run_scan_cursor(
        cursor_home=tmp_path / "h", project_dir=proj, machine_id="m", machine_label="l",
    )
    assert inv.agent_kind == "cursor"
    assert inv.mcp_servers and inv.memory_files
    # Claude-специфичные поля осознанно пусты (нет энфорсера/аудита у Cursor).
    assert inv.hooks == [] and inv.skills == [] and inv.agents == [] and inv.commands == []
    assert inv.sandbox is None and inv.auto_memory == [] and inv.settings_sources == []
