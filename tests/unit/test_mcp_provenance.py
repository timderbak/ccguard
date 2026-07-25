"""Провенанс MCP-серверов: «откуда этот MCP взялся».

Две независимые оси:
  * scope  — где объявлен конфиг (managed = раскатала организация, user =
             поставил себе сам, project = лежит в git, project_local = локально);
  * origin — приехал ли вместе с плагином (+ имя плагина и маркетплейс).

Ключевой инвариант обратной совместимости: агент v0.1/v0.2 не шлёт эти поля,
и тогда строка должна помечаться «источник неизвестен», а не угадываться.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlmodel import Session, select

from ccguard.agent.scan import mcp as scan_mcp
from ccguard.agent.scan import settings as scan_settings
from ccguard.schemas import McpServerEntry
from ccguard.server.db.models import MCPServerBaseline
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import mcp_baseline_service as baseline_svc
from ccguard.server.services import mcp_fleet_service as fleet_svc


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _spec(name: str = "demo") -> dict:
    return {"mcpServers": {name: {"command": "npx", "args": ["-y", name]}}}


# --- агент: определение scope из каждого источника --------------------------


def test_user_settings_scope_is_user(tmp_path):
    claude_home = tmp_path / ".claude"
    project = tmp_path / "proj"
    project.mkdir()
    _write(claude_home / "settings.json", _spec("personal"))
    parsed = scan_settings.parse_all(claude_home, project)
    entries = scan_mcp.extract_from_settings(parsed)
    assert [e.scope for e in entries] == ["user"]
    assert entries[0].origin == "local"


def test_project_settings_scope_is_project(tmp_path):
    claude_home = tmp_path / ".claude"
    claude_home.mkdir(parents=True)
    project = tmp_path / "proj"
    _write(project / ".claude" / "settings.json", _spec("team"))
    parsed = scan_settings.parse_all(claude_home, project)
    entries = scan_mcp.extract_from_settings(parsed)
    assert [e.scope for e in entries] == ["project"]


def test_project_local_settings_scope(tmp_path):
    claude_home = tmp_path / ".claude"
    claude_home.mkdir(parents=True)
    project = tmp_path / "proj"
    _write(project / ".claude" / "settings.local.json", _spec("local-only"))
    parsed = scan_settings.parse_all(claude_home, project)
    entries = scan_mcp.extract_from_settings(parsed)
    assert [e.scope for e in entries] == ["project_local"]


def test_managed_settings_scope(tmp_path, monkeypatch):
    # managed-путь системный, поэтому подменяем список кандидатов.
    managed = tmp_path / "managed-settings.json"
    _write(managed, _spec("corp-approved"))
    monkeypatch.setattr(scan_settings, "_managed_paths", lambda: [managed])
    claude_home = tmp_path / ".claude"
    claude_home.mkdir(parents=True)
    project = tmp_path / "proj"
    project.mkdir()
    parsed = scan_settings.parse_all(claude_home, project)
    entries = scan_mcp.extract_from_settings(parsed)
    assert [e.scope for e in entries] == ["managed"]


def test_project_mcp_json_scope_is_project(tmp_path):
    project = tmp_path / "proj"
    _write(project / ".mcp.json", _spec("repo-mcp"))
    entries = scan_mcp.extract_from_mcp_json(project)
    assert [e.scope for e in entries] == ["project"]


def test_user_mcp_json_scope_is_user(tmp_path):
    claude_home = tmp_path / ".claude"
    _write(claude_home / ".mcp.json", _spec("global-mcp"))
    entries = scan_mcp.extract_from_user_mcp_json(claude_home)
    assert [e.scope for e in entries] == ["user"]


def test_claude_json_scopes_are_user(tmp_path):
    # ~/.claude.json — персональный файл, поэтому и top-level, и projects[]
    # считаются user («поставил себе сам»), даже если привязаны к проекту.
    cj = tmp_path / ".claude.json"
    _write(cj, {
        "mcpServers": {"top": {"command": "npx", "args": []}},
        "projects": {"/home/dev/x": {"mcpServers": {"scoped": {"command": "npx", "args": []}}}},
    })
    entries = scan_mcp.extract_from_claude_json(cj)
    assert {e.name: e.scope for e in entries} == {"top": "user", "scoped": "user"}


# --- агент: привязка к плагину ----------------------------------------------


def _install_plugin(claude_home: Path, plugin: str, marketplace: str, rel: str, mcp_name: str):
    install_path = claude_home / "plugins" / "cache" / plugin
    _write(install_path / rel, _spec(mcp_name))
    _write(claude_home / "plugins" / "installed_plugins.json", {
        "plugins": {f"{plugin}@{marketplace}": [
            {"scope": "user", "installPath": str(install_path)}
        ]}
    })


def test_plugin_shipped_mcp_gets_attribution(tmp_path):
    claude_home = tmp_path / ".claude"
    _install_plugin(
        claude_home, "claude-mem", "anthropics/claude-plugins-official",
        ".mcp.json", "mem-mcp",
    )
    entries = scan_mcp.extract_from_plugins(claude_home)
    assert len(entries) == 1
    e = entries[0]
    assert e.name == "mem-mcp"
    assert e.origin == "plugin"
    assert e.parent_plugin == "claude-mem"
    assert e.source_marketplace == "anthropics/claude-plugins-official"


def test_plugin_mcp_found_in_claude_plugin_manifest(tmp_path):
    # Часть плагинов кладёт mcpServers в .claude-plugin/plugin.json.
    claude_home = tmp_path / ".claude"
    _install_plugin(
        claude_home, "toolkit", "acme/plugins",
        ".claude-plugin/plugin.json", "toolkit-mcp",
    )
    entries = scan_mcp.extract_from_plugins(claude_home)
    assert [e.name for e in entries] == ["toolkit-mcp"]
    assert entries[0].parent_plugin == "toolkit"


def test_plugin_mcp_deduped_across_candidate_paths(tmp_path):
    # Один и тот же MCP лежит и в .mcp.json, и в манифесте — не дублируем.
    claude_home = tmp_path / ".claude"
    install_path = claude_home / "plugins" / "cache" / "dup"
    _write(install_path / ".mcp.json", _spec("same-mcp"))
    _write(install_path / ".claude-plugin" / "plugin.json", _spec("same-mcp"))
    _write(claude_home / "plugins" / "installed_plugins.json", {
        "plugins": {"dup@acme/plugins": [{"scope": "user", "installPath": str(install_path)}]}
    })
    entries = scan_mcp.extract_from_plugins(claude_home)
    assert [e.name for e in entries] == ["same-mcp"]


def test_marketplace_missing_yields_unknown(tmp_path):
    claude_home = tmp_path / ".claude"
    _install_plugin(claude_home, "solo", "", ".mcp.json", "solo-mcp")
    # ключ без '@' → marketplace='unknown' (та же логика, что у skills/agents)
    _write(claude_home / "plugins" / "installed_plugins.json", {
        "plugins": {"solo": [
            {"scope": "user", "installPath": str(claude_home / "plugins" / "cache" / "solo")}
        ]}
    })
    entries = scan_mcp.extract_from_plugins(claude_home)
    assert entries[0].source_marketplace == "unknown"


def test_no_plugins_installed_yields_empty(tmp_path):
    claude_home = tmp_path / ".claude"
    claude_home.mkdir(parents=True)
    assert scan_mcp.extract_from_plugins(claude_home) == []


# --- сервер: сохранение провенанса ------------------------------------------


def _entry(name="notion", scope=None, origin="local", plugin=None, marketplace=None, source="/cfg"):
    from ccguard.agent.scan.mcp import _definition_text, _hash_text

    return McpServerEntry(
        name=name, transport="stdio", command="npx", args=["-y", name], url=None,
        env_keys=[], source=source, description="d",
        description_hash=_hash_text("d"),
        definition_hash=_hash_text(_definition_text("npx", ["-y", name], None)),
        tools_hash=None,
        scope=scope, origin=origin,
        parent_plugin=plugin, source_marketplace=marketplace,
    )


def test_provenance_persisted_on_first_sight():
    eng = _engine()
    with Session(eng) as s:
        baseline_svc.update_and_detect(s, "m1", [
            _entry("mem", scope="user", origin="plugin",
                   plugin="claude-mem", marketplace="anthropics/official",
                   source="plugin:claude-mem@anthropics/official:.mcp.json")
        ])
        s.commit()
        row = s.exec(select(MCPServerBaseline)).one()
        assert row.scope == "user"
        assert row.origin == "plugin"
        assert row.parent_plugin == "claude-mem"
        assert row.source_marketplace == "anthropics/official"
        assert row.source_path.startswith("plugin:claude-mem@")


def test_provenance_updates_when_mcp_moves_config():
    # Сервер переехал из личного конфига в managed — это должно отразиться.
    eng = _engine()
    with Session(eng) as s:
        baseline_svc.update_and_detect(s, "m1", [_entry("x", scope="user")])
        s.commit()
        baseline_svc.update_and_detect(s, "m1", [_entry("x", scope="managed", source="/etc/managed.json")])
        s.commit()
        row = s.exec(select(MCPServerBaseline)).one()
        assert row.scope == "managed"
        assert row.source_path == "/etc/managed.json"


def test_old_agent_without_provenance_does_not_blank_existing():
    # Агент v0.1 не шлёт scope — уже записанный источник затираться не должен.
    eng = _engine()
    with Session(eng) as s:
        baseline_svc.update_and_detect(s, "m1", [_entry("x", scope="managed")])
        s.commit()
        legacy = _entry("x")  # scope=None, как у старого агента
        legacy.scope = None
        baseline_svc.update_and_detect(s, "m1", [legacy])
        s.commit()
        row = s.exec(select(MCPServerBaseline)).one()
        assert row.scope == "managed"


def test_missing_provenance_stays_none():
    eng = _engine()
    with Session(eng) as s:
        e = _entry("x")
        e.scope = None
        baseline_svc.update_and_detect(s, "m1", [e])
        s.commit()
        row = s.exec(select(MCPServerBaseline)).one()
        assert row.scope is None
        assert row.origin == "local"


# --- агрегация по флоту ------------------------------------------------------


def test_fleet_summary_exposes_plugin_label():
    eng = _engine()
    with Session(eng) as s:
        baseline_svc.update_and_detect(s, "m1", [
            _entry("mem", scope="user", origin="plugin",
                   plugin="claude-mem", marketplace="anthropics/official")
        ])
        s.commit()
        row = fleet_svc.aggregate_mcp_servers(s)[0]
        assert row.from_plugin
        assert row.plugin_label == "claude-mem@anthropics/official"


def test_primary_scope_surfaces_least_sanctioned():
    # managed на двух машинах, но на третьей кто-то добавил вручную → показываем
    # именно 'user', иначе самодеятельность спрячется за «организация».
    eng = _engine()
    with Session(eng) as s:
        baseline_svc.update_and_detect(s, "m1", [_entry("x", scope="managed")])
        baseline_svc.update_and_detect(s, "m2", [_entry("x", scope="managed")])
        baseline_svc.update_and_detect(s, "m3", [_entry("x", scope="user")])
        s.commit()
        row = fleet_svc.aggregate_mcp_servers(s)[0]
        assert row.primary_scope == "user"
        assert row.scope_is_mixed
        assert row.scopes == {"managed": 2, "user": 1}


def test_uniform_scope_is_not_mixed():
    eng = _engine()
    with Session(eng) as s:
        baseline_svc.update_and_detect(s, "m1", [_entry("x", scope="managed")])
        baseline_svc.update_and_detect(s, "m2", [_entry("x", scope="managed")])
        s.commit()
        row = fleet_svc.aggregate_mcp_servers(s)[0]
        assert row.primary_scope == "managed"
        assert not row.scope_is_mixed


def test_unknown_provenance_has_no_primary_scope():
    eng = _engine()
    with Session(eng) as s:
        e = _entry("x")
        e.scope = None
        baseline_svc.update_and_detect(s, "m1", [e])
        s.commit()
        row = fleet_svc.aggregate_mcp_servers(s)[0]
        assert row.primary_scope is None
        assert not row.from_plugin
        assert row.plugin_label is None


def test_drill_down_exposes_source_path():
    eng = _engine()
    with Session(eng) as s:
        baseline_svc.update_and_detect(s, "m1", [
            _entry("x", scope="project", source="/repo/.mcp.json")
        ])
        s.commit()
        drill = fleet_svc.machines_for_mcp(s, "x")
        assert drill[0]["scope"] == "project"
        assert drill[0]["source_path"] == "/repo/.mcp.json"
