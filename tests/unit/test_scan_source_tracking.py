"""skills + agents scanner: source tracking via installed_plugins.json."""

from __future__ import annotations

import json
from pathlib import Path

from ccguard.agent.scan.agents import scan_agents
from ccguard.agent.scan.skills import scan_all_skills


def _seed_plugin(claude_home: Path, plugin_key: str, install_path: Path) -> None:
    """Write installed_plugins.json mapping plugin_key → install_path."""
    install_path.mkdir(parents=True, exist_ok=True)
    pj = claude_home / "plugins" / "installed_plugins.json"
    pj.parent.mkdir(parents=True, exist_ok=True)
    data = {"plugins": {plugin_key: [{"installPath": str(install_path), "scope": "user"}]}}
    pj.write_text(json.dumps(data))


def _seed_skill(parent_dir: Path, name: str, body: str = "skill body\n") -> None:
    skill_dir = parent_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(f"---\nname: {name}\n---\n{body}")


def _seed_agent(parent_dir: Path, name: str, tools: str = "Read") -> None:
    parent_dir.mkdir(parents=True, exist_ok=True)
    (parent_dir / f"{name}.md").write_text(
        f"---\nname: {name}\ntools: {tools}\n---\nAgent prompt body."
    )


def test_local_skill_has_no_parent_plugin(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _seed_skill(home / "skills", "my-local-skill")
    skills = scan_all_skills(home)
    assert len(skills) == 1
    s = skills[0]
    assert s.origin == "local"
    assert s.parent_plugin is None
    assert s.source_marketplace is None


def test_plugin_skill_carries_parent_plugin_and_marketplace(tmp_path: Path) -> None:
    home = tmp_path / "home"
    install = tmp_path / "plugin-install"
    _seed_plugin(home, "claude-mem@anthropics/claude-plugins-official", install)
    _seed_skill(install / "skills", "mem-skill")

    skills = scan_all_skills(home)
    assert len(skills) == 1
    s = skills[0]
    assert s.origin == "plugin"
    assert s.parent_plugin == "claude-mem"
    assert s.source_marketplace == "anthropics/claude-plugins-official"


def test_local_agent_default_origin_and_no_parent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _seed_agent(home / "agents", "my-agent")
    agents = scan_agents(home)
    assert len(agents) == 1
    a = agents[0]
    assert a.origin == "local"
    assert a.parent_plugin is None
    assert a.source_marketplace is None


def test_plugin_bundled_agent_is_discovered_and_attributed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    install = tmp_path / "ctx-install"
    _seed_plugin(home, "context-mode@anthropics/claude-plugins-official", install)
    _seed_agent(install / "agents", "ctx-helper", tools="Read, Write")

    agents = scan_agents(home)
    assert len(agents) == 1
    a = agents[0]
    assert a.origin == "plugin"
    assert a.parent_plugin == "context-mode"
    assert a.source_marketplace == "anthropics/claude-plugins-official"
    assert a.tools == ["Read", "Write"]


def test_plugin_install_without_marketplace_key_is_unknown(tmp_path: Path) -> None:
    """Если ключ без '@' — marketplace='unknown' (граничный случай)."""
    home = tmp_path / "home"
    install = tmp_path / "legacy-install"
    _seed_plugin(home, "legacy-plugin", install)  # без '@marketplace'
    _seed_skill(install / "skills", "legacy-skill")

    skills = scan_all_skills(home)
    assert len(skills) == 1
    assert skills[0].parent_plugin == "legacy-plugin"
    assert skills[0].source_marketplace == "unknown"
