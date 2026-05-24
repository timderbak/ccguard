"""Композиция scan: собирает все парсеры в InventoryReport."""

from __future__ import annotations

import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from ccguard import __version__
from ccguard.agent.scan import agents as scan_agents
from ccguard.agent.scan import commands as scan_commands
from ccguard.agent.scan import hooks as scan_hooks
from ccguard.agent.scan import mcp as scan_mcp
from ccguard.agent.scan import permissions as scan_perms
from ccguard.agent.scan import plugins as scan_plugins
from ccguard.agent.scan import settings as scan_settings
from ccguard.agent.scan import skills as scan_skills
from ccguard.schemas import InventoryReport


def _extract_env_keys(parsed_list: list[scan_settings.ParsedSettings]) -> list[str]:
    """Имена ENV-переменных из settings.json (только ключи, не значения)."""
    seen: set[str] = set()
    out: list[str] = []
    for p in parsed_list:
        if p.data is None:
            continue
        env = p.data.get("env")
        if not isinstance(env, dict):
            continue
        for k in env.keys():
            ks = str(k)
            if ks not in seen:
                seen.add(ks)
                out.append(ks)
    return out


def _detect_os() -> Literal["linux", "macos", "windows", "other"]:
    name = platform.system().lower()
    if name == "linux":
        return "linux"
    if name == "darwin":
        return "macos"
    if name == "windows":
        return "windows"
    return "other"


def run_scan(claude_home: Path, project_dir: Path, machine_id: str, machine_label: str | None) -> InventoryReport:
    parsed = scan_settings.parse_all(claude_home, project_dir)

    mcp_servers = scan_mcp.extract_from_settings(parsed)
    mcp_servers.extend(scan_mcp.extract_from_mcp_json(project_dir))
    mcp_servers.extend(scan_mcp.extract_from_user_mcp_json(claude_home))
    mcp_servers.extend(scan_mcp.extract_from_claude_json(claude_home.parent / ".claude.json"))

    return InventoryReport(
        machine_id=machine_id,
        machine_label=machine_label,
        timestamp=datetime.now(UTC),
        agent_version=__version__,
        os=_detect_os(),
        settings_sources=[p.source for p in parsed],
        mcp_servers=mcp_servers,
        skills=scan_skills.scan_all_skills(claude_home),
        hooks=scan_hooks.extract_from_settings(parsed),
        plugins=scan_plugins.extract_from_settings(parsed)
        + scan_plugins.scan_local_plugins(claude_home),
        permissions=scan_perms.extract(parsed),
        agents=scan_agents.scan_agents(claude_home),
        commands=scan_commands.scan_commands(claude_home),
        env_keys=_extract_env_keys(parsed),
        claude_code_version=None,
    )
