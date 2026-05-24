"""Извлечение плагинов / marketplace-источников.

Источники:
  * `~/.claude/settings.json → enabledPlugins` (dict[str, bool], ключ `name@marketplace`)
  * `~/.claude/plugins/installed_plugins.json` (dict[str, list[install]])
  * Legacy `settings.json → plugins | marketplaces` (старые форматы).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import PluginEntry

# Служебные подпапки в ~/.claude/plugins/, которые не являются плагинами.
_RESERVED_DIRS = {"cache", "data", "marketplaces"}


def _split_marketplace(key: str) -> tuple[str, str]:
    """`name@marketplace` → (name, marketplace). Если `@` нет — (key, "unknown")."""
    if "@" in key:
        name, _, mp = key.partition("@")
        return name, mp or "unknown"
    return key, "unknown"


def _from_settings_section(section: Any, source: str) -> list[PluginEntry]:
    """Поддерживаем три формата:
      * dict[str, bool]  — `enabledPlugins`, ключ `name@marketplace`;
      * list[dict]       — legacy список спецификаций;
      * dict[str, dict]  — legacy mapping name → spec.
    """
    out: list[PluginEntry] = []
    if isinstance(section, list):
        for item in section:
            if isinstance(item, dict) and "name" in item:
                out.append(
                    PluginEntry(
                        name=str(item["name"]),
                        source=str(item.get("source") or source),
                        enabled=bool(item.get("enabled", True)),
                    )
                )
    elif isinstance(section, dict):
        for key, spec in section.items():
            if isinstance(spec, bool):
                name, mp = _split_marketplace(str(key))
                out.append(PluginEntry(name=name, source=mp, enabled=spec))
            elif isinstance(spec, dict):
                out.append(
                    PluginEntry(
                        name=str(key),
                        source=str(spec.get("source") or source),
                        enabled=bool(spec.get("enabled", True)),
                    )
                )
    return out


def extract_from_settings(parsed_list: list[ParsedSettings]) -> list[PluginEntry]:
    out: list[PluginEntry] = []
    for p in parsed_list:
        if p.data is None:
            continue
        for key in ("plugins", "enabledPlugins", "marketplaces"):
            section = p.data.get(key)
            if section:
                out.extend(_from_settings_section(section, p.source.path))
    return out


def _read_installed_plugins(claude_home: Path) -> list[PluginEntry]:
    """Прочитать `~/.claude/plugins/installed_plugins.json`.

    Формат: {"plugins": {"name@marketplace": [{"scope":..., "installPath":...}, ...]}}.
    Один entry на каждую установку (scope/projectPath различаются).
    """
    f = claude_home / "plugins" / "installed_plugins.json"
    if not f.exists():
        return []
    try:
        data = json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    plugins = data.get("plugins") or {}
    if not isinstance(plugins, dict):
        return []
    out: list[PluginEntry] = []
    for key, installs in plugins.items():
        name, marketplace = _split_marketplace(str(key))
        if not isinstance(installs, list):
            continue
        for inst in installs:
            if not isinstance(inst, dict):
                continue
            install_path = str(inst.get("installPath") or marketplace)
            out.append(
                PluginEntry(
                    name=name,
                    source=install_path,
                    # «installed» ≠ «enabled»; реальный статус приходит из settings.enabledPlugins.
                    enabled=False,
                )
            )
    return out


def scan_local_plugins(claude_home: Path) -> list[PluginEntry]:
    """Найти установленные плагины. Приоритет: installed_plugins.json.

    Если файла нет — fallback на листинг `~/.claude/plugins/`, но
    исключая служебные подпапки (`cache`, `data`, `marketplaces`).
    """
    out = _read_installed_plugins(claude_home)
    if out:
        return out

    plugins_dir = claude_home / "plugins"
    if not plugins_dir.exists():
        return []
    for child in sorted(plugins_dir.iterdir()):
        if not child.is_dir() or child.name in _RESERVED_DIRS:
            continue
        out.append(PluginEntry(name=child.name, source=str(child), enabled=True))
    return out
