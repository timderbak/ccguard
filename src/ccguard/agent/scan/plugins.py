"""Извлечение плагинов / marketplace-источников."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import PluginEntry


def _from_settings_section(section: Any, source: str) -> list[PluginEntry]:
    """Поддерживаем форматы: список dict'ов или dict {name: spec}."""
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
        for name, spec in section.items():
            if not isinstance(spec, dict):
                continue
            out.append(
                PluginEntry(
                    name=str(name),
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


def scan_local_plugins(claude_home: Path) -> list[PluginEntry]:
    """Каталоги ~/.claude/plugins/<name>/ → энтри (если есть plugin.json или просто папка)."""
    out: list[PluginEntry] = []
    plugins_dir = claude_home / "plugins"
    if not plugins_dir.exists():
        return out
    for child in sorted(plugins_dir.iterdir()):
        if child.is_dir():
            out.append(
                PluginEntry(
                    name=child.name,
                    source=str(child),
                    enabled=True,
                )
            )
    return out
