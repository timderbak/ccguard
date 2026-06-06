"""Сканер кастомных субагентов.

Источники (v0.3):
  * `~/.claude/agents/<name>.md`                    — origin="local"
  * `<plugin_install_path>/agents/<name>.md`        — origin="plugin",
    parent_plugin/source_marketplace из installed_plugins.json
  * `<plugin_install_path>/.claude/agents/<name>.md` (legacy plugin layout)

Парсит YAML-frontmatter для извлечения `tools`, `model`, `description`.
Содержимое тела (промпт) не инвентаризируется — только хеш файла целиком.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Literal

import yaml

from ccguard.schemas import AgentEntry

Origin = Literal["local", "plugin"]

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_frontmatter(text: str) -> dict[str, Any]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _normalize_tools(value: Any) -> list[str] | None:
    """`tools` бывает строкой `"Read, Bash, Grep"` или списком."""
    if value is None:
        return None
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    return None


def _scan_agents_dir(
    agents_dir: Path,
    origin: Origin,
    *,
    parent_plugin: str | None = None,
    source_marketplace: str | None = None,
) -> list[AgentEntry]:
    if not agents_dir.exists() or not agents_dir.is_dir():
        return []
    out: list[AgentEntry] = []
    for p in sorted(agents_dir.glob("*.md")):
        try:
            text = p.read_text()
        except OSError:
            continue
        fm = _parse_frontmatter(text)
        name = str(fm.get("name") or p.stem)
        out.append(
            AgentEntry(
                name=name,
                path=str(p),
                file_hash=_file_hash(p),
                tools=_normalize_tools(fm.get("tools")),
                model=str(fm["model"]) if isinstance(fm.get("model"), str) else None,
                description=str(fm["description"])
                if isinstance(fm.get("description"), str)
                else None,
                origin=origin,
                parent_plugin=parent_plugin,
                source_marketplace=source_marketplace,
            )
        )
    return out


def scan_agents(claude_home: Path) -> list[AgentEntry]:
    """Local-агенты + plugin-bundled агенты.

    Plugin-агенты идентифицируются через ``plugins.plugin_install_index`` —
    тот же источник истины что и для скиллов.
    """
    from ccguard.agent.scan.plugins import plugin_install_index

    out: list[AgentEntry] = []
    out.extend(_scan_agents_dir(claude_home / "agents", "local"))

    for plugin_root, plugin_name, marketplace in plugin_install_index(claude_home):
        out.extend(_scan_agents_dir(
            plugin_root / "agents", "plugin",
            parent_plugin=plugin_name, source_marketplace=marketplace,
        ))
        out.extend(_scan_agents_dir(
            plugin_root / ".claude" / "agents", "plugin",
            parent_plugin=plugin_name, source_marketplace=marketplace,
        ))
    return out
