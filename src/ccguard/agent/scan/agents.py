"""Сканер кастомных субагентов: `~/.claude/agents/<name>.md`.

Парсит YAML-frontmatter для извлечения `tools`, `model`, `description`.
Содержимое тела (промпт) не инвентаризируется — только хеш файла целиком.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

from ccguard.schemas import AgentEntry

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


def scan_agents(claude_home: Path) -> list[AgentEntry]:
    agents_dir = claude_home / "agents"
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
            )
        )
    return out
