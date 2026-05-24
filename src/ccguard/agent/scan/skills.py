"""Сканер скиллов: имя, путь, dir_hash, origin.

Поддерживаемые источники:
  * `~/.claude/skills/<name>/SKILL.md`             — local;
  * `<plugin_install_path>/skills/<name>/SKILL.md` — plugin (через
    `installed_plugins.json`, поле `installPath`).

Глубоко вложенные SKILL.md (`cli-tool/components/skills/...`, shadow-копии
для других AI-инструментов под `.cursor/`, `.gemini/` и т.п.) Claude Code
не загружает, поэтому не инвентаризируем.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from ccguard.schemas import SkillEntry

Origin = Literal["local", "marketplace", "plugin"]


def compute_dir_hash(directory: Path) -> str:
    """sha256 от отсортированного списка `relpath:sha256(content)` всех файлов в директории."""
    sha = hashlib.sha256()
    files = sorted(
        [p for p in directory.rglob("*") if p.is_file()],
        key=lambda p: str(p.relative_to(directory)),
    )
    for f in files:
        try:
            content = f.read_bytes()
        except OSError:
            continue
        rel = str(f.relative_to(directory)).replace("\\", "/")
        file_sha = hashlib.sha256(content).hexdigest()
        sha.update(f"{rel}:{file_sha}\n".encode())
    return sha.hexdigest()


def _scan_skills_dir(skills_dir: Path, origin: Origin) -> list[SkillEntry]:
    """Каждая поддиректория с SKILL.md = один скилл."""
    out: list[SkillEntry] = []
    if not skills_dir.exists() or not skills_dir.is_dir():
        return out
    for child in sorted(skills_dir.iterdir()):
        if not child.is_dir():
            continue
        skill_md = child / "SKILL.md"
        if not skill_md.exists():
            continue
        out.append(
            SkillEntry(
                name=child.name,
                path=str(child),
                origin=origin,
                dir_hash=compute_dir_hash(child),
                has_referenced_scripts=_has_scripts(child),
            )
        )
    return out


def _has_scripts(skill_dir: Path) -> bool:
    """Эвристика: в папке есть .py/.sh/.js/.ts кроме SKILL.md."""
    for ext in ("*.py", "*.sh", "*.js", "*.ts"):
        for _ in skill_dir.rglob(ext):
            return True
    return False


def _plugin_install_paths(claude_home: Path) -> list[Path]:
    """installPath'ы из installed_plugins.json."""
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
    paths: list[Path] = []
    seen: set[str] = set()
    for installs in plugins.values():
        if not isinstance(installs, list):
            continue
        for inst in installs:
            if not isinstance(inst, dict):
                continue
            p = inst.get("installPath")
            if isinstance(p, str) and p not in seen:
                paths.append(Path(p))
                seen.add(p)
    return paths


def scan_all_skills(claude_home: Path) -> list[SkillEntry]:
    """Local-скиллы из ~/.claude/skills/ + per-plugin-скиллы из installed_plugins.json."""
    out: list[SkillEntry] = []
    out.extend(_scan_skills_dir(claude_home / "skills", "local"))

    for plugin_root in _plugin_install_paths(claude_home):
        # Каждый плагин может выкладывать скиллы либо в `<root>/skills/`,
        # либо (старый формат) в `<root>/.claude/skills/`.
        out.extend(_scan_skills_dir(plugin_root / "skills", "plugin"))
        out.extend(_scan_skills_dir(plugin_root / ".claude" / "skills", "plugin"))
    return out
