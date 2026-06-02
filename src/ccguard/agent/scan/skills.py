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


def _scan_skills_dir(
    skills_dir: Path,
    origin: Origin,
    *,
    parent_plugin: str | None = None,
    source_marketplace: str | None = None,
) -> list[SkillEntry]:
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
                parent_plugin=parent_plugin,
                source_marketplace=source_marketplace,
            )
        )
    return out


def _has_scripts(skill_dir: Path) -> bool:
    """Эвристика: в папке есть .py/.sh/.js/.ts кроме SKILL.md."""
    for ext in ("*.py", "*.sh", "*.js", "*.ts"):
        for _ in skill_dir.rglob(ext):
            return True
    return False


def scan_all_skills(claude_home: Path) -> list[SkillEntry]:
    """Local-скиллы из ~/.claude/skills/ + per-plugin-скиллы из installed_plugins.json.

    Скиллы из плагинов получают parent_plugin/source_marketplace из
    installed_plugins.json (см. ``plugins.plugin_install_index``); local
    оставляет оба None.
    """
    from ccguard.agent.scan.plugins import plugin_install_index

    out: list[SkillEntry] = []
    out.extend(_scan_skills_dir(claude_home / "skills", "local"))

    for plugin_root, plugin_name, marketplace in plugin_install_index(claude_home):
        # Каждый плагин может выкладывать скиллы либо в `<root>/skills/`,
        # либо (старый формат) в `<root>/.claude/skills/`.
        out.extend(_scan_skills_dir(
            plugin_root / "skills", "plugin",
            parent_plugin=plugin_name, source_marketplace=marketplace,
        ))
        out.extend(_scan_skills_dir(
            plugin_root / ".claude" / "skills", "plugin",
            parent_plugin=plugin_name, source_marketplace=marketplace,
        ))
    return out
