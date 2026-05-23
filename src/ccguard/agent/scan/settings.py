"""Парсинг settings.json Claude Code из всех scope'ов."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ccguard.schemas import SettingsSource

Scope = Literal["user", "project", "project_local", "managed"]


@dataclass
class ParsedSettings:
    """Результат парсинга одного файла settings.json."""

    source: SettingsSource
    data: dict[str, Any] | None  # None если файла нет или битый


def _managed_paths() -> list[Path]:
    """Системные managed settings — зависят от ОС."""
    candidates: list[Path] = []
    # Linux/macOS
    candidates.append(Path("/etc/claude-code/managed-settings.json"))
    # macOS
    candidates.append(Path("/Library/Application Support/ClaudeCode/managed-settings.json"))
    return candidates


def discover_settings_files(claude_home: Path, project_dir: Path) -> list[tuple[Path, Scope]]:
    """Список (path, scope) для всех потенциальных источников settings.

    Поиск:
    - user: $CLAUDE_HOME/settings.json
    - project: <project>/.claude/settings.json
    - project_local: <project>/.claude/settings.local.json
    - managed: системные пути по платформе
    """
    files: list[tuple[Path, Scope]] = [
        (claude_home / "settings.json", "user"),
        (project_dir / ".claude" / "settings.json", "project"),
        (project_dir / ".claude" / "settings.local.json", "project_local"),
    ]
    for mp in _managed_paths():
        files.append((mp, "managed"))
    return files


def parse_settings_file(path: Path, scope: Scope) -> ParsedSettings:
    """Прочитать и распарсить один settings.json. Не бросает: на ошибках возвращает source.parse_error."""
    if not path.exists():
        return ParsedSettings(
            source=SettingsSource(path=str(path), scope=scope, exists=False),
            data=None,
        )
    try:
        raw = path.read_text()
        if not raw.strip():
            return ParsedSettings(
                source=SettingsSource(path=str(path), scope=scope, exists=True),
                data={},
            )
        data = json.loads(raw)
        if not isinstance(data, dict):
            return ParsedSettings(
                source=SettingsSource(
                    path=str(path),
                    scope=scope,
                    exists=True,
                    parse_error="top-level value is not an object",
                ),
                data=None,
            )
        return ParsedSettings(
            source=SettingsSource(path=str(path), scope=scope, exists=True),
            data=data,
        )
    except json.JSONDecodeError as e:
        return ParsedSettings(
            source=SettingsSource(
                path=str(path), scope=scope, exists=True, parse_error=f"json decode: {e}"
            ),
            data=None,
        )
    except OSError as e:
        return ParsedSettings(
            source=SettingsSource(
                path=str(path), scope=scope, exists=True, parse_error=f"read error: {e}"
            ),
            data=None,
        )


def parse_all(claude_home: Path, project_dir: Path) -> list[ParsedSettings]:
    return [parse_settings_file(p, s) for p, s in discover_settings_files(claude_home, project_dir)]


def detect_dangerously_skip(rc_files: list[Path] | None = None) -> bool:
    """Поиск алиасов / обёрток с --dangerously-skip-permissions в rc-файлах юзера."""
    if rc_files is None:
        home = Path(os.path.expanduser("~"))
        rc_files = [
            home / ".bashrc",
            home / ".zshrc",
            home / ".profile",
            home / ".bash_profile",
        ]
    needle = "--dangerously-skip-permissions"
    for rc in rc_files:
        if rc.exists():
            try:
                if needle in rc.read_text():
                    return True
            except OSError:
                continue
    return False
