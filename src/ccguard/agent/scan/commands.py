"""Сканер кастомных slash-команд: `~/.claude/commands/[<ns>/]<name>.md`."""

from __future__ import annotations

import hashlib
from pathlib import Path

from ccguard.schemas import CommandEntry


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scan_commands(claude_home: Path) -> list[CommandEntry]:
    cmd_dir = claude_home / "commands"
    if not cmd_dir.exists() or not cmd_dir.is_dir():
        return []
    out: list[CommandEntry] = []
    for p in sorted(cmd_dir.rglob("*.md")):
        if not p.is_file():
            continue
        try:
            rel = p.relative_to(cmd_dir).with_suffix("")
        except ValueError:
            continue
        name = str(rel).replace("\\", "/")
        try:
            out.append(CommandEntry(name=name, path=str(p), file_hash=_file_hash(p)))
        except OSError:
            continue
    return out
