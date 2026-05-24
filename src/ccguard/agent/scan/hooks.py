"""Извлечение хуков из settings.json."""

from __future__ import annotations

import hashlib
import shlex
from pathlib import Path
from typing import Any, get_args

from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import HookEntry
from ccguard.schemas.inventory import HookEntry as _HookEntry

# Перечень допустимых событий — берём из Literal схемы.
_KNOWN_EVENTS = set(get_args(_HookEntry.model_fields["event"].annotation))


_SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".pl", ".php"}
_INTERPRETER_BASENAMES = {
    "node", "deno", "bun",
    "python", "python2", "python3",
    "bash", "sh", "zsh", "dash",
    "ruby", "perl", "php",
    "env", "/usr/bin/env",
}


def _looks_like_script(path: Path) -> bool:
    if path.suffix.lower() in _SCRIPT_EXTS:
        return True
    return path.name not in _INTERPRETER_BASENAMES


def _resolve_hook_script(command: str | None) -> tuple[str, str] | None:
    """По команде хука вернуть (file_path, sha256_hex), если она ссылается на скрипт.

    Эвристика: shlex-split, отдаём предпочтение токену с известным
    script-расширением (.sh, .js, .py, …) или просто файлу, имя которого
    не совпадает с известным интерпретатором (node/bash/python/…).
    """
    if not command:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    existing_files: list[Path] = []
    for tok in tokens:
        if not tok or not tok.startswith("/"):
            continue
        p = Path(tok)
        if p.is_file():
            existing_files.append(p)

    # 1) первый файл с явным script-расширением.
    for p in existing_files:
        if p.suffix.lower() in _SCRIPT_EXTS:
            chosen = p
            break
    else:
        # 2) первый файл, не похожий на интерпретатор.
        chosen = next((p for p in existing_files if _looks_like_script(p)), None)
        if chosen is None:
            return None

    try:
        h = hashlib.sha256(chosen.read_bytes()).hexdigest()
    except OSError:
        return None
    return (str(chosen), h)


def _extract_one(event: str, matcher: str | None, spec: dict[str, Any], source: str) -> HookEntry | None:
    htype = spec.get("type")
    if htype not in {"command", "http", "mcp_tool", "prompt", "agent"}:
        return None
    command = spec.get("command")
    file_path: str | None = None
    file_hash: str | None = None
    if isinstance(command, str):
        resolved = _resolve_hook_script(command)
        if resolved is not None:
            file_path, file_hash = resolved
    return HookEntry(
        event=event,  # type: ignore[arg-type]
        matcher=matcher,
        type=htype,  # type: ignore[arg-type]
        command=command,
        url=spec.get("url"),
        timeout_sec=spec.get("timeout"),
        source=source,
        command_file_path=file_path,
        command_file_hash=file_hash,
    )


def extract_from_settings(parsed_list: list[ParsedSettings]) -> list[HookEntry]:
    """Пройти все settings.json, извлечь hooks. Неизвестные события пропускаются."""
    out: list[HookEntry] = []
    for p in parsed_list:
        if p.data is None:
            continue
        hooks_section = p.data.get("hooks") or {}
        if not isinstance(hooks_section, dict):
            continue
        for event, entries in hooks_section.items():
            if event not in _KNOWN_EVENTS:
                continue
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                matcher = entry.get("matcher")
                hooks_list = entry.get("hooks") or []
                if not isinstance(hooks_list, list):
                    continue
                for h in hooks_list:
                    if isinstance(h, dict):
                        hook_entry = _extract_one(event, matcher, h, p.source.path)
                        if hook_entry:
                            out.append(hook_entry)
    return out


def detect_disable_all_hooks(parsed_list: list[ParsedSettings]) -> bool:
    """Любой settings.json с disableAllHooks=true → True."""
    for p in parsed_list:
        if p.data is None:
            continue
        if p.data.get("disableAllHooks") is True:
            return True
    return False
