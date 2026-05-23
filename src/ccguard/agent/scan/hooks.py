"""Извлечение хуков из settings.json."""

from __future__ import annotations

from typing import Any, get_args

from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import HookEntry
from ccguard.schemas.inventory import HookEntry as _HookEntry

# Перечень допустимых событий — берём из Literal схемы.
_KNOWN_EVENTS = set(get_args(_HookEntry.model_fields["event"].annotation))


def _extract_one(event: str, matcher: str | None, spec: dict[str, Any], source: str) -> HookEntry | None:
    htype = spec.get("type")
    if htype not in {"command", "http", "mcp_tool", "prompt", "agent"}:
        return None
    return HookEntry(
        event=event,  # type: ignore[arg-type]
        matcher=matcher,
        type=htype,  # type: ignore[arg-type]
        command=spec.get("command"),
        url=spec.get("url"),
        timeout_sec=spec.get("timeout"),
        source=source,
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
