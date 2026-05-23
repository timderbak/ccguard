"""Извлечение блока permissions из settings.json + детект dangerously-skip."""

from __future__ import annotations

from ccguard.agent.scan.settings import ParsedSettings, detect_dangerously_skip
from ccguard.schemas import PermissionsSnapshot


def extract(parsed_list: list[ParsedSettings]) -> PermissionsSnapshot:
    allow: list[str] = []
    deny: list[str] = []
    ask: list[str] = []
    for p in parsed_list:
        if p.data is None:
            continue
        perms = p.data.get("permissions") or {}
        if not isinstance(perms, dict):
            continue
        if isinstance(perms.get("allow"), list):
            allow.extend(str(x) for x in perms["allow"])
        if isinstance(perms.get("deny"), list):
            deny.extend(str(x) for x in perms["deny"])
        if isinstance(perms.get("ask"), list):
            ask.extend(str(x) for x in perms["ask"])
    return PermissionsSnapshot(
        allow=allow,
        deny=deny,
        ask=ask,
        dangerously_skip_detected=detect_dangerously_skip(),
    )
