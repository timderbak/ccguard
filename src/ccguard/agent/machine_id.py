"""Деривация стабильного псевдонима machine_id."""

from __future__ import annotations

import base64
import hashlib
import os
import platform
from pathlib import Path

_MACHINE_ID_CANDIDATES = [
    Path("/etc/machine-id"),
    Path("/var/lib/dbus/machine-id"),
]


def _read_raw_machine_id() -> str:
    for p in _MACHINE_ID_CANDIDATES:
        if p.exists():
            txt = p.read_text().strip()
            if txt:
                return txt
    return platform.node() or "unknown-host"


def derive_machine_id(
    install_salt: str, uid: int | None = None, agent_kind: str = "claude_code"
) -> str:
    """sha256(raw || uid || salt [|| agent_kind]), обрезано до 128 бит, base32 lower.

    ``agent_kind`` подмешивается в хеш ТОЛЬКО для НЕ-claude_code: так один хост
    даёт отдельную строку флота на каждый агент ((host, user, agent) — свой
    machine_id), а Cursor не «прыгает» поверх Claude-строки. Для claude_code
    материал хеша байт-в-байт прежний — иначе весь существующий флот
    перерегистрировался бы под новыми id.
    """
    raw = _read_raw_machine_id()
    effective_uid = uid if uid is not None else os.getuid()
    material = f"{raw}|{effective_uid}|{install_salt}"
    if agent_kind != "claude_code":
        material = f"{material}|{agent_kind}"
    digest = hashlib.sha256(material.encode()).digest()
    return base64.b32encode(digest[:16]).decode().rstrip("=").lower()
