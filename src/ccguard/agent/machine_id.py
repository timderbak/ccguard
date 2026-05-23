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


def derive_machine_id(install_salt: str, uid: int | None = None) -> str:
    """sha256(raw || uid || salt), обрезано до 128 бит, base32 lower."""
    raw = _read_raw_machine_id()
    effective_uid = uid if uid is not None else os.getuid()
    digest = hashlib.sha256(
        f"{raw}|{effective_uid}|{install_salt}".encode()
    ).digest()
    return base64.b32encode(digest[:16]).decode().rstrip("=").lower()
