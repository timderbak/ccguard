"""Detect the shell user running the agent (Per-User Attribution).

Privacy: this returns a username (``alice``) not a UID, never a hostname or
PII. Capped at 64 chars to bound the field in the wire schema. Always
fail-open — never raises into the hot path.

Order of fallback:
1. ``USER`` env (POSIX shells)
2. ``LOGNAME`` env (older POSIX)
3. ``USERNAME`` env (Windows)
4. ``os.getlogin()`` (last resort; can raise on detached/CI sessions)
5. ``None`` (event ingested with no actor attribution)
"""
from __future__ import annotations

import os

_MAX_LEN = 64


def _clean(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    return s[:_MAX_LEN]


def detect_actor_user() -> str | None:
    """Return the current shell user or None.

    Fail-open: any exception in ``os.getlogin`` returns None — never lets the
    hot path crash on attribution.
    """
    for env_key in ("USER", "LOGNAME", "USERNAME"):
        cleaned = _clean(os.environ.get(env_key))
        if cleaned is not None:
            return cleaned
    try:
        return _clean(os.getlogin())
    except Exception:  # noqa: BLE001 — os.getlogin on detached tty raises OSError
        return None
