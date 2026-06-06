"""Agent-side heartbeat (ТЗ-07): explicit "I'm alive" ping + self-integrity.

Sent on the daemon cadence even when inventory/audit are empty, so the server
can tell an idle-but-alive sensor from a dead one. The self-check reports
whether the ccguard hook is still installed in settings.json — if someone strips
the hook but the daemon is still running, the server learns about it.

Best-effort: ``send_heartbeat`` never raises (a heartbeat failure must not crash
the daemon).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_HTTP_TIMEOUT_S = 10.0


def check_hooks_intact(settings_path: Path) -> bool | None:
    """Is the ccguard hook still wired into ``settings.json``?

    Returns True if a ccguard command hook is present, False if the file is
    readable but contains no ccguard hook, None if it can't be determined
    (missing/unreadable/malformed) — None must NOT be read as removal.
    """
    try:
        if not settings_path.exists():
            return None
        data = json.loads(settings_path.read_text())
    except Exception:  # noqa: BLE001 — unknown, not "removed"
        return None
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return False
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            for h in (entry.get("hooks", []) if isinstance(entry, dict) else []):
                cmd = h.get("command", "") if isinstance(h, dict) else ""
                if isinstance(cmd, str) and "ccguard" in cmd:
                    return True
    return False


def build_heartbeat(
    *,
    machine_id: str,
    agent_version: str | None,
    hooks_intact: bool | None,
    expected_interval_sec: int | None,
) -> dict[str, Any]:
    """Build the heartbeat payload — liveness metadata only, never raw activity."""
    return {
        "machine_id": machine_id,
        "agent_version": agent_version,
        "hooks_intact": hooks_intact,
        "expected_interval_sec": expected_interval_sec,
    }


def send_heartbeat(*, server_url: str, token: str, payload: dict[str, Any]) -> bool:
    """POST the heartbeat. Returns True on 2xx, False on any failure (never raises)."""
    import httpx

    url = f"{server_url.rstrip('/')}/api/v1/heartbeat"
    headers = {"X-CCGuard-Token": token, "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_S) as client:
            resp = client.post(url, content=json.dumps(payload), headers=headers)
        return 200 <= resp.status_code < 300
    except Exception as exc:  # noqa: BLE001 — heartbeat is best-effort
        log.debug("heartbeat send failed: %r", exc)
        return False
