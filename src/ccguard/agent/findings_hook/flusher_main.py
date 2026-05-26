"""Entrypoint for the findings flusher (PI-01).

Invoked as ``python -m ccguard.agent.findings_hook.flusher_main`` from a cron
job, systemd timer, or the agent's opportunistic sync path. Oneshot mode —
makes one flush pass and exits, matching the audit_hook pattern.

Fail-silent: any exception inside ``flush()`` returns 0 so an upstream cron
wrapper never alarms on transient network glitches; persistent failures show
up as growing ``retry_count`` in the local buffer (and ultimately
DLQ-mark themselves).
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from ccguard.agent.findings_hook.flusher import flush

        flush()
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
