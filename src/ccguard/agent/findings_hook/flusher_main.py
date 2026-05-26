"""Entrypoint for the findings flusher (PI-01).

Invoked as ``python -m ccguard.agent.findings_hook.flusher_main`` from a cron
job, systemd timer, or the agent's opportunistic sync path. Oneshot mode —
makes one flush pass and exits, matching the audit_hook pattern.

Fail-silent on the EXIT-CODE contract: any exception inside ``flush()``
still returns 0 so an upstream cron wrapper never alarms on transient
network glitches; persistent failures show up as growing ``retry_count``
in the local buffer (and ultimately DLQ-mark themselves). WR-04: but
the exception is now logged to stderr (with class name + repr) so
``cron`` / ``systemd``-managed log files capture engine-level bugs
that never reach the retry loop (e.g. sqlite corruption, missing config
dir). Without this, a silent failure was invisible across the fleet.
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from ccguard.agent.findings_hook.flusher import flush

        flush()
    except Exception as exc:
        # WR-04: surface to stderr so cron/systemd captures it. We still
        # return 0 to keep the exit-code contract (cron must not alarm).
        print(
            f"ccguard.findings_hook.flusher_main: {type(exc).__name__}: {exc!r}",
            file=sys.stderr,
        )
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
