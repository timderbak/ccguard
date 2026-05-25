"""Entrypoint for the detached flusher subprocess (subprocess fallback path).

When ``os.fork`` is unavailable (e.g. Windows in a hypothetical future port),
:func:`ccguard.agent.audit_hook.flusher.maybe_spawn_flusher` invokes this
module via ``python -m ccguard.agent.audit_hook.flusher_main``. The body is
wrapped in a swallow-all guard so a failing flusher never blocks Claude Code.
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from ccguard.agent.audit_hook.flusher import _run_flush_loop

        _run_flush_loop()
    except Exception:
        # Fail-silent: the flusher is a best-effort background task. Real
        # diagnostics live in the audit-log buffer state itself (rows pile up
        # if we can't drain them) and on the server side.
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
