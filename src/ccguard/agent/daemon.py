"""Background sync daemon for the agent.

The third process in the agent triad (alongside the PreToolUse enforce hook
and the PostToolUse audit hook). Runs as a long-lived OS service —
launchd on macOS, systemd-user on Linux — and keeps the server's view of
this machine fresh by periodically calling ``scan + sync`` even when
Claude Code isn't actively running.

Why a daemon instead of just a cron entry:
* Single process whose state we can observe (``daemon.state.json``)
* Survives across user logins, sleep/wake (OS handles restart policy)
* Honors a stop-event for tests + clean shutdown
* Centralized retry/backoff on transient network errors

The loop logic is pure (takes a ``do_sync`` callable + ``stop_event`` +
``state``) so it tests without any network, subprocess, or filesystem
touches. The ``main()`` wires the real ``perform_sync`` underneath.
"""
from __future__ import annotations

import json
import logging
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("ccguard.agent.daemon")


@dataclass(frozen=True)
class DaemonConfig:
    """Tunables for the loop. All in seconds, none in env-time."""

    interval_seconds: float = 900.0  # 15 minutes default
    retry_initial_seconds: float = 5.0
    retry_max_seconds: float = 60.0


@dataclass
class DaemonResult:
    """One sync attempt outcome — returned by the ``do_sync`` callable."""

    ok: bool
    error: str | None
    duration_ms: float


@dataclass
class DaemonState:
    """Mutable observability snapshot — written to ``daemon.state.json``."""

    sync_count: int = 0
    last_sync_at: datetime | None = None
    last_error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    consecutive_failures: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "sync_count": self.sync_count,
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "last_error": self.last_error,
            "started_at": self.started_at.isoformat(),
            "consecutive_failures": self.consecutive_failures,
        }

    def write_to(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self.to_dict(), ensure_ascii=False))
        except OSError:
            log.warning("daemon: failed to write state at %s", path)


SyncCallable = Callable[[], DaemonResult]


def _interruptible_sleep(seconds: float, stop_event: threading.Event) -> None:
    """Sleep up to ``seconds`` but break early when stop_event fires.

    ``Event.wait`` returns True on set, False on timeout — either way we exit
    quickly. Keeps shutdown latency under one tick regardless of interval.
    """
    stop_event.wait(timeout=seconds)


def run_loop(
    config: DaemonConfig,
    *,
    do_sync: SyncCallable,
    state: DaemonState,
    stop_event: threading.Event,
    state_path: Path | None = None,
) -> None:
    """Run the daemon loop until ``stop_event`` is set.

    Each iteration:
    1. Calls ``do_sync()`` — catches any exception so a buggy sync never
       crashes the daemon.
    2. Updates ``state`` (sync_count, last_sync_at, last_error,
       consecutive_failures).
    3. Persists state if ``state_path`` is provided.
    4. Sleeps until next interval — base ``interval_seconds`` on success,
       exponential backoff on failure (capped at ``retry_max_seconds``).
    """
    log.info("daemon: starting loop interval=%.1fs", config.interval_seconds)
    while not stop_event.is_set():
        try:
            result = do_sync()
        except Exception as exc:  # noqa: BLE001 — daemon must not crash
            result = DaemonResult(ok=False, error=f"unhandled: {exc!r}", duration_ms=0.0)

        state.sync_count += 1
        if result.ok:
            state.last_sync_at = datetime.now(UTC)
            state.last_error = None
            state.consecutive_failures = 0
            wait = config.interval_seconds
            log.info("daemon: sync ok (%.0fms), next in %.0fs",
                     result.duration_ms, wait)
        else:
            state.last_error = result.error
            state.consecutive_failures += 1
            # Exponential backoff bounded by retry_max_seconds.
            backoff = min(
                config.retry_initial_seconds * (2 ** (state.consecutive_failures - 1)),
                config.retry_max_seconds,
            )
            wait = backoff
            log.warning("daemon: sync failed (%s), retry in %.0fs (attempt %d)",
                        result.error, wait, state.consecutive_failures)

        if state_path is not None:
            state.write_to(state_path)

        _interruptible_sleep(wait, stop_event)

    log.info("daemon: stop_event received, loop exit")


# --- Production wiring ----------------------------------------------------


def _build_real_sync_callable(interval_seconds: float) -> SyncCallable:
    """Returns a ``do_sync`` that runs the real perform_sync + scan.

    ``interval_seconds`` is the daemon's actual loop cadence — threaded through
    so the per-cycle heartbeat reports a truthful ``expected_interval_sec`` to
    the server's silence detector (previously it read a non-existent
    ``cfg.interval_seconds`` and always sent ``None``).
    """
    import os as _os
    from pathlib import Path as _Path

    import yaml as _yaml

    from ccguard.agent.check import check_inventory
    from ccguard.agent.config import default_config_dir, load_or_create
    from ccguard.agent.machine_id import derive_machine_id
    from ccguard.agent.scan import run_scan
    from ccguard.agent.sync import perform_sync, sync_cursor_inventory
    from ccguard.schemas import Finding, Policy

    def _claude_home() -> _Path:
        return _Path(_os.environ.get("CCGUARD_CLAUDE_HOME", _Path.home() / ".claude"))

    def _cursor_home() -> _Path:
        return _Path(_os.environ.get("CCGUARD_CURSOR_HOME", _Path.home() / ".cursor"))

    def do_sync() -> DaemonResult:
        t0 = time.monotonic()
        try:
            cfg, _ = load_or_create()
            inv = run_scan(
                claude_home=_claude_home(),
                project_dir=_Path.cwd(),
                machine_id=derive_machine_id(cfg.install_salt),
                machine_label=cfg.machine_label,
            )
            cache = cfg.resolved_cache_path()
            findings: list[Finding] = []
            if cache.exists():
                try:
                    data = _yaml.safe_load(cache.read_text()) or {}
                    policy = Policy.model_validate(data)
                    findings = check_inventory(inv, policy)
                except Exception:  # noqa: BLE001
                    pass
            audit_path = default_config_dir() / "audit.log"
            audit_cursor_path = default_config_dir() / "audit.cursor"
            result = perform_sync(
                config=cfg,
                inventory=inv,
                findings=findings,
                audit_path=audit_path,
                audit_cursor_path=audit_cursor_path,
                policy_cache_path=cache,
            )
            # ТЗ-07: explicit heartbeat every cycle — sent even when the sync
            # carried nothing, so the server can tell idle-but-alive from dead.
            # Best-effort: a heartbeat failure never affects the sync result.
            _send_heartbeat_best_effort(cfg, inv.machine_id, interval_seconds)
            # P6: ship locally-buffered PI/Read findings on the same cycle.
            # Without this the findings_buffer.db never reaches the server in a
            # default install (no cron/systemd timer). Best-effort: a flush
            # failure never affects the sync result.
            _flush_findings_best_effort()
            # Мультиагентность: если на машине есть Cursor — отправить его
            # инвентарь отдельным machine_id. Best-effort и полностью изолирован:
            # ни отсутствие Cursor, ни сбой его sync не влияют на основной цикл.
            try:
                sync_cursor_inventory(
                    config=cfg, cursor_home=_cursor_home(), project_dir=_Path.cwd()
                )
            except Exception:  # noqa: BLE001
                pass
            dur_ms = (time.monotonic() - t0) * 1000.0
            if getattr(result, "error", None):
                return DaemonResult(ok=False, error=str(result.error), duration_ms=dur_ms)
            return DaemonResult(ok=True, error=None, duration_ms=dur_ms)
        except Exception as exc:  # noqa: BLE001
            dur_ms = (time.monotonic() - t0) * 1000.0
            return DaemonResult(ok=False, error=f"{type(exc).__name__}: {exc}", duration_ms=dur_ms)

    return do_sync


def _flush_findings_best_effort() -> None:
    """Ship any locally-buffered findings (PI/Read) to the server (P6).

    Mirrors the heartbeat best-effort contract: swallows every exception so a
    flush failure never affects the daemon sync result. The flusher itself
    handles retries/DLQ; this only guarantees the buffer is drained on each
    daemon cycle so findings are not stranded in a default install.
    """
    try:
        from ccguard.agent.findings_hook.flusher import flush

        flush()
    except Exception:  # noqa: BLE001
        pass


def _send_heartbeat_best_effort(cfg: object, machine_id: str, interval_seconds: float) -> None:
    """Fire one heartbeat with a self-integrity check. Swallows everything.

    ``interval_seconds`` is the daemon's real loop cadence; it is reported as
    ``expected_interval_sec`` so the server can size its silence grace window
    correctly (server clamps it to ``sensor.max_interval_sec``).
    """
    try:
        import os as _os
        from pathlib import Path as _Path

        from ccguard import __version__ as _ccguard_version
        from ccguard.agent import heartbeat as _hb

        settings_path = (
            _Path(_os.environ.get("CCGUARD_CLAUDE_HOME", _Path.home() / ".claude"))
            / "settings.json"
        )
        interval = int(interval_seconds) if interval_seconds and interval_seconds > 0 else None
        payload = _hb.build_heartbeat(
            machine_id=machine_id,
            agent_version=_ccguard_version,
            hooks_intact=_hb.check_hooks_intact(settings_path),
            expected_interval_sec=interval,
            hooks_hash=_hb.compute_hooks_hash(settings_path),
        )
        _hb.send_heartbeat(
            server_url=cfg.server.url, token=cfg.server.token, payload=payload
        )
    except Exception:  # noqa: BLE001 — heartbeat must never break the daemon
        pass


def main() -> int:
    """``ccguard-daemon`` entry point.

    Reads agent config, wires the real sync callable, registers SIGTERM/SIGINT
    handlers, and runs the loop until signalled.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    from ccguard.agent.config import default_config_dir, load_or_create

    # Loop cadence comes from config (sync.interval_minutes) so the daemon honors
    # it AND reports the same value in the heartbeat's expected_interval_sec.
    try:
        cfg, _ = load_or_create()
        interval_seconds = float(cfg.sync.interval_minutes * 60)
    except Exception:  # noqa: BLE001 — never let config errors stop the daemon
        interval_seconds = DaemonConfig().interval_seconds
    if interval_seconds <= 0:
        interval_seconds = DaemonConfig().interval_seconds

    state_path = default_config_dir() / "daemon.state.json"
    state = DaemonState()
    stop_event = threading.Event()

    def _on_signal(signum, _frame):
        log.info("daemon: caught signal %d, requesting stop", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    run_loop(
        DaemonConfig(interval_seconds=interval_seconds),
        do_sync=_build_real_sync_callable(interval_seconds),
        state=state,
        stop_event=stop_event,
        state_path=state_path,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
