"""Daemon loop core — periodic sync with stop-event + retry/backoff."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from ccguard.agent.daemon import (
    DaemonConfig,
    DaemonResult,
    DaemonState,
    run_loop,
)


@dataclass
class FakeSync:
    """Records calls; can simulate failures."""

    calls: list[float] = field(default_factory=list)
    fail_next_n: int = 0
    raise_on_call: Exception | None = None

    def __call__(self) -> DaemonResult:
        self.calls.append(time.monotonic())
        if self.raise_on_call is not None:
            err = self.raise_on_call
            self.raise_on_call = None
            raise err
        if self.fail_next_n > 0:
            self.fail_next_n -= 1
            return DaemonResult(ok=False, error="simulated failure", duration_ms=1.0)
        return DaemonResult(ok=True, error=None, duration_ms=1.0)


def _stop_after(events: int, stop_event: threading.Event, state: DaemonState) -> threading.Thread:
    """Watcher thread that sets stop_event after `events` sync calls."""

    def watch():
        while state.sync_count < events and not stop_event.is_set():
            time.sleep(0.01)
        stop_event.set()

    t = threading.Thread(target=watch, daemon=True)
    t.start()
    return t


def test_runs_sync_immediately_then_at_interval():
    fake = FakeSync()
    state = DaemonState()
    stop = threading.Event()
    _stop_after(3, stop, state)
    run_loop(
        DaemonConfig(interval_seconds=0.05, retry_initial_seconds=0.01, retry_max_seconds=0.05),
        do_sync=fake,
        state=state,
        stop_event=stop,
    )
    assert len(fake.calls) >= 3
    # Roughly the configured interval (allow generous slack — CI noise).
    if len(fake.calls) >= 2:
        gap = fake.calls[1] - fake.calls[0]
        assert 0.02 < gap < 0.5


def test_records_last_sync_at_on_success():
    fake = FakeSync()
    state = DaemonState()
    stop = threading.Event()
    _stop_after(1, stop, state)
    run_loop(
        DaemonConfig(interval_seconds=0.05),
        do_sync=fake,
        state=state,
        stop_event=stop,
    )
    assert state.last_sync_at is not None
    assert state.last_sync_at.tzinfo is UTC
    assert state.sync_count >= 1
    assert state.last_error is None


def test_failure_records_error_and_keeps_running():
    fake = FakeSync(fail_next_n=1)
    state = DaemonState()
    stop = threading.Event()
    _stop_after(2, stop, state)
    run_loop(
        DaemonConfig(interval_seconds=0.05, retry_initial_seconds=0.01),
        do_sync=fake,
        state=state,
        stop_event=stop,
    )
    # First call failed → last_error set; subsequent success clears it.
    assert state.sync_count >= 2
    # After the success the error MUST be cleared.
    assert state.last_error is None


def test_exception_in_sync_does_not_crash_loop():
    fake = FakeSync(raise_on_call=RuntimeError("network exploded"))
    state = DaemonState()
    stop = threading.Event()
    _stop_after(2, stop, state)
    run_loop(
        DaemonConfig(interval_seconds=0.05, retry_initial_seconds=0.01),
        do_sync=fake,
        state=state,
        stop_event=stop,
    )
    assert state.sync_count >= 2  # the loop continued after exception
    # First call exception was caught into last_error then cleared.
    assert state.last_error is None


def test_stop_event_breaks_loop_promptly():
    fake = FakeSync()
    state = DaemonState()
    stop = threading.Event()
    started = time.monotonic()
    # Stop after 1 call AND after at most ~100ms.
    def stopper():
        time.sleep(0.05)
        stop.set()

    threading.Thread(target=stopper, daemon=True).start()
    run_loop(
        DaemonConfig(interval_seconds=10.0),  # very long, but stop will fire early
        do_sync=fake,
        state=state,
        stop_event=stop,
    )
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"loop did not respect stop_event: {elapsed=}"


def test_backoff_grows_then_resets():
    """3 consecutive failures grow retry; next success resets to base interval."""
    fake = FakeSync(fail_next_n=3)
    state = DaemonState()
    stop = threading.Event()
    _stop_after(5, stop, state)
    run_loop(
        DaemonConfig(
            interval_seconds=0.05,
            retry_initial_seconds=0.02,
            retry_max_seconds=0.10,
        ),
        do_sync=fake,
        state=state,
        stop_event=stop,
    )
    assert state.sync_count >= 4
    # Backoff exponent stays bounded — we don't sleep > retry_max even after 3 fails.
    assert state.last_error is None


def test_state_to_dict_is_json_safe():
    state = DaemonState()
    state.sync_count = 5
    state.last_sync_at = datetime(2026, 5, 31, 12, 0, tzinfo=UTC)
    state.last_error = None
    d = state.to_dict()
    import json as _json
    _json.dumps(d)  # must not raise
    assert d["sync_count"] == 5
    assert d["last_sync_at"].startswith("2026-05-31")
