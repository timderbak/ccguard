"""Scheduler wiring — the dedicated fast sensor-silence sweep (C1, part 2).

The full correlation tick runs hourly; that is too slow for a dead-man switch
(detecting that the agent went silent). A separate job sweeps sensor health on a
fast cadence so suppression is noticed in ~1 minute, not ~1 hour.
"""
from __future__ import annotations


class _FakeScheduler:
    """Records add_job calls without an event loop (APScheduler lifecycle-free)."""

    def __init__(self) -> None:
        self.jobs: list[dict] = []

    def add_job(self, fn, **kwargs) -> None:  # type: ignore[no-untyped-def]
        self.jobs.append({"fn": fn, **kwargs})


def test_register_sensor_sweep_uses_fast_interval() -> None:
    from ccguard.server.scheduler import (
        SENSOR_SWEEP_INTERVAL_SECONDS,
        SENSOR_SWEEP_JOB_ID,
        register_sensor_sweep,
    )

    fake = _FakeScheduler()
    register_sensor_sweep(fake, lambda: None)

    assert len(fake.jobs) == 1
    job = fake.jobs[0]
    assert job["id"] == SENSOR_SWEEP_JOB_ID
    # Fast cadence — well under the hourly correlation tick.
    assert SENSOR_SWEEP_INTERVAL_SECONDS <= 120
    assert job["trigger"].interval.total_seconds() == SENSOR_SWEEP_INTERVAL_SECONDS
    # Never overlap / collapse missed runs.
    assert job["max_instances"] == 1
    assert job["coalesce"] is True
