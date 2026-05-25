"""APScheduler integration for the ccguard anomaly tick (Plan 02-03).

Thin factory + lifecycle helpers over :class:`AsyncIOScheduler`. The scheduler
lives inside the FastAPI event loop (registered in ``main._lifespan``) and runs
the per-machine anomaly evaluation hourly, with a 30-second first-tick so
developers see output shortly after server boot.

Test-safety: the FastAPI lifespan checks :func:`is_disabled` before starting
the scheduler. Setting ``CCGUARD_DISABLE_SCHEDULER=1`` (done unconditionally
in ``tests/conftest.py``) keeps ``TestClient`` from booting the scheduler
thread — otherwise the in-process AsyncIOScheduler would race with the test
event loop and occasionally hang teardown.

Locked config choices (per plan 02-03):

* ``timezone="UTC"``  — finding dedup keys on the UTC date.
* ``IntervalTrigger(hours=1)`` — first tick at ``now + 30s``, hourly afterward.
* ``coalesce=True`` + ``max_instances=1`` — if the host is slow / sleeping, we
  collapse missed runs into one and never overlap ticks.
* ``shutdown(wait=False)`` — never block FastAPI shutdown on a running tick.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)

ANOMALY_JOB_ID: str = "anomaly-tick"
FIRST_TICK_DELAY_SECONDS: int = 30
TICK_INTERVAL_HOURS: int = 1


def build_scheduler() -> AsyncIOScheduler:
    """Return a configured AsyncIOScheduler pinned to UTC."""
    return AsyncIOScheduler(timezone="UTC")


def start_scheduler(
    scheduler: AsyncIOScheduler,
    tick_callable: Callable[[], None],
) -> None:
    """Register the anomaly tick and start the scheduler.

    First run is scheduled at ``now(UTC) + 30s`` so devs get fast feedback;
    subsequent runs follow the hourly interval. ``coalesce=True`` and
    ``max_instances=1`` ensure missed runs collapse and ticks never overlap.
    """
    next_run = datetime.now(UTC) + timedelta(seconds=FIRST_TICK_DELAY_SECONDS)
    scheduler.add_job(
        tick_callable,
        trigger=IntervalTrigger(hours=TICK_INTERVAL_HOURS),
        id=ANOMALY_JOB_ID,
        replace_existing=True,
        next_run_time=next_run,
        coalesce=True,
        max_instances=1,
    )
    scheduler.start()
    log.info(
        "anomaly scheduler started: first tick at %s UTC, interval %dh",
        next_run.isoformat(),
        TICK_INTERVAL_HOURS,
    )


async def shutdown_scheduler(scheduler: AsyncIOScheduler) -> None:
    """Stop the scheduler without waiting for an in-flight tick.

    Async signature to match FastAPI ``lifespan`` shutdown ergonomics; the
    underlying APScheduler call is synchronous but cheap.
    """
    scheduler.shutdown(wait=False)
    log.info("anomaly scheduler stopped")


def is_disabled() -> bool:
    """Return True iff ``CCGUARD_DISABLE_SCHEDULER`` is set to a truthy value."""
    return os.environ.get("CCGUARD_DISABLE_SCHEDULER", "").lower() in ("1", "true", "yes")
