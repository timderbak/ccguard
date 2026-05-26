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
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from ccguard.server.db.models import ScanResult

log = logging.getLogger(__name__)

ANOMALY_JOB_ID: str = "anomaly-tick"
FIRST_TICK_DELAY_SECONDS: int = 30
TICK_INTERVAL_HOURS: int = 1
RESCAN_ALL_JOB_ID: str = "llm-rescan-all"


def build_scheduler() -> AsyncIOScheduler:
    """Return a configured AsyncIOScheduler pinned to UTC."""
    return AsyncIOScheduler(timezone="UTC")


def start_scheduler(
    scheduler: AsyncIOScheduler,
    tick_callable: Callable[..., object],
) -> None:
    """Register the anomaly tick and start the scheduler.

    First run is scheduled at ``now(UTC) + 30s`` so devs get fast feedback;
    subsequent runs follow the hourly interval. ``coalesce=True`` and
    ``max_instances=1`` ensure missed runs collapse and ticks never overlap.

    ``tick_callable`` may be a sync or async callable; an async callable is
    awaited by AsyncIOScheduler on the event loop. Production wraps the
    blocking SQL tick in ``asyncio.to_thread`` (see ``main._lifespan``) so the
    loop stays responsive during sweeps (WR-05).
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


# --- Plan 03-05: global re-scan-all one-shot job ---------------------------


def rescan_all_files(engine: Engine) -> None:
    """Expire every ScanResult row's TTL so the next agent inventory cycle
    repopulates the cache (D-03: server never stores content).

    Idempotent — running concurrently is safe; rows just get pushed further
    into the past. Phase 2 anomaly tick path is unaffected.
    """
    now_expired = datetime.now(UTC) - timedelta(seconds=1)
    with Session(engine) as s:
        rows = list(s.exec(select(ScanResult)))
        for row in rows:
            row.ttl_expires_at = now_expired
            s.add(row)
        s.commit()
    log.info("llm rescan-all: expired %d ScanResult rows", len(rows))


def enqueue_rescan_all(scheduler: AsyncIOScheduler, engine: Engine) -> None:
    """Enqueue a one-shot APScheduler job that expires every ScanResult TTL.

    Uses ``DateTrigger(run_date=now)`` so the job fires as soon as the
    scheduler's event loop picks it up (typically next tick). When the
    scheduler is disabled (tests, CCGUARD_DISABLE_SCHEDULER=1) the job is
    executed synchronously in-process so admin UI flows still behave end-to-end
    and integration tests do not need to spin up the real scheduler.
    """
    if scheduler is None or not scheduler.running:
        # Test / disabled-scheduler path: run inline so the UI's 303-then-GET
        # cycle observes a consistent post-state.
        rescan_all_files(engine)
        return
    scheduler.add_job(
        rescan_all_files,
        trigger=DateTrigger(run_date=datetime.now(UTC)),
        args=[engine],
        id=RESCAN_ALL_JOB_ID,
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
