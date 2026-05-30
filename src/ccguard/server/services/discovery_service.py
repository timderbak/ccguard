"""Discovery orchestrator (Rule Discovery Agent · E3).

Drives the source monitors → LLM drafter → ProposedSignal pipeline. Designed
to be cheap (once-per-day gate, dedup-before-LLM) and isolation-safe (one bad
monitor doesn't kill the sweep, one bad LLM response is logged but doesn't
stop the queue).

Wired into the existing tick chain in ``server/main.py`` lifespan after
:func:`sequence_service.tick`. Skip-by-default via :func:`should_run` so the
expensive monitor HTTP fetches only happen once a day, not every 5 minutes.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import SourceFetchLog
from ccguard.server.services import proposed_signal_service, signal_drafter
from ccguard.server.services.settings_service import get_setting, set_setting
from ccguard.server.services.source_monitors.base import SourceItem, SourceMonitor

log = logging.getLogger(__name__)

_LAST_RUN_KEY = "discovery.last_run_at"


def should_run(session: Session, *, now: datetime, min_interval_hours: float = 23.0) -> bool:
    """True if the daily discovery sweep hasn't run in ``min_interval_hours``.

    23h default rather than 24 so the cron drift doesn't push us past a full
    calendar day. Treats unparseable / missing values as "go".
    """
    raw = get_setting(session, _LAST_RUN_KEY)
    if not raw:
        return True
    try:
        last = datetime.fromisoformat(raw)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return (now - last) >= timedelta(hours=min_interval_hours)


def _already_fetched(session: Session, url: str) -> bool:
    stmt = select(SourceFetchLog.id).where(SourceFetchLog.item_url == url).limit(1)
    return session.exec(stmt).first() is not None


def _log_fetch(
    session: Session,
    *,
    monitor_name: str,
    url: str,
    proposed_signal_id: int | None,
) -> None:
    session.add(
        SourceFetchLog(
            monitor_name=monitor_name,
            item_url=url,
            proposed_signal_id=proposed_signal_id,
        )
    )
    session.commit()


def _since_for_monitor(session: Session, monitor_name: str) -> datetime:
    """Latest ``fetched_at`` for this monitor, or 30 days back on first run."""
    stmt = (
        select(SourceFetchLog.fetched_at)
        .where(SourceFetchLog.monitor_name == monitor_name)
        .order_by(SourceFetchLog.fetched_at.desc())  # type: ignore[attr-defined]
        .limit(1)
    )
    last = session.exec(stmt).first()
    if last is not None:
        return last if last.tzinfo else last.replace(tzinfo=UTC)
    return datetime.now(UTC) - timedelta(days=30)


def tick(
    session: Session,
    *,
    drafter: signal_drafter.SignalDrafterProtocol,
    monitors: list[SourceMonitor],
) -> dict[str, Any]:
    """One discovery sweep. Returns a summary dict.

    Idempotent across sweeps thanks to SourceFetchLog. A monitor raising is
    caught and reported; the rest still run. A drafter error logs the URL
    (so we don't retry the same bad item) but doesn't propose anything.
    A BudgetExhausted aborts the sweep early without logging the unprocessed
    items, so the next run-after-budget-reset picks them up.
    """
    items_seen = 0
    deduped = 0
    proposed = 0
    drafter_errors = 0
    budget_exhausted = False
    monitor_errors: dict[str, str] = {}

    for m in monitors:
        try:
            since = _since_for_monitor(session, m.name)
            items: list[SourceItem] = m.poll(since)
        except Exception as exc:  # noqa: BLE001 — boundary isolation by design
            monitor_errors[m.name] = str(exc)
            log.warning("discovery: monitor %s failed: %s", m.name, exc)
            continue

        for item in items:
            items_seen += 1
            if _already_fetched(session, item.url):
                deduped += 1
                continue
            try:
                row = signal_drafter.draft_signal_from_text(
                    session,
                    drafter=drafter,
                    threat_text=item.text,
                    source_kind=m.name,
                    source_url=item.url,
                    source_title=item.title,
                )
                _log_fetch(session, monitor_name=m.name, url=item.url, proposed_signal_id=row.id)
                proposed += 1
            except signal_drafter.BudgetExhausted:
                budget_exhausted = True
                log.warning("discovery: budget exhausted — pausing sweep")
                break
            except signal_drafter.DrafterError as exc:
                drafter_errors += 1
                log.warning("discovery: drafter error for %s: %s", item.url, exc)
                _log_fetch(session, monitor_name=m.name, url=item.url, proposed_signal_id=None)
            except proposed_signal_service.InvalidDraft as exc:
                drafter_errors += 1
                log.warning("discovery: invalid draft for %s: %s", item.url, exc)
                _log_fetch(session, monitor_name=m.name, url=item.url, proposed_signal_id=None)
        if budget_exhausted:
            break

    set_setting(session, _LAST_RUN_KEY, datetime.now(UTC).isoformat())

    return {
        "items_seen": items_seen,
        "deduped": deduped,
        "proposed": proposed,
        "drafter_errors": drafter_errors,
        "budget_exhausted": budget_exhausted,
        "monitor_errors": monitor_errors,
    }
