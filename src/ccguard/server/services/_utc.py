"""SQLite datetime helpers shared across services.

SQLite stores ``DATETIME`` as ISO strings without timezone info. SQLModel
reads them back as naive ``datetime`` instances even though we wrote tz-aware
values. Comparing naive vs aware raises ``TypeError`` — every reader that
touches DB-stored timestamps has to coerce defensively.

Use :func:`aware_utc` whenever you read a datetime back from the ORM and
plan to compare or arithmetic-op it against ``datetime.now(UTC)``.
"""
from __future__ import annotations

from datetime import UTC, datetime


def aware_utc(dt: datetime) -> datetime:
    """Coerce a possibly-naive datetime to tz-aware UTC.

    Idempotent: tz-aware inputs are returned unchanged. Naive inputs are
    treated as UTC (which is correct for everything we write — we always
    persist UTC via ``datetime.now(UTC)`` or pydantic's UTC-enforcement).
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
