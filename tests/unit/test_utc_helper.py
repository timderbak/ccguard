"""aware_utc helper: idempotent, treats naive as UTC."""
from __future__ import annotations

from datetime import UTC, datetime, timezone

from ccguard.server.services._utc import aware_utc


def test_naive_datetime_becomes_utc():
    naive = datetime(2026, 5, 30, 12, 0, 0)
    coerced = aware_utc(naive)
    assert coerced.tzinfo is UTC
    assert coerced == datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)


def test_already_aware_returns_unchanged():
    aware = datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)
    assert aware_utc(aware) is aware


def test_non_utc_aware_preserves_offset():
    """We don't convert offsets — caller's responsibility if it matters."""
    tz_plus_three = timezone.utcoffset.__class__  # noqa: unused
    msk = timezone(__import__("datetime").timedelta(hours=3))
    aware = datetime(2026, 5, 30, 15, 0, 0, tzinfo=msk)
    assert aware_utc(aware) is aware
    assert aware_utc(aware).tzinfo is msk
