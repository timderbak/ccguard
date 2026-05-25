"""Unit tests for ToolUseEvent service layer (list_events + timeline_buckets) — TUA-02."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlmodel import Session

from ccguard.server.db.models import ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.tool_use_service import (
    _TIMEFRAMES,
    list_events,
    timeline_buckets,
)


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _ev(*, machine_id="laptop-1", ts=None, tool_name="Bash",
        fingerprint="0123456789abcdef", decision="allow",
        result_status="success") -> ToolUseEvent:
    return ToolUseEvent(
        machine_id=machine_id,
        ts=ts or datetime.now(UTC),
        tool_name=tool_name,
        fingerprint=fingerprint,
        decision=decision,
        result_status=result_status,
    )


def _seed(session: Session, events: list[ToolUseEvent]) -> None:
    for e in events:
        session.add(e)
    session.commit()


# -------------------------- list_events --------------------------

def test_list_events_empty_table() -> None:
    engine = _engine()
    with Session(engine) as s:
        rows, total = list_events(s)
        assert rows == []
        assert total == 0


def test_list_events_default_returns_all_recent() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed(s, [_ev(ts=now - timedelta(minutes=i)) for i in range(5)])
        rows, total = list_events(s)
        assert len(rows) == 5
        assert total == 5


def test_list_events_machine_id_like_filter() -> None:
    engine = _engine()
    with Session(engine) as s:
        _seed(s, [
            _ev(machine_id="laptop-A"),
            _ev(machine_id="laptop-B"),
            _ev(machine_id="server-1"),
        ])
        rows, total = list_events(s, machine_id_like="laptop")
        assert total == 2
        assert all("laptop" in r.machine_id for r in rows)


def test_list_events_tool_name_exact_filter() -> None:
    engine = _engine()
    with Session(engine) as s:
        _seed(s, [
            _ev(tool_name="Bash"),
            _ev(tool_name="Bash"),
            _ev(tool_name="Read"),
        ])
        rows, total = list_events(s, tool_name="Bash")
        assert total == 2
        assert all(r.tool_name == "Bash" for r in rows)


def test_list_events_decision_filter() -> None:
    engine = _engine()
    with Session(engine) as s:
        _seed(s, [
            _ev(decision="allow"),
            _ev(decision="deny"),
            _ev(decision="allow"),
        ])
        rows, total = list_events(s, decision="allow")
        assert total == 2
        assert all(r.decision == "allow" for r in rows)


def test_list_events_timeframe_1h_excludes_older() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed(s, [
            _ev(ts=now - timedelta(minutes=30)),  # within 1h
            _ev(ts=now - timedelta(hours=2)),     # outside 1h
        ])
        rows, total = list_events(s, timeframe="1h")
        assert total == 1


def test_list_events_timeframe_24h_includes_all_within() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed(s, [
            _ev(ts=now - timedelta(hours=1)),
            _ev(ts=now - timedelta(hours=12)),
            _ev(ts=now - timedelta(hours=23)),
        ])
        rows, total = list_events(s, timeframe="24h")
        assert total == 3


def test_list_events_limit_enforced_but_total_full() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed(s, [_ev(ts=now - timedelta(seconds=i)) for i in range(10)])
        rows, total = list_events(s, limit=3)
        assert len(rows) == 3
        assert total == 10


def test_list_events_ordered_ts_desc() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed(s, [
            _ev(ts=now - timedelta(minutes=10), tool_name="old"),
            _ev(ts=now - timedelta(minutes=1),  tool_name="new"),
            _ev(ts=now - timedelta(minutes=5),  tool_name="mid"),
        ])
        rows, _ = list_events(s)
        names = [r.tool_name for r in rows]
        assert names == ["new", "mid", "old"]


def test_timeframes_constant() -> None:
    assert _TIMEFRAMES == {"1h": 1, "24h": 24, "7d": 168}


# -------------------------- timeline_buckets --------------------------

def test_timeline_empty_table_returns_24_zero_buckets() -> None:
    engine = _engine()
    with Session(engine) as s:
        buckets = timeline_buckets(s)
        assert len(buckets) == 24
        assert all(b["count"] == 0 for b in buckets)


def test_timeline_bucket_count_equals_hours_parameter() -> None:
    engine = _engine()
    with Session(engine) as s:
        for h in (1, 24, 48, 168):
            assert len(timeline_buckets(s, hours=h)) == h


def test_timeline_recent_hour_count() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        # 3 events in the current hour
        _seed(s, [
            _ev(ts=now),
            _ev(ts=now - timedelta(minutes=10)),
            _ev(ts=now - timedelta(minutes=30)),
        ])
        buckets = timeline_buckets(s)
        assert len(buckets) == 24
        # last bucket (newest) should be the current hour
        assert buckets[-1]["count"] == 3
        # all earlier buckets should be 0
        assert sum(b["count"] for b in buckets[:-1]) == 0


def test_timeline_filter_machine_id() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed(s, [
            _ev(ts=now, machine_id="laptop-A"),
            _ev(ts=now, machine_id="laptop-B"),
            _ev(ts=now, machine_id="server-X"),
        ])
        buckets = timeline_buckets(s, machine_id_like="laptop")
        assert sum(b["count"] for b in buckets) == 2


def test_timeline_filter_tool_and_decision() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed(s, [
            _ev(ts=now, tool_name="Bash", decision="allow"),
            _ev(ts=now, tool_name="Bash", decision="deny"),
            _ev(ts=now, tool_name="Read", decision="allow"),
        ])
        b1 = timeline_buckets(s, tool_name="Bash")
        assert sum(b["count"] for b in b1) == 2
        b2 = timeline_buckets(s, decision="deny")
        assert sum(b["count"] for b in b2) == 1


def test_timeline_hour_label_format() -> None:
    """hour_label format must be 'HH:MM DD.MM' to match UI-SPEC."""
    import re
    engine = _engine()
    with Session(engine) as s:
        buckets = timeline_buckets(s)
        pattern = re.compile(r"^\d{2}:\d{2} \d{2}\.\d{2}$")
        for b in buckets:
            assert pattern.match(b["hour_label"]), f"bad label: {b['hour_label']!r}"
            # minute must be 00 (hour-aligned)
            assert b["hour_label"].startswith(b["hour_label"][:3])
            assert b["hour_label"][3:5] == "00"


def test_timeline_buckets_oldest_first() -> None:
    engine = _engine()
    with Session(engine) as s:
        buckets = timeline_buckets(s, hours=5)
        # Parse bucket_iso to check chronological order
        isos = [b["bucket_iso"] for b in buckets]
        assert isos == sorted(isos)


def test_timeline_buckets_minute_aligned() -> None:
    """Every bucket_iso must have minute=0 (hour-aligned)."""
    engine = _engine()
    with Session(engine) as s:
        buckets = timeline_buckets(s, hours=24)
        for b in buckets:
            # parse from ISO: bucket_iso uses datetime.isoformat()
            dt = datetime.fromisoformat(b["bucket_iso"])
            assert dt.minute == 0
            assert dt.second == 0
            assert dt.microsecond == 0


# -------------------------- index existence (regression for init_db) --------------------------

def test_init_db_creates_composite_indexes() -> None:
    engine = _engine()
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA index_list('tooluseevent')")).all()
    names = {r[1] for r in rows}
    assert "ix_tooluseevent_machine_ts" in names
    assert "ix_tooluseevent_tool_ts" in names
    assert "ix_tooluseevent_decision_ts" in names


def test_init_db_idempotent() -> None:
    engine = _engine()
    # second call must not raise
    init_db(engine)
    init_db(engine)
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA index_list('tooluseevent')")).all()
    names = {r[1] for r in rows}
    assert "ix_tooluseevent_machine_ts" in names
