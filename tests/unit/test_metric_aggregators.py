"""Unit tests for Phase 2 metric aggregators (Plan 02-02).

Covers the four pure-function series builders that drive both the matrix-page
sparklines and baseline-statistics computation:

* ``bash_calls_per_day_series`` — SQL-backed daily counts from ToolUseEvent.
* ``new_mcp_per_week_series`` — inventory-diff, rolling-week semantics.
* ``new_agents_per_week_series`` — same, identity = (name, file_hash).
* ``skill_dir_hash_changes_per_week_series`` — same, identity = (name, dir_hash).

All four return ``list[tuple[date, int]]`` of length 14 (oldest first, today
last). Missing days are zero-padded so sparklines align without client gap-fill.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import InventorySnapshot, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.metric_aggregators import (
    bash_calls_per_day_series,
    new_agents_per_week_series,
    new_mcp_per_week_series,
    skill_dir_hash_changes_per_week_series,
)


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _at_utc(d: date, hour: int = 12) -> datetime:
    return datetime(d.year, d.month, d.day, hour, 0, 0, tzinfo=UTC)


def _seed_event(
    session: Session,
    *,
    machine_id: str = "m1",
    ts: datetime,
    tool_name: str = "Bash",
    decision: str = "allow",
) -> None:
    session.add(
        ToolUseEvent(
            machine_id=machine_id,
            ts=ts,
            tool_name=tool_name,
            fingerprint="0123456789abcdef",
            decision=decision,
            result_status="success",
        )
    )


def _inventory_payload(
    *,
    machine_id: str = "m1",
    ts: datetime,
    mcp_servers: list[dict] | None = None,
    agents: list[dict] | None = None,
    skills: list[dict] | None = None,
) -> str:
    payload = {
        "schema_version": 1,
        "machine_id": machine_id,
        "timestamp": ts.isoformat(),
        "agent_version": "0.1.0",
        "os": "linux",
        "settings_sources": [],
        "mcp_servers": mcp_servers or [],
        "skills": skills or [],
        "hooks": [],
        "plugins": [],
        "permissions": {"allow": [], "deny": [], "ask": [], "dangerously_skip_detected": False},
        "agents": agents or [],
        "commands": [],
        "env_keys": [],
        "claude_code_version": None,
    }
    return json.dumps(payload)


def _seed_snapshot(
    session: Session,
    *,
    machine_id: str = "m1",
    received_at: datetime,
    mcp_servers: list[dict] | None = None,
    agents: list[dict] | None = None,
    skills: list[dict] | None = None,
) -> None:
    session.add(
        InventorySnapshot(
            machine_id=machine_id,
            received_at=received_at,
            payload_json=_inventory_payload(
                machine_id=machine_id,
                ts=received_at,
                mcp_servers=mcp_servers,
                agents=agents,
                skills=skills,
            ),
        )
    )


# ===========================================================================
# bash_calls_per_day_series
# ===========================================================================


def test_bash_calls_per_day_returns_14_length_with_correct_counts() -> None:
    """5 Bash events across 3 distinct UTC days for m1 → correct counts."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        # 2 events on anchor day (d0)
        _seed_event(s, ts=_at_utc(anchor, 9))
        _seed_event(s, ts=_at_utc(anchor, 18))
        # 1 event on d-3
        _seed_event(s, ts=_at_utc(anchor - timedelta(days=3), 10))
        # 2 events on d-13 (oldest in window)
        _seed_event(s, ts=_at_utc(anchor - timedelta(days=13), 1))
        _seed_event(s, ts=_at_utc(anchor - timedelta(days=13), 22))
        s.commit()

        series = bash_calls_per_day_series(s, "m1", anchor_date=anchor)

    assert len(series) == 14
    by_day = dict(series)
    assert by_day[anchor] == 2
    assert by_day[anchor - timedelta(days=3)] == 1
    assert by_day[anchor - timedelta(days=13)] == 2
    # remaining days = 0
    zeros = [d for d, c in series if c == 0]
    assert len(zeros) == 11


def test_bash_calls_excludes_other_tools() -> None:
    """Events with tool_name='Edit' must be excluded."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_event(s, ts=_at_utc(anchor, 9), tool_name="Edit")
        _seed_event(s, ts=_at_utc(anchor, 10), tool_name="Bash")
        s.commit()
        series = bash_calls_per_day_series(s, "m1", anchor_date=anchor)
    assert dict(series)[anchor] == 1


def test_bash_calls_excludes_other_machines() -> None:
    """Events for a different machine_id must be excluded."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_event(s, machine_id="m1", ts=_at_utc(anchor, 9))
        _seed_event(s, machine_id="m2", ts=_at_utc(anchor, 10))
        _seed_event(s, machine_id="m2", ts=_at_utc(anchor, 11))
        s.commit()
        series = bash_calls_per_day_series(s, "m1", anchor_date=anchor)
    assert dict(series)[anchor] == 1


def test_bash_calls_anchor_is_last_oldest_is_13_days_before() -> None:
    """Anchor day is last element; series spans [anchor-13 ... anchor]."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        series = bash_calls_per_day_series(s, "m1", anchor_date=anchor)
    assert series[-1][0] == anchor
    assert series[0][0] == anchor - timedelta(days=13)
    # strictly ascending
    days = [d for d, _ in series]
    assert days == sorted(days)


def test_bash_calls_empty_returns_all_zeros() -> None:
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        series = bash_calls_per_day_series(s, "m1", anchor_date=anchor)
    assert len(series) == 14
    assert all(c == 0 for _, c in series)


def test_bash_calls_events_outside_window_excluded() -> None:
    """Events older than anchor-13 days must not appear."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        # 15 days ago — outside the 14-day window
        _seed_event(s, ts=_at_utc(anchor - timedelta(days=15), 12))
        # 1 valid event today for sanity
        _seed_event(s, ts=_at_utc(anchor, 12))
        s.commit()
        series = bash_calls_per_day_series(s, "m1", anchor_date=anchor)
    total = sum(c for _, c in series)
    assert total == 1


def test_bash_calls_tz_aware_orm_roundtrip_matches() -> None:
    """Regression for CR-01: tz-aware datetimes inserted via the ORM must
    match the aggregator's date-prefix range filter regardless of how the
    underlying driver/dialect serializes the timestamp (space vs ``T``
    separator, with or without trailing ``+00:00`` offset).
    """
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        # tz-aware UTC datetime, identical to what Phase 1 ingest produces.
        _seed_event(s, ts=datetime(2026, 5, 25, 0, 0, 1, tzinfo=UTC))
        _seed_event(s, ts=datetime(2026, 5, 25, 23, 59, 59, tzinfo=UTC))
        # Boundary: anchor - 13 days (still in window).
        _seed_event(s, ts=datetime(2026, 5, 12, 12, 0, 0, tzinfo=UTC))
        # Boundary: anchor - 14 days (out of window).
        _seed_event(s, ts=datetime(2026, 5, 11, 12, 0, 0, tzinfo=UTC))
        s.commit()
        series = bash_calls_per_day_series(s, "m1", anchor_date=anchor)
    by_day = dict(series)
    # CR-01 regression: must NOT be all zeros against ORM-stored tz-aware rows.
    assert sum(by_day.values()) == 3
    assert by_day[anchor] == 2
    assert by_day[date(2026, 5, 12)] == 1
    assert date(2026, 5, 11) not in by_day  # outside the 14-day window


# ===========================================================================
# new_mcp_per_week_series
# ===========================================================================


def _mcp(name: str) -> dict:
    return {
        "name": name,
        "transport": "stdio",
        "command": "npx",
        "args": [],
        "url": None,
        "env_keys": [],
        "source": "/test",
    }


def test_new_mcp_per_week_basic_rolling_window() -> None:
    """Snapshots at d-10 [A,B] and d-2 [A,B,C] → C is new at anchor=d."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=10)),
            mcp_servers=[_mcp("A"), _mcp("B")],
        )
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=2)),
            mcp_servers=[_mcp("A"), _mcp("B"), _mcp("C")],
        )
        s.commit()
        series = new_mcp_per_week_series(s, "m1", anchor_date=anchor)
    by_day = dict(series)
    # at anchor=d, latest pre-d snapshot is d-2 (inside last 7d); baseline
    # (snapshots strictly older than d-7) had only [A,B]. C is new → 1.
    assert by_day[anchor] == 1
    # at anchor=d-5: window is (d-12, d-5]. Latest pre-d-5 snapshot = d-10 [A,B].
    # baseline (strictly older than d-12) is empty. So everything in [A,B] is "new"? No —
    # for "new" we compare snapshots inside window vs strictly older. d-10 is INSIDE the
    # (d-12, d-5] window. So no snapshot strictly inside window adds anything new
    # beyond what's strictly older. baseline window is strictly older than (d-5 - 7) = d-12,
    # which is empty. Latest pre-d-5 = d-10 (inside window). New items = items in [A,B]
    # not present strictly before d-12 → both A and B count. Hmm — but plan says
    # "at anchor=d-5, count=0". Plan's intent: an item is "new in last 7d" if it
    # appears in the latest snapshot ≤ anchor AND did NOT appear in any snapshot
    # strictly older than (anchor - 7d). At anchor d-5, latest ≤ d-5 is d-10 (inside
    # the (d-12, d-5] window). Items strictly older than d-12: none. So [A,B] would
    # both be new. But plan says 0. The plan must mean: count items "new" only when
    # the *latest* snapshot ≤ anchor is INSIDE (anchor-7d, anchor]. d-10 is NOT inside
    # (d-12, d-5] — wait, d-10 IS inside (d-12, d-5] since d-12 < d-10 ≤ d-5. So we
    # need to re-read the plan. The plan's example says "at anchor=d-5, count=0".
    # The natural reading: at anchor d-5, the latest snapshot at-or-before d-5 is the
    # d-10 snapshot. For there to be "new MCP in last 7d", a snapshot must exist
    # INSIDE (d-5 - 7d, d-5] = (d-12, d-5] that introduces an item not seen in a
    # snapshot STRICTLY OLDER than d-12. The d-10 snapshot IS inside the window.
    # Items strictly older than d-12: none. So by literal reading [A,B] are "new" → 2.
    # But the plan example asserts 0. The reconciliation: the plan's intent is to
    # detect *changes* (deltas), not initial population. So if the older window is
    # empty, we treat all items as "established baseline", not new. We implement:
    # if there's no snapshot strictly older than (anchor - 7d), then count=0
    # (no baseline to compare against → no signal). This matches the plan example.
    assert by_day[anchor - timedelta(days=5)] == 0
    # at anchor=d-1: window (d-8, d-1]. Latest ≤ d-1 = d-2 [A,B,C]. Snapshots
    # strictly older than d-8 = d-10 [A,B]. C is new → 1.
    assert by_day[anchor - timedelta(days=1)] == 1


def test_new_mcp_per_week_empty_inventory() -> None:
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        series = new_mcp_per_week_series(s, "m1", anchor_date=anchor)
    assert len(series) == 14
    assert all(c == 0 for _, c in series)


def test_new_mcp_per_week_returns_14_length_ascending() -> None:
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        series = new_mcp_per_week_series(s, "m1", anchor_date=anchor)
    assert len(series) == 14
    days = [d for d, _ in series]
    assert days[0] == anchor - timedelta(days=13)
    assert days[-1] == anchor
    assert days == sorted(days)


def test_new_mcp_per_week_other_machine_isolated() -> None:
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_snapshot(
            s,
            machine_id="other",
            received_at=_at_utc(anchor - timedelta(days=10)),
            mcp_servers=[_mcp("A")],
        )
        _seed_snapshot(
            s,
            machine_id="other",
            received_at=_at_utc(anchor - timedelta(days=2)),
            mcp_servers=[_mcp("A"), _mcp("Z")],
        )
        s.commit()
        series = new_mcp_per_week_series(s, "m1", anchor_date=anchor)
    assert sum(c for _, c in series) == 0


# ===========================================================================
# new_agents_per_week_series
# ===========================================================================


def _agent(name: str, file_hash: str) -> dict:
    return {
        "name": name,
        "path": f"/agents/{name}.md",
        "file_hash": file_hash,
        "tools": None,
        "model": None,
        "description": None,
    }


def test_new_agents_per_week_identity_includes_hash() -> None:
    """Agent x with file_hash=h1 in d-10, h2 in d-2 → at anchor=d count=1."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=10)),
            agents=[_agent("x", "h1")],
        )
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=2)),
            agents=[_agent("x", "h2")],
        )
        s.commit()
        series = new_agents_per_week_series(s, "m1", anchor_date=anchor)
    by_day = dict(series)
    # (x,h2) is new vs strictly-older-than-(d-7) baseline which contains (x,h1).
    assert by_day[anchor] == 1


def test_new_agents_per_week_unchanged_hash_no_signal() -> None:
    """Same (name, file_hash) in both snapshots → no new agent."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=10)),
            agents=[_agent("x", "h1")],
        )
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=2)),
            agents=[_agent("x", "h1")],
        )
        s.commit()
        series = new_agents_per_week_series(s, "m1", anchor_date=anchor)
    assert dict(series)[anchor] == 0


def test_new_agents_per_week_empty_inventory() -> None:
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        series = new_agents_per_week_series(s, "m1", anchor_date=anchor)
    assert len(series) == 14
    assert all(c == 0 for _, c in series)


# ===========================================================================
# skill_dir_hash_changes_per_week_series
# ===========================================================================


def _skill(name: str, dir_hash: str) -> dict:
    return {
        "name": name,
        "path": f"/skills/{name}",
        "origin": "local",
        "dir_hash": dir_hash,
        "has_referenced_scripts": False,
    }


def test_skill_dir_hash_changes_basic() -> None:
    """Skill s with dir_hash=h1 in d-10, h2 in d-3 → at anchor=d count=1."""
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=10)),
            skills=[_skill("s", "h1")],
        )
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=3)),
            skills=[_skill("s", "h2")],
        )
        s.commit()
        series = skill_dir_hash_changes_per_week_series(s, "m1", anchor_date=anchor)
    by_day = dict(series)
    assert by_day[anchor] == 1


def test_skill_dir_hash_no_change_no_signal() -> None:
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=10)),
            skills=[_skill("s", "h1")],
        )
        _seed_snapshot(
            s,
            received_at=_at_utc(anchor - timedelta(days=3)),
            skills=[_skill("s", "h1")],
        )
        s.commit()
        series = skill_dir_hash_changes_per_week_series(s, "m1", anchor_date=anchor)
    assert dict(series)[anchor] == 0


def test_skill_dir_hash_empty_inventory() -> None:
    anchor = date(2026, 5, 25)
    engine = _engine()
    with Session(engine) as s:
        series = skill_dir_hash_changes_per_week_series(s, "m1", anchor_date=anchor)
    assert len(series) == 14
    assert all(c == 0 for _, c in series)
