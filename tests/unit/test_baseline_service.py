"""Unit tests for baseline_service (Plan 02-02).

Covers:

* :func:`compute_baseline` — pure stdlib stats with warm-up flag at
  ``sample_count >= WARMUP_THRESHOLD`` (=7).
* :func:`upsert_baseline` — race-free INSERT/ON-CONFLICT into
  ``MachineBaseline``; second call updates in place, never duplicates.
"""

from __future__ import annotations

import json
import statistics
import time

from sqlmodel import Session, select

from ccguard.server.db.models import MachineBaseline
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.baseline_service import (
    WARMUP_THRESHOLD,
    compute_baseline,
    upsert_baseline,
)


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


# ---------------------------------------------------------------------------
# compute_baseline
# ---------------------------------------------------------------------------


def test_compute_baseline_identical_points_zero_stdev() -> None:
    """14 identical points → mean=5.0, stdev=0.0, ready=True."""
    result = compute_baseline([5.0] * 14)
    assert result["mean"] == 5.0
    assert result["stdev"] == 0.0
    assert result["sample_count"] == 14
    assert result["baseline_ready"] is True


def test_compute_baseline_full_window_includes_zeros() -> None:
    """6 nonzero + 8 zeros → sample_count=6 (CR-02: non-zero gate), ready=False.

    Statistics (mean/stdev) are still computed over the full 14-point series
    so the zero-padded days correctly anchor the distribution; only the
    warm-up gate uses the non-zero count.
    """
    pts = [10.0, 5.0, 3.0, 2.0, 1.0, 4.0] + [0.0] * 8
    result = compute_baseline(pts)
    assert result["sample_count"] == 6
    assert result["baseline_ready"] is False
    # statistical correctness — mean/stdev still derived from full series
    assert result["mean"] == statistics.fmean(pts)
    assert result["stdev"] == statistics.stdev(pts)


def test_compute_baseline_warmup_under_threshold() -> None:
    """CR-02: fewer than 7 non-zero points → baseline_ready=False.

    Aggregators always return a 14-length zero-padded series; ``points`` of
    length ``n>0`` (all ones) here simulates n days of real activity.
    """
    for n in range(0, WARMUP_THRESHOLD):
        result = compute_baseline([1.0] * n if n > 0 else [])
        assert result["baseline_ready"] is False, f"n={n} should be warm-up"
        assert result["sample_count"] == n


def test_compute_baseline_exactly_7_points_ready() -> None:
    """Boundary: exactly 7 non-zero points → baseline_ready=True."""
    result = compute_baseline([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0])
    assert result["baseline_ready"] is True
    assert result["sample_count"] == 7


def test_compute_baseline_uses_sample_stdev_n_minus_1() -> None:
    """stdev uses statistics.stdev (n-1 denominator) — verify vs known value."""
    pts = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    result = compute_baseline(pts)
    assert abs(result["stdev"] - statistics.stdev(pts)) < 1e-12
    assert abs(result["mean"] - statistics.fmean(pts)) < 1e-12


def test_compute_baseline_single_point_stdev_zero() -> None:
    """<2 points → stdev defined as 0.0 (statistics.stdev would raise)."""
    result = compute_baseline([3.0])
    assert result["stdev"] == 0.0
    assert result["mean"] == 3.0
    assert result["sample_count"] == 1
    assert result["baseline_ready"] is False


def test_compute_baseline_empty_input_safe() -> None:
    """Empty list → mean=0.0, stdev=0.0, ready=False (no crash)."""
    result = compute_baseline([])
    assert result["sample_count"] == 0
    assert result["mean"] == 0.0
    assert result["stdev"] == 0.0
    assert result["baseline_ready"] is False


# ---------------------------------------------------------------------------
# upsert_baseline
# ---------------------------------------------------------------------------


def test_upsert_baseline_insert_then_update_no_duplicate() -> None:
    """Two upserts with same (machine_id, metric) keep row count at 1."""
    engine = _engine()
    with Session(engine) as s:
        upsert_baseline(s, "m1", "bash_calls_per_day", [1.0] * 14)
        upsert_baseline(s, "m1", "bash_calls_per_day", [2.0] * 14)
        rows = list(s.exec(select(MachineBaseline)))
    assert len(rows) == 1
    assert rows[0].mean == 2.0


def test_upsert_baseline_stores_recent_points_json() -> None:
    """recent_points_json is json.dumps(points)."""
    engine = _engine()
    points = [float(i) for i in range(14)]
    with Session(engine) as s:
        upsert_baseline(s, "m1", "bash_calls_per_day", points)
        row = s.exec(select(MachineBaseline)).one()
    assert json.loads(row.recent_points_json) == points


def test_upsert_baseline_updated_at_advances() -> None:
    """Each upsert advances updated_at."""
    engine = _engine()
    with Session(engine) as s:
        upsert_baseline(s, "m1", "bash_calls_per_day", [1.0] * 14)
        first = s.exec(select(MachineBaseline)).one().updated_at
        time.sleep(0.01)  # ensure microsecond delta on fast machines
        upsert_baseline(s, "m1", "bash_calls_per_day", [2.0] * 14)
        second = s.exec(select(MachineBaseline)).one().updated_at
    assert second > first


def test_upsert_baseline_different_metric_same_machine_inserts_new() -> None:
    """Different metric for the same machine → distinct row."""
    engine = _engine()
    with Session(engine) as s:
        upsert_baseline(s, "m1", "bash_calls_per_day", [1.0] * 14)
        upsert_baseline(s, "m1", "new_mcp_per_week", [0.0] * 14)
        rows = list(s.exec(select(MachineBaseline)))
    assert len(rows) == 2
    metrics = {r.metric for r in rows}
    assert metrics == {"bash_calls_per_day", "new_mcp_per_week"}


def test_upsert_baseline_repeated_calls_never_raise() -> None:
    """Concurrent-style repeat calls never raise IntegrityError."""
    engine = _engine()
    with Session(engine) as s:
        for i in range(5):
            upsert_baseline(s, "m1", "bash_calls_per_day", [float(i)] * 14)
        rows = list(s.exec(select(MachineBaseline)))
    assert len(rows) == 1
    assert rows[0].mean == 4.0


def test_upsert_baseline_persists_warmup_flag() -> None:
    """With <7 points, baseline_ready=False is persisted."""
    engine = _engine()
    with Session(engine) as s:
        upsert_baseline(s, "m1", "bash_calls_per_day", [1.0, 2.0, 3.0])
        row = s.exec(select(MachineBaseline)).one()
    assert row.baseline_ready is False
    assert row.sample_count == 3


def test_upsert_baseline_persists_ready_flag() -> None:
    """With ≥7 points, baseline_ready=True is persisted."""
    engine = _engine()
    with Session(engine) as s:
        upsert_baseline(s, "m1", "bash_calls_per_day", [1.0] * 7)
        row = s.exec(select(MachineBaseline)).one()
    assert row.baseline_ready is True
    assert row.sample_count == 7


def test_upsert_baseline_returns_machine_baseline() -> None:
    """upsert_baseline returns the persisted MachineBaseline row."""
    engine = _engine()
    with Session(engine) as s:
        result = upsert_baseline(s, "m1", "bash_calls_per_day", [1.0] * 14)
    assert isinstance(result, MachineBaseline)
    assert result.machine_id == "m1"
    assert result.metric == "bash_calls_per_day"
    assert result.mean == 1.0


def test_warmup_threshold_constant_is_7() -> None:
    """Locked constant per plan 02-02."""
    assert WARMUP_THRESHOLD == 7
