"""Cross-cutting anomaly edge cases (Plan 02-06 / Task 3).

Locks down the corner cases that span multiple modules:

* stdev==0 with flat history — quiet machine stays quiet
* 14 identical zero points — no false positive
* sparse-but-long window — baseline_ready still flips on window length
* clock-rollover — different UTC days are NOT same-day dedup'd
* empty Machine table — tick returns the zero summary
* rule_id_for contract sanity
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from unittest.mock import patch

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import anomaly_service
from ccguard.server.services.anomaly_constants import rule_id_for


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _machine(session: Session, mid: str) -> None:
    session.add(Machine(machine_id=mid))
    session.commit()


# ---------------------------------------------------------------------------
# Degenerate stdev (flat baselines)
# ---------------------------------------------------------------------------


def test_stdev_zero_latest_equals_mean_no_finding() -> None:
    """14 identical points → mean=N, stdev=0, latest=N → not flagged."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "flat")
        pts = [(date(2026, 5, 1) + timedelta(days=i), 7) for i in range(14)]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *_a, **_k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "flat", "bash_calls_per_day")
        assert f is None


def test_stdev_zero_latest_differs_by_one_is_outlier() -> None:
    """Flat history then any positive deviation → flagged (degenerate guard)."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "flat-diff")
        pts = [(date(2026, 5, 1) + timedelta(days=i), 7) for i in range(13)]
        pts.append((date(2026, 5, 14), 8))  # +1 over a flat baseline
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *_a, **_k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "flat-diff", "bash_calls_per_day")
        assert f is not None
        assert f.rule_id == "anomaly.bash_calls_per_day"


def test_fourteen_zero_points_no_finding() -> None:
    """All-zero history (calm machine) → mean=0, stdev=0, latest=0 → no finding."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "quiet")
        pts = [(date(2026, 5, 1) + timedelta(days=i), 0) for i in range(14)]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *_a, **_k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "quiet", "bash_calls_per_day")
        assert f is None


def test_window_baseline_ready_gates_on_nonzero_count() -> None:
    """CR-02 fix: baseline_ready is gated on the non-zero point count, not
    the zero-padded window length. The aggregators always return 14 points
    (zero-padded), so the previous length-based gate flipped to True on the
    very first tick of a brand-new machine and immediately produced
    false-positive 3σ findings when any spike appeared. Now: a 14-point
    series with exactly 7 non-zero entries records ``sample_count=7`` and
    flips ``baseline_ready=True``; with fewer than 7 it stays in warm-up.
    """
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "sparse")
        # 7 zeros then 7 nonzero — real_n=7 → sample_count=7, ready=True.
        values = [0, 0, 0, 0, 0, 0, 0, 4, 5, 4, 5, 4, 5, 4]
        pts = [(date(2026, 5, 1) + timedelta(days=i), v) for i, v in enumerate(values)]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *_a, **_k: pts},
        ):
            anomaly_service.evaluate_one(s, "sparse", "bash_calls_per_day")
        bl = s.exec(
            select(MachineBaseline).where(MachineBaseline.machine_id == "sparse")
        ).first()
        assert bl is not None
        assert bl.sample_count == 7
        assert bl.baseline_ready is True


def test_window_baseline_warmup_under_threshold_nonzero() -> None:
    """CR-02 fix: 14-point series with <7 non-zero values stays in warm-up
    (sample_count < WARMUP_THRESHOLD)."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "brand-new")
        # 13 zeros + 1 spike — real_n=1 → ready=False, no false positive.
        values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42]
        pts = [(date(2026, 5, 1) + timedelta(days=i), v) for i, v in enumerate(values)]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *_a, **_k: pts},
        ):
            finding = anomaly_service.evaluate_one(s, "brand-new", "bash_calls_per_day")
        bl = s.exec(
            select(MachineBaseline).where(MachineBaseline.machine_id == "brand-new")
        ).first()
        assert bl is not None
        assert bl.sample_count == 1
        assert bl.baseline_ready is False
        assert finding is None  # warm-up gates emission


# ---------------------------------------------------------------------------
# Clock-rollover / dedup boundary
# ---------------------------------------------------------------------------


def test_different_day_finding_not_deduplicated() -> None:
    """A finding at 23:59 UTC and another at 00:01 UTC the next day are NOT
    treated as same-day duplicates (dedup is bucketed on func.date)."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "rollover")
        pts = [(date(2026, 5, 1) + timedelta(days=i), 5) for i in range(13)]
        pts.append((date(2026, 5, 14), 99))
        late = datetime(2026, 5, 14, 23, 59, 0, tzinfo=UTC)
        early = datetime(2026, 5, 15, 0, 1, 0, tzinfo=UTC)

        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *_a, **_k: pts},
        ):
            # First tick: pin "now" at 23:59 UTC on day N.
            with patch("ccguard.server.services.anomaly_service.datetime") as mdt:
                mdt.now.return_value = late
                # Pass through any other attribute access (e.g. UTC).
                mdt.side_effect = lambda *a, **k: datetime(*a, **k)
                f1 = anomaly_service.evaluate_one(s, "rollover", "bash_calls_per_day")
            assert f1 is not None

            # Second tick: pin "now" at 00:01 UTC on day N+1 — must NOT dedup.
            with patch("ccguard.server.services.anomaly_service.datetime") as mdt:
                mdt.now.return_value = early
                mdt.side_effect = lambda *a, **k: datetime(*a, **k)
                f2 = anomaly_service.evaluate_one(s, "rollover", "bash_calls_per_day")
            assert f2 is not None
            assert f2.id != f1.id

        # Two distinct FindingRecord rows persist.
        rows = s.exec(
            select(FindingRecord).where(
                FindingRecord.machine_id == "rollover",
                FindingRecord.rule_id == "anomaly.bash_calls_per_day",
            )
        ).all()
        assert len(rows) == 2


# ---------------------------------------------------------------------------
# Empty Machine table → zero-summary tick
# ---------------------------------------------------------------------------


def test_tick_empty_machine_table_returns_zero_summary() -> None:
    eng = _engine()
    with Session(eng) as s:
        summary = anomaly_service.tick(s)
        assert summary == {
            "machines_evaluated": 0,
            "findings_emitted": 0,
            "errors": [],
        }


# ---------------------------------------------------------------------------
# Contract sanity
# ---------------------------------------------------------------------------


def test_rule_id_for_bash_calls_per_day_contract() -> None:
    """The route layer hardcodes 'anomaly.<metric>' — keep that contract stable."""
    assert rule_id_for("bash_calls_per_day") == "anomaly.bash_calls_per_day"
    assert rule_id_for("new_mcp_per_week") == "anomaly.new_mcp_per_week"
