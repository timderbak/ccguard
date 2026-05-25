"""Unit tests for anomaly_service.tick() and evaluate_one (Plan 02-03).

Covers:

* warm-up: baseline_ready=False suppresses findings
* within-3σ: no finding emitted
* degenerate stdev==0: any nonzero positive deviation flagged
* same-day dedup: second tick on same day for same (machine, rule) → no dup
* finding payload: observed_value/mean/stdev/sigma_distance/metric/sample_count
* tick() iterates all machines × ALL_METRICS
* tick() tolerates per-machine aggregator failure (records error, continues)
* machine with no events / no snapshots → no findings
* sudden bash spike → bash_calls_per_day finding emitted
* different-day re-emission: yesterday's finding does not block today's
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from unittest.mock import patch

from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    InventorySnapshot,
    Machine,
    MachineBaseline,
    ToolUseEvent,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import anomaly_service
from ccguard.server.services.anomaly_constants import ALL_METRICS, rule_id_for


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _machine(session: Session, mid: str = "m1") -> Machine:
    m = Machine(machine_id=mid)
    session.add(m)
    session.commit()
    return m


def _at_utc(d: date, hour: int = 12) -> datetime:
    return datetime(d.year, d.month, d.day, hour, 0, 0, tzinfo=UTC)


def _seed_bash_spike(session: Session, machine_id: str, today: date) -> None:
    """13 days of 5 bash calls/day, then 100 bash calls on `today` → outlier."""
    for offset in range(1, 14):
        d = today - timedelta(days=offset)
        for k in range(5):
            session.add(
                ToolUseEvent(
                    machine_id=machine_id,
                    ts=_at_utc(d, hour=k % 24),
                    tool_name="Bash",
                    fingerprint=f"f{offset:02d}{k:02d}aabbccdd"[:16],
                    decision="allow",
                    result_status="success",
                )
            )
    for k in range(100):
        session.add(
            ToolUseEvent(
                machine_id=machine_id,
                ts=_at_utc(today, hour=k % 24),
                tool_name="Bash",
                fingerprint=f"t{k:03d}aabbccddeeff"[:16],
                decision="allow",
                result_status="success",
            )
        )
    session.commit()


# ---------------------------------------------------------------------------
# evaluate_one — warm-up, within-3σ, dedup, payload
# ---------------------------------------------------------------------------


def test_evaluate_one_warmup_returns_none() -> None:
    """Aggregator returns a series of only zeros — but with sample_count>=7 the
    baseline is "ready". To test warmup specifically, we patch the aggregator
    to return a too-short series."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mw")

        short = [(date(2026, 5, 1) + timedelta(days=i), 0) for i in range(3)]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: short},
        ):
            f = anomaly_service.evaluate_one(s, "mw", "bash_calls_per_day")
        assert f is None
        bl = s.exec(
            select(MachineBaseline).where(MachineBaseline.machine_id == "mw")
        ).first()
        assert bl is not None
        assert bl.baseline_ready is False


def test_evaluate_one_within_3sigma_no_finding() -> None:
    """Latest point within mean+3σ → no finding."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "ms")

        # Mix giving stdev > 0; latest is close to mean → not an outlier
        pts = [(date(2026, 5, 1) + timedelta(days=i), v)
               for i, v in enumerate([4, 6, 5, 5, 6, 4, 5, 6, 4, 5, 6, 4, 5, 5])]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "ms", "bash_calls_per_day")
        assert f is None


def test_evaluate_one_degenerate_stdev_zero_positive_deviation_flags() -> None:
    """stdev=0 and latest > mean → flagged as outlier (degenerate guard)."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "md")
        pts = [(date(2026, 5, 1) + timedelta(days=i), 3) for i in range(13)]
        pts.append((date(2026, 5, 14), 9))
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "md", "bash_calls_per_day")
        assert f is not None
        assert f.rule_id == "anomaly.bash_calls_per_day"
        assert f.severity == "warn"
        assert f.inventory_id is None


def test_evaluate_one_degenerate_stdev_zero_sigma_distance_is_none() -> None:
    """WR-02: when stdev==0 in the underlying baseline the persisted
    ``sigma_distance`` is ``None`` (JSON-portable), NOT ``float('inf')`` —
    ``json.dumps`` would otherwise emit the non-RFC-7159 ``Infinity`` literal.
    Use an exactly-flat baseline so the upserted MachineBaseline has stdev=0.
    """
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mdg")
        # 14 identical points → stdev=0, BUT the latest must equal mean so
        # _is_outlier returns False — we instead test that if the LATEST is
        # higher, _is_outlier flags it and the resulting persisted
        # sigma_distance is None. Use 13 of 3 + spike of 9, where:
        #   compute_baseline runs on [3]*13 + [9] → stdev > 0 normally.
        # To force stdev==0 we need a truly flat list. So upsert manually.
        from ccguard.server.services import baseline_service
        baseline_service.upsert_baseline(s, "mdg", "bash_calls_per_day", [5.0] * 14)
        # Now patch the aggregator to return a series whose LAST value > mean.
        pts = [(date(2026, 5, 1) + timedelta(days=i), 5) for i in range(13)]
        pts.append((date(2026, 5, 14), 5))  # latest == mean → not outlier on first call
        # Bump the last to force outlier on next call, while keeping recent series
        # for upsert. Simpler: directly call evaluate_one twice; first establishes
        # baseline with 14×5 (stdev=0), second uses a spike series, but
        # upsert_baseline will recompute stdev from new points, breaking degeneracy.
        # Instead: short-circuit by patching baseline_service.upsert_baseline.
        from unittest.mock import patch as _patch
        from ccguard.server.db.models import MachineBaseline as _MB
        flat_baseline = _MB(
            machine_id="mdg", metric="bash_calls_per_day",
            mean=5.0, stdev=0.0, sample_count=14, baseline_ready=True,
            recent_points_json="[5,5,5,5,5,5,5,5,5,5,5,5,5,9]",
        )
        spike_pts = [(date(2026, 5, 1) + timedelta(days=i), 5) for i in range(13)]
        spike_pts.append((date(2026, 5, 14), 9))
        with _patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: spike_pts},
        ), _patch.object(
            anomaly_service.baseline_service, "upsert_baseline",
            return_value=flat_baseline,
        ):
            f = anomaly_service.evaluate_one(s, "mdg", "bash_calls_per_day")
        assert f is not None
        payload = json.loads(f.payload_json)  # must round-trip cleanly
        assert payload["sigma_distance"] is None
        # And the persisted JSON must NOT contain the non-portable Infinity literal.
        assert "Infinity" not in f.payload_json


def test_evaluate_one_degenerate_stdev_zero_negative_deviation_no_flag() -> None:
    """stdev=0 and latest < mean → NOT flagged (we only alert on the high side)."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mn")
        pts = [(date(2026, 5, 1) + timedelta(days=i), 5) for i in range(13)]
        pts.append((date(2026, 5, 14), 0))
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "mn", "bash_calls_per_day")
        assert f is None


def test_evaluate_one_finding_payload_fields() -> None:
    """Payload has observed_value, mean, stdev, sigma_distance, metric, sample_count."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mp")
        # 13 days of small variance, today huge → outlier with finite sigma_distance
        pts = [(date(2026, 5, 1) + timedelta(days=i), v)
               for i, v in enumerate([4, 6, 5, 5, 4, 6, 5, 5, 4, 6, 5, 5, 4, 200])]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "mp", "bash_calls_per_day")
        assert f is not None
        payload = json.loads(f.payload_json)
        for k in ("observed_value", "mean", "stdev", "sigma_distance",
                  "metric", "sample_count"):
            assert k in payload, f"missing payload field: {k}"
        assert payload["observed_value"] == 200
        assert payload["metric"] == "bash_calls_per_day"
        assert payload["sample_count"] == 14


def test_evaluate_one_same_day_dedup() -> None:
    """Two consecutive evaluations on the same UTC day → exactly one finding."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mdup")
        pts = [(date(2026, 5, 1) + timedelta(days=i), v)
               for i, v in enumerate([4, 6, 5, 5, 4, 6, 5, 5, 4, 6, 5, 5, 4, 200])]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: pts},
        ):
            f1 = anomaly_service.evaluate_one(s, "mdup", "bash_calls_per_day")
            f2 = anomaly_service.evaluate_one(s, "mdup", "bash_calls_per_day")
        assert f1 is not None
        assert f2 is None
        rows = s.exec(
            select(FindingRecord).where(FindingRecord.machine_id == "mdup")
        ).all()
        assert len(rows) == 1


def test_evaluate_one_different_day_reemits() -> None:
    """A finding discovered yesterday does NOT block today's emission."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mdd")
        # Pre-insert a finding "discovered yesterday" for the same rule_id
        yesterday = datetime.now(UTC) - timedelta(days=1)
        s.add(FindingRecord(
            machine_id="mdd",
            inventory_id=None,
            rule_id="anomaly.bash_calls_per_day",
            severity="warn",
            discovered_at=yesterday,
            payload_json="{}",
        ))
        s.commit()

        pts = [(date(2026, 5, 1) + timedelta(days=i), v)
               for i, v in enumerate([4, 6, 5, 5, 4, 6, 5, 5, 4, 6, 5, 5, 4, 200])]
        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": lambda *a, **k: pts},
        ):
            f = anomaly_service.evaluate_one(s, "mdd", "bash_calls_per_day")
        assert f is not None
        rows = s.exec(
            select(FindingRecord).where(FindingRecord.machine_id == "mdd")
        ).all()
        assert len(rows) == 2  # yesterday's + today's


# ---------------------------------------------------------------------------
# tick() — full sweep
# ---------------------------------------------------------------------------


def test_tick_no_machines_returns_zero_counts() -> None:
    eng = _engine()
    with Session(eng) as s:
        summary = anomaly_service.tick(s)
        assert summary["machines_evaluated"] == 0
        assert summary["findings_emitted"] == 0
        assert summary["errors"] == []


def test_tick_empty_machine_emits_no_findings() -> None:
    """Machine with zero events and zero snapshots → all 4 metrics flat zeros → no findings."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mempty")
        summary = anomaly_service.tick(s)
        assert summary["machines_evaluated"] == 1
        assert summary["findings_emitted"] == 0
        assert summary["errors"] == []
        rows = s.exec(select(FindingRecord)).all()
        assert rows == []


def test_tick_bash_spike_emits_one_finding() -> None:
    """13 days of 5 bash/day, today 100 → one anomaly.bash_calls_per_day finding."""
    eng = _engine()
    today = datetime.now(UTC).date()
    with Session(eng) as s:
        _machine(s, "mspike")
        _seed_bash_spike(s, "mspike", today)
        summary = anomaly_service.tick(s)
        assert summary["machines_evaluated"] == 1
        assert summary["findings_emitted"] >= 1
        assert summary["errors"] == []
        rows = s.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == "mspike")
            .where(FindingRecord.rule_id == "anomaly.bash_calls_per_day")
        ).all()
        assert len(rows) == 1
        assert rows[0].severity == "warn"
        assert rows[0].inventory_id is None


def test_tick_is_idempotent_within_same_day() -> None:
    """Second tick on the same day produces no extra findings."""
    eng = _engine()
    today = datetime.now(UTC).date()
    with Session(eng) as s:
        _machine(s, "midem")
        _seed_bash_spike(s, "midem", today)
        s1 = anomaly_service.tick(s)
        s2 = anomaly_service.tick(s)
        assert s1["findings_emitted"] >= 1
        assert s2["findings_emitted"] == 0
        rows = s.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == "midem")
            .where(FindingRecord.rule_id == "anomaly.bash_calls_per_day")
        ).all()
        assert len(rows) == 1


def test_tick_tolerates_aggregator_failure() -> None:
    """A raising aggregator on one metric must not abort processing of others."""
    eng = _engine()
    today = datetime.now(UTC).date()
    with Session(eng) as s:
        _machine(s, "merr")
        _seed_bash_spike(s, "merr", today)

        def _boom(*a, **k):
            raise RuntimeError("kaboom")

        # Break bash_calls_per_day; the other three metrics should still run.
        with patch.dict(anomaly_service._DISPATCH, {"bash_calls_per_day": _boom}):
            summary = anomaly_service.tick(s)
        assert summary["machines_evaluated"] == 1
        assert any("kaboom" in e for e in summary["errors"])


def test_tick_iterates_all_metrics_per_machine() -> None:
    """Each machine evaluated for all ALL_METRICS — verify baselines materialised."""
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "mall")
        anomaly_service.tick(s)
        baselines = s.exec(
            select(MachineBaseline).where(MachineBaseline.machine_id == "mall")
        ).all()
        # Empty data still produces a baseline row per metric (14 zeros).
        metrics_seen = {b.metric for b in baselines}
        assert metrics_seen == set(ALL_METRICS)


def test_tick_multiple_machines_processed() -> None:
    """tick() processes every Machine row, not just the first."""
    eng = _engine()
    today = datetime.now(UTC).date()
    with Session(eng) as s:
        _machine(s, "m_a")
        _machine(s, "m_b")
        _seed_bash_spike(s, "m_a", today)
        # m_b stays quiet
        summary = anomaly_service.tick(s)
        assert summary["machines_evaluated"] == 2
        # m_a should have the spike finding; m_b should not.
        a_rows = s.exec(
            select(FindingRecord).where(FindingRecord.machine_id == "m_a")
        ).all()
        b_rows = s.exec(
            select(FindingRecord).where(FindingRecord.machine_id == "m_b")
        ).all()
        assert len(a_rows) >= 1
        assert b_rows == []
