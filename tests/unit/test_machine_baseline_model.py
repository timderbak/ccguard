"""Unit tests for MachineBaseline SQLModel + nullable FindingRecord.inventory_id.

Plan 02-01: storage foundation for anomaly detection.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, MachineBaseline
from ccguard.server.db.session import init_db, make_engine


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def test_machine_baseline_roundtrip() -> None:
    """Test 1: Insert MachineBaseline and read it back with auto updated_at."""
    engine = _engine()
    with Session(engine) as s:
        s.add(
            MachineBaseline(
                machine_id="m1",
                metric="bash_calls_per_day",
                mean=10.0,
                stdev=2.0,
                sample_count=14,
                baseline_ready=True,
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(MachineBaseline)).one()
        assert row.machine_id == "m1"
        assert row.metric == "bash_calls_per_day"
        assert row.mean == 10.0
        assert row.stdev == 2.0
        assert row.sample_count == 14
        assert row.baseline_ready is True
        assert row.updated_at is not None
        # default factory should set a real datetime
        assert isinstance(row.updated_at, datetime)


def test_machine_baseline_composite_uniqueness() -> None:
    """Test 2: Two rows with same (machine_id, metric) raise IntegrityError."""
    engine = _engine()
    with Session(engine) as s:
        s.add(
            MachineBaseline(
                machine_id="m1",
                metric="bash_calls_per_day",
                mean=1.0,
                stdev=0.0,
                sample_count=1,
            )
        )
        s.commit()
    with Session(engine) as s:
        s.add(
            MachineBaseline(
                machine_id="m1",
                metric="bash_calls_per_day",
                mean=2.0,
                stdev=0.0,
                sample_count=2,
            )
        )
        with pytest.raises(IntegrityError):
            s.commit()


def test_machine_baseline_different_metric_allowed() -> None:
    """Test 3: Different metric for the same machine is allowed."""
    engine = _engine()
    with Session(engine) as s:
        s.add(
            MachineBaseline(
                machine_id="m1",
                metric="bash_calls_per_day",
                mean=1.0,
                stdev=0.0,
                sample_count=1,
            )
        )
        s.add(
            MachineBaseline(
                machine_id="m1",
                metric="new_mcp_per_week",
                mean=0.5,
                stdev=0.1,
                sample_count=4,
            )
        )
        s.commit()
    with Session(engine) as s:
        rows = list(s.exec(select(MachineBaseline)))
        assert len(rows) == 2
        metrics = {r.metric for r in rows}
        assert metrics == {"bash_calls_per_day", "new_mcp_per_week"}


def test_finding_record_inventory_id_nullable() -> None:
    """Test 4: FindingRecord with inventory_id=None inserts and reads back NULL."""
    engine = _engine()
    with Session(engine) as s:
        s.add(
            FindingRecord(
                machine_id="m1",
                inventory_id=None,
                rule_id="anomaly.bash_calls_per_day",
                severity="medium",
                payload_json="{}",
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(FindingRecord)).one()
        assert row.inventory_id is None
        assert row.rule_id == "anomaly.bash_calls_per_day"


def test_finding_record_backward_compat_non_null_inventory_id() -> None:
    """Test 5: Pre-existing FindingRecord with non-null inventory_id still loads."""
    engine = _engine()
    with Session(engine) as s:
        s.add(
            FindingRecord(
                machine_id="m1",
                inventory_id=42,
                rule_id="legacy.rule",
                severity="high",
                discovered_at=datetime.now(UTC),
                payload_json='{"old":true}',
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(FindingRecord)).one()
        assert row.inventory_id == 42
        assert row.rule_id == "legacy.rule"
        assert row.severity == "high"


def test_machine_baseline_recent_points_json_roundtrip() -> None:
    """Test 6: recent_points_json round-trips a JSON list of 14 floats byte-identical."""
    engine = _engine()
    points = [float(i) * 1.5 for i in range(14)]
    blob = json.dumps(points)
    with Session(engine) as s:
        s.add(
            MachineBaseline(
                machine_id="m1",
                metric="bash_calls_per_day",
                mean=10.0,
                stdev=2.0,
                sample_count=14,
                recent_points_json=blob,
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(MachineBaseline)).one()
        assert row.recent_points_json == blob
        assert json.loads(row.recent_points_json) == points
