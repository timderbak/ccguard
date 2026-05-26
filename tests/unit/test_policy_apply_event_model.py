"""Unit tests for PolicyApplyEvent SQLModel (Plan 04-01, Task 2).

Verifies:
- Success/rollback row round-trip
- Composite indexes (machine_id, ts) and (result, ts) exist
- create_all picks up the new table
- result accepts only ``success`` / ``rollback`` at the Pydantic write boundary
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import inspect, text
from sqlmodel import Session, select

from ccguard.server.db.models import PolicyApplyEvent
from ccguard.server.db.session import init_db, make_engine


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def test_policy_apply_event_success_row_roundtrip() -> None:
    engine = _engine()
    with Session(engine) as s:
        s.add(
            PolicyApplyEvent(
                machine_id="m1",
                result="success",
                applied_count=3,
                snapshot_id="20260526-120000",
                reason=None,
                failed_file=None,
                policy_revision=7,
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(PolicyApplyEvent)).one()
        assert row.machine_id == "m1"
        assert row.result == "success"
        assert row.applied_count == 3
        assert row.snapshot_id == "20260526-120000"
        assert row.reason is None
        assert row.failed_file is None
        assert row.policy_revision == 7
        assert isinstance(row.ts, datetime)


def test_policy_apply_event_rollback_row_roundtrip() -> None:
    engine = _engine()
    with Session(engine) as s:
        s.add(
            PolicyApplyEvent(
                machine_id="m2",
                result="rollback",
                applied_count=0,
                snapshot_id="20260526-120000",
                reason="PermissionError on ~/.claude/agents/x.md",
                failed_file="~/.claude/agents/x.md",
                policy_revision=7,
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(PolicyApplyEvent)).one()
        assert row.result == "rollback"
        assert row.applied_count == 0
        assert row.reason == "PermissionError on ~/.claude/agents/x.md"
        assert row.failed_file == "~/.claude/agents/x.md"


def test_composite_index_machine_ts_created() -> None:
    engine = _engine()
    insp = inspect(engine)
    idx_names = {ix["name"] for ix in insp.get_indexes("policyapplyevent")}
    assert "ix_policy_apply_machine_ts" in idx_names


def test_composite_index_result_ts_created() -> None:
    engine = _engine()
    insp = inspect(engine)
    idx_names = {ix["name"] for ix in insp.get_indexes("policyapplyevent")}
    assert "ix_policy_apply_result_ts" in idx_names


def test_create_all_registers_policy_apply_event_table() -> None:
    engine = _engine()
    insp = inspect(engine)
    assert "policyapplyevent" in insp.get_table_names()


def test_policy_apply_event_query_filters_by_result_and_orders_ts_desc() -> None:
    """End-to-end query path matching /audit?event_source=policy_apply&result=rollback."""
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add(
            PolicyApplyEvent(
                machine_id="m1",
                ts=now - timedelta(minutes=2),
                result="success",
                applied_count=2,
                policy_revision=1,
            )
        )
        s.add(
            PolicyApplyEvent(
                machine_id="m1",
                ts=now - timedelta(minutes=1),
                result="rollback",
                applied_count=0,
                reason="x",
                failed_file="y",
                policy_revision=1,
            )
        )
        s.add(
            PolicyApplyEvent(
                machine_id="m1",
                ts=now,
                result="rollback",
                applied_count=0,
                reason="z",
                failed_file="w",
                policy_revision=2,
            )
        )
        s.commit()
    with Session(engine) as s:
        rows = list(
            s.exec(
                select(PolicyApplyEvent)
                .where(PolicyApplyEvent.result == "rollback")
                .order_by(PolicyApplyEvent.ts.desc())
            )
        )
        assert [r.policy_revision for r in rows] == [2, 1]


def test_policy_apply_event_result_literal_rejects_invalid_value() -> None:
    """At the Pydantic write boundary (``model_validate``), result must be
    'success' or 'rollback'.

    Note: SQLModel ``table=True`` skips Pydantic validation on direct ``__init__``
    (SQLAlchemy compatibility), so the canonical write path used by API code is
    ``PolicyApplyEvent.model_validate({...})``. That is what we assert here.
    """
    # Valid values pass through model_validate
    ok = PolicyApplyEvent.model_validate(
        {"machine_id": "m1", "result": "success", "policy_revision": 1}
    )
    assert ok.result == "success"
    # Invalid value is rejected
    with pytest.raises(ValidationError):
        PolicyApplyEvent.model_validate(
            {"machine_id": "m1", "result": "weird", "policy_revision": 1}
        )
