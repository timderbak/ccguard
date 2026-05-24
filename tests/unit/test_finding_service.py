"""Tests for finding_service.query_findings filters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.finding_service import query_findings


@pytest.fixture
def db():
    engine = make_engine("sqlite://")
    init_db(engine)
    with Session(engine) as s:
        now = datetime.now(UTC)
        s.add(
            FindingRecord(
                machine_id="m1",
                inventory_id=1,
                rule_id="mcp.denylist",
                severity="warn",
                discovered_at=now - timedelta(minutes=3),
                payload_json="{}",
            )
        )
        s.add(
            FindingRecord(
                machine_id="m1",
                inventory_id=1,
                rule_id="agents.forbidden_tool",
                severity="warn",
                discovered_at=now - timedelta(minutes=2),
                payload_json="{}",
            )
        )
        s.add(
            FindingRecord(
                machine_id="m2",
                inventory_id=2,
                rule_id="permissions.dangerously_skip",
                severity="block",
                discovered_at=now - timedelta(minutes=1),
                payload_json="{}",
            )
        )
        s.commit()
        yield s


def test_query_no_filters_returns_all(db) -> None:
    rows = query_findings(db)
    assert len(rows) == 3


def test_query_filter_by_severity(db) -> None:
    rows = query_findings(db, severity="block")
    assert len(rows) == 1
    assert rows[0].rule_id == "permissions.dangerously_skip"


def test_query_filter_by_rule_id(db) -> None:
    rows = query_findings(db, rule_id="agents.forbidden_tool")
    assert len(rows) == 1
    assert rows[0].machine_id == "m1"


def test_query_filter_by_machine(db) -> None:
    rows = query_findings(db, machine_id="m1")
    assert len(rows) == 2


def test_query_respects_limit(db) -> None:
    rows = query_findings(db, limit=2)
    assert len(rows) == 2
