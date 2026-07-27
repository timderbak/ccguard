"""Tests for machine_service compliance status logic."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session

from ccguard.server.db.models import InventorySnapshot, Machine, PolicyVersion
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.machine_service import (
    compliance_status,
    list_machines_with_status,
)


@pytest.fixture
def db():
    engine = make_engine("sqlite://")
    init_db(engine)
    with Session(engine) as s:
        yield s


def _ts(hours_ago: float) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours_ago)


def test_compliant() -> None:
    assert (
        compliance_status(
            last_seen=_ts(1),
            agent_policy_revision=5,
            current_published_revision=5,
            block_findings_count=0,
        )
        == "compliant"
    )


def test_policy_old() -> None:
    assert (
        compliance_status(
            last_seen=_ts(1),
            agent_policy_revision=4,
            current_published_revision=5,
            block_findings_count=0,
        )
        == "policy-old"
    )


def test_policy_old_when_revision_none() -> None:
    assert (
        compliance_status(
            last_seen=_ts(1),
            agent_policy_revision=None,
            current_published_revision=5,
            block_findings_count=0,
        )
        == "policy-old"
    )


def test_stale() -> None:
    assert (
        compliance_status(
            last_seen=_ts(24 * 8),
            agent_policy_revision=5,
            current_published_revision=5,
            block_findings_count=0,
        )
        == "stale"
    )


def test_blocking_overrides_other() -> None:
    # Even if stale and policy-old, blocking wins.
    assert (
        compliance_status(
            last_seen=_ts(24 * 30),
            agent_policy_revision=1,
            current_published_revision=10,
            block_findings_count=2,
        )
        == "blocking"
    )


def test_non_claude_agent_is_visibility_only_not_compliant() -> None:
    # Свежий Cursor-агент НЕ должен показываться зелёным «соответствует»
    # (переобещание защиты) — только «видимость». Enforcement-лесенка к нему
    # неприменима: нет ни блокировки, ни ccguard-policy.
    assert (
        compliance_status(
            last_seen=_ts(1),
            agent_policy_revision=None,
            current_published_revision=10,
            block_findings_count=0,
            agent_kind="cursor",
        )
        == "visibility-only"
    )


def test_non_claude_agent_stale_when_silent() -> None:
    # Молчащий Cursor честно показывается «молчит», а не «видимость».
    assert (
        compliance_status(
            last_seen=_ts(24 * 30),
            agent_policy_revision=None,
            current_published_revision=10,
            block_findings_count=0,
            agent_kind="cursor",
        )
        == "stale"
    )


def test_claude_code_default_unchanged() -> None:
    # Явный agent_kind=claude_code — прежнее поведение, регрессия-страховка.
    assert (
        compliance_status(
            last_seen=_ts(1),
            agent_policy_revision=5,
            current_published_revision=5,
            block_findings_count=0,
            agent_kind="claude_code",
        )
        == "compliant"
    )


def test_fleet_agent_posture_counts_enforced_and_visibility_only() -> None:
    from types import SimpleNamespace

    from ccguard.server.services.machine_service import fleet_agent_posture

    machines = [
        SimpleNamespace(agent_kind="claude_code"),
        SimpleNamespace(agent_kind="claude_code"),
        SimpleNamespace(agent_kind="cursor"),
        SimpleNamespace(agent_kind=None),  # None трактуется как claude_code
    ]
    p = fleet_agent_posture(machines)  # type: ignore[arg-type]
    assert p["total"] == 4
    assert p["enforced"] == 3          # 2 claude + 1 None
    assert p["visibility_only"] == 1   # cursor
    assert p["by_kind"]["claude_code"] == 3
    assert p["by_kind"]["cursor"] == 1


def test_fleet_agent_posture_empty() -> None:
    from ccguard.server.services.machine_service import fleet_agent_posture

    p = fleet_agent_posture([])
    assert p == {"total": 0, "enforced": 0, "visibility_only": 0, "by_kind": {}}


def test_naive_datetime_treated_as_utc() -> None:
    # SQLite roundtrips can strip tzinfo.
    naive = (datetime.now(UTC) - timedelta(hours=1)).replace(tzinfo=None)
    assert (
        compliance_status(
            last_seen=naive,
            agent_policy_revision=5,
            current_published_revision=5,
            block_findings_count=0,
        )
        == "compliant"
    )


def test_list_machines_returns_one_compliant(db) -> None:
    now = datetime.now(UTC)
    db.add(
        PolicyVersion(
            revision=5,
            status="published",
            yaml_text="meta:\n  revision: 5",
            created_by="admin",
        )
    )
    db.add(
        Machine(
            machine_id="m1",
            machine_label="laptop",
            first_seen=now,
            last_seen=now,
            agent_version="0.1.0",
        )
    )
    db.add(
        InventorySnapshot(
            machine_id="m1",
            received_at=now,
            payload_json=json.dumps({"meta": {"revision": 5}}),
        )
    )
    db.commit()

    rows = list_machines_with_status(db)
    assert len(rows) == 1
    row = rows[0]
    assert row.machine_id == "m1"
    assert row.agent_policy_revision == 5
    assert row.warn_count == 0
    assert row.block_count == 0
    assert row.status == "compliant"
