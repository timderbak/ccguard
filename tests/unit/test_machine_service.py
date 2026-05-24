"""Tests for machine_service compliance status logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccguard.server.services.machine_service import compliance_status


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
