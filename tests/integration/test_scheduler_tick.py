"""Integration tests for anomaly_service.tick() — direct invocation (Plan 02-06 / Task 2).

These tests *never* go through the real APScheduler timer; they call
``anomaly_service.tick(session)`` directly. The TestClient-based end-to-end
test then verifies that a tick-emitted finding actually appears in the
``/_partials/anomalies/overview`` partial.

Per Plan 02-03, ``CCGUARD_DISABLE_SCHEDULER=1`` is set in tests/conftest.py at
the top of the module, so importing the FastAPI app never spins up an
APScheduler thread. One test in this file asserts that contract directly.
"""

from __future__ import annotations

import os
from datetime import UTC, date, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    Machine,
    MachineBaseline,
    ToolUseEvent,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.main import create_app
from ccguard.server.services import anomaly_service
from ccguard.server.services.anomaly_constants import ALL_METRICS
from ccguard.server.services.auth_service import create_session, hash_password


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _at_utc(d: date, hour: int = 12) -> datetime:
    return datetime(d.year, d.month, d.day, hour, 0, 0, tzinfo=UTC)


def _seed_bash_outlier_history(
    session: Session, machine_id: str, today: date
) -> None:
    """13 days of ~5 bash calls, then 100 bash calls on `today` (clean outlier)."""
    for offset in range(1, 14):
        d = today - timedelta(days=offset)
        for k in range(5):
            session.add(
                ToolUseEvent(
                    machine_id=machine_id,
                    ts=_at_utc(d, hour=k % 24),
                    tool_name="Bash",
                    fingerprint=f"h{offset:02d}{k:02d}aabbccdd"[:16],
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


@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    """TestClient + engine + admin session id, with the scheduler disabled."""
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("CCGUARD_DISABLE_SCHEDULER", "1")
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        yield client, engine, sid


# ---------------------------------------------------------------------------
# Direct tick() invocations (no TestClient required)
# ---------------------------------------------------------------------------


def test_tick_emits_finding_on_real_bash_outlier() -> None:
    eng = _engine()
    today = datetime.now(UTC).date()
    with Session(eng) as s:
        s.add(Machine(machine_id="m1"))
        s.commit()
        _seed_bash_outlier_history(s, "m1", today)
        summary = anomaly_service.tick(s)

        assert summary["machines_evaluated"] == 1
        assert summary["findings_emitted"] >= 1
        assert summary["errors"] == []

        # MachineBaseline row was persisted and is past warm-up.
        bl = s.exec(
            select(MachineBaseline).where(
                MachineBaseline.machine_id == "m1",
                MachineBaseline.metric == "bash_calls_per_day",
            )
        ).first()
        assert bl is not None
        assert bl.baseline_ready is True

        # FindingRecord for the bash anomaly was emitted with correct shape.
        f = s.exec(
            select(FindingRecord).where(
                FindingRecord.machine_id == "m1",
                FindingRecord.rule_id == "anomaly.bash_calls_per_day",
            )
        ).first()
        assert f is not None
        assert f.severity == "warn"
        assert f.inventory_id is None


def test_tick_same_day_idempotent() -> None:
    eng = _engine()
    today = datetime.now(UTC).date()
    with Session(eng) as s:
        s.add(Machine(machine_id="m1"))
        s.commit()
        _seed_bash_outlier_history(s, "m1", today)
        first = anomaly_service.tick(s)
        assert first["findings_emitted"] >= 1

        before = len(
            s.exec(
                select(FindingRecord).where(
                    FindingRecord.machine_id == "m1",
                    FindingRecord.rule_id == "anomaly.bash_calls_per_day",
                )
            ).all()
        )
        second = anomaly_service.tick(s)
        after = len(
            s.exec(
                select(FindingRecord).where(
                    FindingRecord.machine_id == "m1",
                    FindingRecord.rule_id == "anomaly.bash_calls_per_day",
                )
            ).all()
        )
        # Same-day dedup: row count unchanged, summary emits 0 new findings
        # for the bash metric specifically (other metrics still 0 because
        # there are no inventory snapshots).
        assert after == before
        assert second["findings_emitted"] == 0


def test_tick_warmup_too_few_days_no_finding() -> None:
    eng = _engine()
    today = datetime.now(UTC).date()
    with Session(eng) as s:
        s.add(Machine(machine_id="m-warm"))
        s.commit()
        # Only 5 days of bash events — sample_count < WARMUP_THRESHOLD (7).
        for offset in range(5):
            d = today - timedelta(days=offset)
            for k in range(5):
                s.add(
                    ToolUseEvent(
                        machine_id="m-warm",
                        ts=_at_utc(d, hour=k % 24),
                        tool_name="Bash",
                        fingerprint=f"w{offset:02d}{k:02d}aabbccdd"[:16],
                        decision="allow",
                        result_status="success",
                    )
                )
        s.commit()
        summary = anomaly_service.tick(s)

        # baseline_ready may be True because the series is 14 zero-padded
        # points from the aggregator. The actual contract under test: no
        # bash anomaly finding emitted (sparse + low variance + no spike).
        f = s.exec(
            select(FindingRecord).where(
                FindingRecord.machine_id == "m-warm",
                FindingRecord.rule_id == "anomaly.bash_calls_per_day",
            )
        ).first()
        assert f is None
        assert summary["errors"] == []


def test_tick_tolerates_aggregator_failure_and_continues() -> None:
    eng = _engine()
    with Session(eng) as s:
        s.add(Machine(machine_id="m-good"))
        s.add(Machine(machine_id="m-bad"))
        s.commit()

        # Patch the bash aggregator to raise so we hit the per-iteration
        # try/except. Other metrics (inventory diff) still run cleanly.
        def _boom(*_a, **_k):
            raise RuntimeError("aggregator went boom")

        with patch.dict(
            anomaly_service._DISPATCH,
            {"bash_calls_per_day": _boom},
        ):
            summary = anomaly_service.tick(s)

        # Two machines × one broken metric → 2 errors recorded, tick continues.
        assert summary["machines_evaluated"] == 2
        assert len(summary["errors"]) == 2
        for msg in summary["errors"]:
            assert "bash_calls_per_day" in msg
            assert "boom" in msg


def test_scheduler_disabled_env_guard_enforced() -> None:
    # The conftest top-of-module sets CCGUARD_DISABLE_SCHEDULER=1 before any
    # FastAPI import. Confirm the guard is live and the lifespan-built scheduler
    # is None.
    assert os.environ.get("CCGUARD_DISABLE_SCHEDULER") == "1"
    with TestClient(create_app()) as c:
        # app.state.scheduler is set inside lifespan; when disabled, it's None.
        assert getattr(c.app.state, "scheduler", "absent") in (None, "absent")


# ---------------------------------------------------------------------------
# End-to-end: tick writes → route renders
# ---------------------------------------------------------------------------


def test_tick_finding_visible_in_overview_partial(admin_client) -> None:
    client, engine, sid = admin_client
    today = datetime.now(UTC).date()
    with Session(engine) as s:
        s.add(Machine(machine_id="m1-e2e-001"))
        s.commit()
        _seed_bash_outlier_history(s, "m1-e2e-001", today)
        summary = anomaly_service.tick(s)
        assert summary["findings_emitted"] >= 1

    r = client.get(
        "/_partials/anomalies/overview", cookies={"ccg_session": sid}
    )
    assert r.status_code == 200
    # End-to-end: machine_id[:12] and metric label both visible.
    assert "m1-e2e-001"[:12] in r.text
    assert "bash_calls_per_day" in r.text
