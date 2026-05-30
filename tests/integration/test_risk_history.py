"""Risk history snapshots fed by risk_tick + 14-day fetch helper."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    Machine,
    MachineBaseline,
    MachineRiskHistory,
    ToolUseEvent,
)
from ccguard.server.services import risk_service
from ccguard.server.services.risk_history import get_risk_history_14d


def _warm(session: Session, mid: str = "m-hist") -> str:
    now = datetime.now(UTC)
    session.add(Machine(machine_id=mid, first_seen=now, last_seen=now))
    session.add(
        MachineBaseline(
            machine_id=mid, metric="bash_calls_per_day",
            mean=1.0, stdev=0.5, sample_count=14, baseline_ready=True,
        )
    )
    session.commit()
    return mid


def _event(session: Session, mid: str, signals: list[str]) -> None:
    session.add(
        ToolUseEvent(
            machine_id=mid, ts=datetime.now(UTC),
            tool_name="Bash", fingerprint="0123456789abcdef",
            decision="allow", result_status="success",
            signals_json=json.dumps(signals),
        )
    )
    session.commit()


def test_risk_tick_writes_daily_snapshot(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _event(s, mid, ["cred.read.aws", "egress.network_tool"])
        risk_service.tick(s)
        rows = list(s.exec(select(MachineRiskHistory)))
        assert len(rows) == 1
        assert rows[0].machine_id == mid
        assert rows[0].score > 0
        assert rows[0].date_utc == datetime.now(UTC).date().isoformat()
        assert rows[0].top_signal in {"cred.read.aws", "egress.network_tool"}


def test_risk_tick_upserts_same_day(client: TestClient) -> None:
    """Multiple ticks on the same UTC day refresh the row, don't insert duplicates."""
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _event(s, mid, ["cred.read.aws"])
        risk_service.tick(s)
        _event(s, mid, ["egress.network_tool"])
        risk_service.tick(s)
        rows = list(
            s.exec(select(MachineRiskHistory).where(MachineRiskHistory.machine_id == mid))
        )
        assert len(rows) == 1
        # Score should reflect both events.
        assert rows[0].score > 5  # cred (5) + egress (4) with small decay


def test_risk_tick_writes_zero_for_warm_but_quiet_machine(client: TestClient) -> None:
    """A warm machine with no signal events still gets a 0-score row so
    the sparkline shows continuous data, not gaps."""
    with Session(client.app.state.engine) as s:
        mid = _warm(s, "m-quiet")
        risk_service.tick(s)
        rows = list(s.exec(select(MachineRiskHistory).where(MachineRiskHistory.machine_id == mid)))
        assert len(rows) == 1
        assert rows[0].score == 0.0
        assert rows[0].top_signal is None


def test_get_risk_history_14d_returns_aligned_series(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        today = datetime.now(UTC).date()
        for delta in (0, 1, 5, 13, 14):
            s.add(MachineRiskHistory(
                machine_id=mid,
                date_utc=(today - timedelta(days=delta)).isoformat(),
                score=float(delta),
                top_signal="x" if delta == 0 else None,
            ))
        s.commit()
        series = get_risk_history_14d(s, mid)
        assert len(series) == 14
        # Latest day is index 13 (rightmost on chart).
        assert series[13]["date"] == today.isoformat()
        assert series[13]["score"] == 0.0  # today's row
        # Day 14 ago is outside the window.
        assert all(p["date"] != (today - timedelta(days=14)).isoformat() for p in series)


def test_get_risk_history_14d_fills_missing_days_with_zero(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s, "m-sparse")
        # Only the 7-days-ago row exists.
        today = datetime.now(UTC).date()
        s.add(MachineRiskHistory(
            machine_id=mid,
            date_utc=(today - timedelta(days=7)).isoformat(),
            score=8.5,
        ))
        s.commit()
        series = get_risk_history_14d(s, mid)
        assert len(series) == 14
        assert series[6]["score"] == 8.5
        # All other days zero.
        zero_count = sum(1 for p in series if p["score"] == 0.0)
        assert zero_count == 13
