"""Risk tick: warm-up guard, threshold gate, dedup, finding payload shape."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    Machine,
    MachineBaseline,
    ToolUseEvent,
)
from ccguard.server.services import risk_service
from ccguard.server.services.risk_constants import RISK_RULE_ID


def _seed_warm_machine(session: Session, mid: str = "m-risk") -> str:
    session.add(Machine(machine_id=mid, hostname="h"))
    session.add(
        MachineBaseline(
            machine_id=mid,
            metric="bash_calls_per_day",
            mean=1.0,
            stdev=0.5,
            sample_count=14,
            baseline_ready=True,
        )
    )
    session.commit()
    return mid


def _add_event(
    session: Session,
    mid: str,
    signals: list[str],
    ts: datetime | None = None,
) -> None:
    session.add(
        ToolUseEvent(
            machine_id=mid,
            ts=ts or datetime.now(UTC),
            tool_name="Bash",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps(signals),
        )
    )
    session.commit()


def test_no_warm_baseline_no_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        session.add(Machine(machine_id="m-cold", hostname="h"))
        session.commit()
        _add_event(session, "m-cold", ["cred.read.aws", "egress.network_tool"])
        summary = risk_service.tick(session)
    assert summary["findings_emitted"] == 0


def test_below_threshold_no_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        mid = _seed_warm_machine(session)
        _add_event(session, mid, ["discovery.recon"])  # weight 1.0, default threshold 10
        summary = risk_service.tick(session)
    assert summary["findings_emitted"] == 0


def test_above_threshold_emits_finding_with_breakdown(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        mid = _seed_warm_machine(session)
        # cred (5) + egress (4) + pipe (4) = 13 > default threshold 10
        _add_event(
            session,
            mid,
            ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"],
        )
        summary = risk_service.tick(session)
        assert summary["findings_emitted"] == 1
        f = session.exec(
            select(FindingRecord).where(FindingRecord.rule_id == RISK_RULE_ID)
        ).first()
    assert f is not None
    payload = json.loads(f.payload_json)
    assert payload["score"] >= 13.0 - 0.01
    assert "contributions" in payload
    assert set(payload["contributions"]) == {
        "cred.read.aws",
        "egress.network_tool",
        "exec.pipe_to_shell",
    }
    assert payload["event_count"] == 1


def test_same_day_dedup(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        mid = _seed_warm_machine(session)
        _add_event(
            session,
            mid,
            ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"],
        )
        risk_service.tick(session)
        risk_service.tick(session)
        rows = list(
            session.exec(
                select(FindingRecord).where(FindingRecord.rule_id == RISK_RULE_ID)
            )
        )
    assert len(rows) == 1


def test_events_outside_window_ignored(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        mid = _seed_warm_machine(session)
        old_ts = datetime.now(UTC) - timedelta(hours=48)  # default window 24h
        _add_event(
            session,
            mid,
            ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"],
            ts=old_ts,
        )
        summary = risk_service.tick(session)
    assert summary["findings_emitted"] == 0
