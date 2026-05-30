"""Sequence tick: warm-up guard, same-day dedup, high-severity finding."""
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
from ccguard.server.services import sequence_service
from ccguard.server.services.sequence_constants import SEQUENCE_RULE_ID


def _mk_machine(session: Session, mid: str = "m-seq", *, warm: bool = True) -> str:
    session.add(Machine(machine_id=mid, hostname="h"))
    if warm:
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


def _mk_event(
    session: Session, mid: str, signals: list[str], ts: datetime | None = None
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
        mid = _mk_machine(session, "m-cold", warm=False)
        now = datetime.now(UTC)
        _mk_event(session, mid, ["cred.read.aws"], ts=now - timedelta(minutes=2))
        _mk_event(session, mid, ["egress.network_tool"], ts=now)
        summary = sequence_service.tick(session)
        assert summary["findings_emitted"] == 0


def test_cred_only_no_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        mid = _mk_machine(session)
        _mk_event(session, mid, ["cred.read.aws"])
        summary = sequence_service.tick(session)
        assert summary["findings_emitted"] == 0


def test_cred_then_egress_in_window_emits_high_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        mid = _mk_machine(session)
        now = datetime.now(UTC)
        _mk_event(session, mid, ["cred.read.aws"], ts=now - timedelta(minutes=5))
        _mk_event(session, mid, ["egress.network_tool"], ts=now)
        summary = sequence_service.tick(session)
        assert summary["findings_emitted"] == 1

        f = session.exec(
            select(FindingRecord).where(FindingRecord.rule_id == SEQUENCE_RULE_ID)
        ).first()
        assert f is not None
        assert f.severity == "high"
        assert f.machine_id == mid
        payload = json.loads(f.payload_json)
        assert payload["cred_signal"] == "cred.read.aws"
        assert payload["egress_signal"] == "egress.network_tool"
        assert payload["elapsed_seconds"] >= 0.0
        assert "window_minutes" in payload


def test_same_day_dedup(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        mid = _mk_machine(session)
        now = datetime.now(UTC)
        _mk_event(session, mid, ["cred.read.aws"], ts=now - timedelta(minutes=2))
        _mk_event(session, mid, ["egress.network_tool"], ts=now)
        sequence_service.tick(session)
        sequence_service.tick(session)
        rows = list(
            session.exec(
                select(FindingRecord).where(FindingRecord.rule_id == SEQUENCE_RULE_ID)
            )
        )
        assert len(rows) == 1


def test_only_one_of_two_machines_matches(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        m_hot = _mk_machine(session, "m-hot")
        m_quiet = _mk_machine(session, "m-quiet")
        now = datetime.now(UTC)
        _mk_event(session, m_hot, ["cred.read.aws"], ts=now - timedelta(minutes=3))
        _mk_event(session, m_hot, ["egress.network_tool"], ts=now)
        _mk_event(session, m_quiet, ["discovery.recon"], ts=now)
        summary = sequence_service.tick(session)
        assert summary["findings_emitted"] == 1
        rows = list(
            session.exec(
                select(FindingRecord).where(FindingRecord.rule_id == SEQUENCE_RULE_ID)
            )
        )
        assert len(rows) == 1
        assert rows[0].machine_id == m_hot
