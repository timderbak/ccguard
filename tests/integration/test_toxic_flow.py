"""Toxic-flow (confused-deputy) IOA — orchestrator, session-scope, dedup, tick.

``ioa.toxic_flow`` fires when external/untrusted content (``content.read.external``,
already emitted by the agent on WebFetch/WebSearch/every mcp__* call/untrusted
reads) is followed within the window, in the SAME session, by a weaponized sink:
config self-tamper, persistence, destruction, or exfil to a suspicious host.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.services import sequence_service
from ccguard.server.services.sequence_constants import (
    TAINT_SOURCE_SIGNAL,
    TOXIC_FLOW_RULE_ID,
)

pytestmark = pytest.mark.integration

TAINT = TAINT_SOURCE_SIGNAL


def _mk_machine(session: Session, mid: str) -> str:
    session.add(Machine(machine_id=mid, hostname="h"))
    session.commit()
    return mid


def _mk_event(
    session: Session,
    mid: str,
    signals: list[str],
    *,
    ts: datetime | None = None,
    session_id: str | None = "s1",
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
            session_id=session_id,
        )
    )
    session.commit()


def _toxic_findings(session: Session, mid: str) -> list[FindingRecord]:
    return list(
        session.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == mid)
            .where(FindingRecord.rule_id == TOXIC_FLOW_RULE_ID)
        )
    )


def test_external_then_config_tamper_fires_critical(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        mid = _mk_machine(s, "m-toxic")
        now = datetime.now(UTC)
        _mk_event(s, mid, [TAINT], ts=now - timedelta(minutes=3))
        _mk_event(s, mid, ["config.agent_settings_edit"], ts=now - timedelta(minutes=1))
        f = sequence_service.evaluate_one_toxic_flow(s, mid)
        assert f is not None
        assert f.severity == "critical"
        assert f.rule_id == TOXIC_FLOW_RULE_ID
        payload = json.loads(f.payload_json)
    assert payload["sink_class"] == "config_tamper"
    assert payload["taint_signal"] == TAINT
    assert payload["session_id"] == "s1"


def test_external_then_generic_egress_does_not_fire(client: TestClient) -> None:
    """Precision: MCP/web read then an ordinary curl (egress.http_client) is NOT
    a toxic flow — otherwise every MCP-using session would false-positive."""
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        mid = _mk_machine(s, "m-benign")
        now = datetime.now(UTC)
        _mk_event(s, mid, [TAINT], ts=now - timedelta(minutes=3))
        _mk_event(s, mid, ["egress.http_client"], ts=now - timedelta(minutes=1))
        assert sequence_service.evaluate_one_toxic_flow(s, mid) is None
        assert _toxic_findings(s, mid) == []


def test_cross_session_does_not_correlate(client: TestClient) -> None:
    """Taint in session A must not pair with a sink in session B (that would be
    unrelated work sharing a machine)."""
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        mid = _mk_machine(s, "m-xsession")
        now = datetime.now(UTC)
        _mk_event(s, mid, [TAINT], ts=now - timedelta(minutes=3), session_id="A")
        _mk_event(s, mid, ["persist.cron"], ts=now - timedelta(minutes=1), session_id="B")
        assert sequence_service.evaluate_one_toxic_flow(s, mid) is None


def test_same_day_dedup(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        mid = _mk_machine(s, "m-dedup")
        now = datetime.now(UTC)
        _mk_event(s, mid, [TAINT], ts=now - timedelta(minutes=3))
        _mk_event(s, mid, ["impact.delete"], ts=now - timedelta(minutes=1))
        first = sequence_service.evaluate_one_toxic_flow(s, mid)
        second = sequence_service.evaluate_one_toxic_flow(s, mid)
    assert first is not None
    assert second is None  # one per machine per day
    assert len(_toxic_findings_after(client, mid)) == 1


def _toxic_findings_after(client: TestClient, mid: str) -> list[FindingRecord]:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        return _toxic_findings(s, mid)


def test_tick_includes_toxic_flow(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        mid = _mk_machine(s, "m-tick")
        now = datetime.now(UTC)
        _mk_event(s, mid, [TAINT], ts=now - timedelta(minutes=3))
        _mk_event(s, mid, ["persist.ssh_authorized_keys"], ts=now - timedelta(minutes=1))
        summary = sequence_service.tick(s)
        assert summary["findings_emitted"] >= 1
        assert len(_toxic_findings(s, mid)) == 1
