"""One-click signal suppression — per (machine, signal) with TTL."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    Machine,
    MachineBaseline,
    SettingsRecord,
    ToolUseEvent,
)
from ccguard.server.services import risk_service, suppression_service


def _warm(session: Session, mid: str = "m-sup") -> str:
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


def test_add_writes_setting_with_ttl(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        suppression_service.add(
            s, machine_id="m1", signal_id="cred.read.aws",
            days=30, reason="known dev workflow", by="admin",
        )
        row = s.get(SettingsRecord, "suppress.m1.cred.read.aws")
        assert row is not None
        payload = json.loads(row.value)
        assert payload["reason"] == "known dev workflow"
        assert payload["by"] == "admin"
        assert "until" in payload


def test_list_active_returns_only_unexpired(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        suppression_service.add(s, machine_id="m1", signal_id="cred.read.aws",
                                days=30, reason="x", by="admin")
        # Manually backdate an "expired" entry.
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        s.add(SettingsRecord(
            key="suppress.m1.egress.network_tool",
            value=json.dumps({"until": past, "reason": "old", "by": "admin"}),
        ))
        s.commit()
        active = suppression_service.list_active(s, machine_id="m1", now=datetime.now(UTC))
        assert active == {"cred.read.aws"}


def test_list_active_skips_corrupt_entries(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        s.add(SettingsRecord(key="suppress.m1.bad.signal", value="{not json"))
        s.commit()
        assert suppression_service.list_active(s, machine_id="m1", now=datetime.now(UTC)) == set()


def test_remove_deletes_entry(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        suppression_service.add(s, machine_id="m1", signal_id="cred.read.aws",
                                days=30, reason="x", by="admin")
        suppression_service.remove(s, machine_id="m1", signal_id="cred.read.aws")
        assert s.get(SettingsRecord, "suppress.m1.cred.read.aws") is None


def test_risk_tick_ignores_suppressed_signals(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _event(s, mid, ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"])
        # Suppress the big-weight signal.
        suppression_service.add(s, machine_id=mid, signal_id="cred.read.aws",
                                days=30, reason="known", by="admin")
        summary = risk_service.tick(s)
        # Score before: 5+4+4=13, threshold 10 → would fire.
        # With cred.read.aws suppressed: 4+4=8 < 10 → no finding.
        assert summary["findings_emitted"] == 0


def test_suppression_expiry_restores_signal(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _event(s, mid, ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"])
        # Insert an already-expired suppression manually.
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        s.add(SettingsRecord(
            key=f"suppress.{mid}.cred.read.aws",
            value=json.dumps({"until": past, "reason": "x", "by": "admin"}),
        ))
        s.commit()
        summary = risk_service.tick(s)
        # Expired → signal counts → finding fires.
        assert summary["findings_emitted"] == 1


def test_suppression_per_machine_isolation(client: TestClient) -> None:
    """Suppression for m1 must not affect m2."""
    with Session(client.app.state.engine) as s:
        m1 = _warm(s, "m1")
        m2 = _warm(s, "m2")
        _event(s, m1, ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"])
        _event(s, m2, ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"])
        suppression_service.add(s, machine_id=m1, signal_id="cred.read.aws",
                                days=30, reason="x", by="admin")
        summary = risk_service.tick(s)
        # m1 suppressed → no finding; m2 not suppressed → 1 finding.
        assert summary["findings_emitted"] == 1
