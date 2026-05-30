"""Per-user risk scoring — daily UPSERT + 14-day series + UI."""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    Machine,
    MachineBaseline,
    MachineUserRiskHistory,
    ToolUseEvent,
)
from ccguard.server.services import risk_service
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.risk_history import (
    get_user_risk_history_14d,
    get_user_scores_today,
)
from ccguard.server.main import create_app


def _warm(session: Session, mid: str = "m-puc") -> str:
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


def _event(s: Session, mid: str, signals: list[str], actor: str | None) -> None:
    s.add(ToolUseEvent(
        machine_id=mid, ts=datetime.now(UTC),
        tool_name="Bash", fingerprint="0123456789abcdef",
        decision="allow", result_status="success",
        signals_json=json.dumps(signals), actor_user=actor,
    ))
    s.commit()


def test_risk_tick_writes_per_user_snapshots(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _event(s, mid, ["cred.read.aws"], "alice")
        _event(s, mid, ["egress.network_tool"], "bob")
        risk_service.tick(s)
        rows = list(s.exec(select(MachineUserRiskHistory).where(
            MachineUserRiskHistory.machine_id == mid
        )))
        actors = {r.actor_user for r in rows}
        assert actors == {"alice", "bob"}


def test_unattributed_event_gets_unknown_bucket(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _event(s, mid, ["cred.read.aws"], None)
        risk_service.tick(s)
        rows = list(s.exec(select(MachineUserRiskHistory)))
        assert any(r.actor_user == "_unknown" for r in rows)


def test_per_user_score_isolation(client: TestClient) -> None:
    """Alice's high-weight activity must NOT inflate Bob's score."""
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        # Alice fires three heavy signals.
        for _ in range(3):
            _event(s, mid, ["cred.read.aws", "egress.network_tool"], "alice")
        # Bob fires one cheap signal.
        _event(s, mid, ["discovery.recon"], "bob")
        risk_service.tick(s)
        scores = get_user_scores_today(s, machine_id=mid)
        by_actor = {r["actor"]: r["score"] for r in scores}
        assert by_actor["alice"] > by_actor["bob"] + 5


def test_get_user_risk_history_14d_fills_missing(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        today = datetime.now(UTC).date()
        s.add(MachineUserRiskHistory(
            machine_id=mid, actor_user="alice",
            date_utc=(today - timedelta(days=3)).isoformat(),
            score=7.5,
        ))
        s.commit()
        series = get_user_risk_history_14d(s, machine_id=mid, actor_user="alice")
        assert len(series) == 14
        # Day -3 has the row.
        assert series[10]["score"] == 7.5
        # Today (no row) defaults to 0.
        assert series[13]["score"] == 0.0


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-puc")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def test_machine_detail_shows_per_user_score_chip(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            mid = _warm(s, "m-puc-ui")
            for _ in range(3):
                _event(s, mid, ["cred.read.aws", "egress.network_tool"], "alice")
            _event(s, mid, ["discovery.recon"], "bob")
            risk_service.tick(s)
        r = client.get("/machines/m-puc-ui", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "Пользователи за 7 дней" in body
        assert "alice" in body
        assert "bob" in body
        # Score chips should be rendered (cc-risk-score class or numeric near user).
        assert "risk:" in body or re.search(r"alice[\s\S]{0,300}\d+\.\d", body)
    finally:
        client.__exit__(None, None, None)
