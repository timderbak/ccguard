"""Fleet risk helper + overview panel rendering."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import Machine, MachineBaseline, ToolUseEvent
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.fleet_risk import compute_fleet_risk
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-fleet")
    return TestClient(create_app())


def _warm_machine(session: Session, mid: str, label: str | None = None) -> None:
    now = datetime.now(UTC)
    session.add(
        Machine(machine_id=mid, machine_label=label, first_seen=now, last_seen=now)
    )
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


def _add_event(session: Session, mid: str, signals: list[str]) -> None:
    session.add(
        ToolUseEvent(
            machine_id=mid,
            ts=datetime.now(UTC),
            tool_name="Bash",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps(signals),
        )
    )
    session.commit()


def test_compute_fleet_risk_sorts_desc_with_top_contributor(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _warm_machine(s, "m-hot", "hotbox")
            _warm_machine(s, "m-cool", "coolbox")
            _warm_machine(s, "m-idle", "idlebox")
            _add_event(s, "m-hot", ["cred.read.aws", "egress.network_tool"])  # 9
            _add_event(s, "m-cool", ["discovery.recon"])  # 1
            # m-idle has no signal events.
            rows = compute_fleet_risk(s, limit=10)

        assert [r["machine_id"] for r in rows[:2]] == ["m-hot", "m-cool"]
        assert rows[0]["score"] > rows[1]["score"]
        # Top contributor is the highest-weighted signal.
        assert rows[0]["top_signal"] == "cred.read.aws"
        # Idle warm machine is included with score 0.
        idle = next((r for r in rows if r["machine_id"] == "m-idle"), None)
        assert idle is not None
        assert idle["score"] == 0.0


def test_compute_fleet_risk_skips_cold_machines(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            now = datetime.now(UTC)
            s.add(Machine(machine_id="m-cold", first_seen=now, last_seen=now))
            s.commit()
            _add_event(s, "m-cold", ["cred.read.aws"])
            rows = compute_fleet_risk(s, limit=10)
        assert all(r["machine_id"] != "m-cold" for r in rows)


def test_compute_fleet_risk_respects_limit(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            for i in range(5):
                _warm_machine(s, f"m-{i}")
                _add_event(s, f"m-{i}", ["cred.read.aws"])
            rows = compute_fleet_risk(s, limit=3)
        assert len(rows) == 3


def test_overview_page_renders_fleet_risk_panel(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _warm_machine(s, "m-hot", "hotbox")
            _add_event(s, "m-hot", ["cred.read.aws", "egress.network_tool"])
            sid = create_session(s, user_id="admin")
        r = client.get("/", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "Риск флота" in body
        assert "hotbox" in body or "m-hot" in body
        assert "cred.read.aws" in body
