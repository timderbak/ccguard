"""Snapshot tests for representative pages — anti-brittle replacement for
exact-markup substring asserts.

To regenerate after an intentional UI change::

    CCGUARD_UPDATE_SNAPSHOTS=1 uv run pytest tests/integration/test_render_snapshots.py

The helper normalizes dynamic content (CSRF, timestamps, hex IDs) so reruns
on different days produce stable diffs.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import (
    FindingRecord,
    InventorySnapshot,
    Machine,
    MachineRiskHistory,
)
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.risk_constants import RISK_RULE_ID
from ccguard.server.main import create_app

from tests._snapshot import assert_snapshot


def _login(monkeypatch, tmp_path, db_name: str = "snap.db") -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/{db_name}")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-snap")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def test_overview_empty_snapshot(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert_snapshot("overview_empty.html", r.text)
    finally:
        client.__exit__(None, None, None)


def test_machine_detail_with_risk_and_sparkline_snapshot(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path, db_name="snap-md.db")
    try:
        engine = client.app.state.engine
        with Session(engine) as s:
            now = datetime.now(UTC)
            s.add(Machine(machine_id="m-snap", machine_label="snapbox",
                          first_seen=now, last_seen=now, agent_version="0.2.0"))
            s.add(InventorySnapshot(
                machine_id="m-snap", received_at=now,
                payload_json=json.dumps({"mcp_servers": [{"name": "fs"}]}),
            ))
            s.add(FindingRecord(
                machine_id="m-snap", inventory_id=None, rule_id=RISK_RULE_ID,
                severity="warn", discovered_at=now,
                payload_json=json.dumps({
                    "score": 12.0, "threshold": 10.0,
                    "window_hours": 24.0, "half_life_hours": 6.0,
                    "contributions": {"cred.read.aws": 5.0, "egress.network_tool": 4.0},
                    "event_count": 1,
                }),
            ))
            # Seed 3 sparkline days for visual interest.
            today = now.date()
            from datetime import timedelta
            for i, score in enumerate([0.0, 5.0, 12.0]):
                s.add(MachineRiskHistory(
                    machine_id="m-snap",
                    date_utc=(today - timedelta(days=2 - i)).isoformat(),
                    score=score,
                    top_signal="cred.read.aws" if score > 0 else None,
                ))
            s.commit()
        r = client.get("/machines/m-snap", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert_snapshot("machine_detail_with_risk.html", r.text)
    finally:
        client.__exit__(None, None, None)


def test_login_page_snapshot(monkeypatch, tmp_path):
    client, _ = _login(monkeypatch, tmp_path, db_name="snap-login.db")
    try:
        r = client.get("/login")
        assert r.status_code == 200
        assert_snapshot("login.html", r.text)
    finally:
        client.__exit__(None, None, None)
