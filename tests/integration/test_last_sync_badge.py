"""Last-sync freshness badge on machine_detail (D3)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import Machine
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-d3")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def _machine(s, mid, last_seen):
    s.add(Machine(machine_id=mid, first_seen=last_seen,
                  last_seen=last_seen, agent_version="0.2.0"))
    s.commit()


def test_fresh_sync_renders_emerald_badge(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            _machine(s, "m-fresh", datetime.now(UTC) - timedelta(minutes=5))
        r = client.get("/machines/m-fresh", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "sync: 5 мин назад" in body
        assert "bg-emerald-50" in body
    finally:
        client.__exit__(None, None, None)


def test_stale_sync_renders_amber_badge(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            _machine(s, "m-stale", datetime.now(UTC) - timedelta(hours=3))
        r = client.get("/machines/m-stale", cookies={"ccg_session": sid})
        body = r.text
        assert "sync: 3 ч назад" in body
        assert "bg-amber-50" in body
    finally:
        client.__exit__(None, None, None)


def test_missing_sync_renders_red_badge(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            _machine(s, "m-gone", datetime.now(UTC) - timedelta(days=5))
        r = client.get("/machines/m-gone", cookies={"ccg_session": sid})
        body = r.text
        assert "sync: 5 дн назад" in body
        assert "bg-red-50" in body
    finally:
        client.__exit__(None, None, None)
