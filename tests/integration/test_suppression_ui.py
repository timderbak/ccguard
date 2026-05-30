"""Suppression UI: POST flow + machine_detail renders suppression list."""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import Machine, SettingsRecord
from ccguard.server.services import suppression_service
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-sup")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        now = datetime.now(UTC)
        s.add(Machine(machine_id="m-sup", first_seen=now, last_seen=now))
        s.commit()
        sid = create_session(s, user_id="admin")
    return client, sid


def _csrf(client: TestClient, sid: str) -> str:
    r = client.get("/machines/m-sup", cookies={"ccg_session": sid})
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m is not None
    return m.group(1)


def test_suppress_route_writes_setting(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        r = client.post(
            "/machines/m-sup/suppress",
            data={
                "signal_id": "cred.read.aws",
                "days": "30",
                "reason": "known dev workflow",
                "csrf_token": token,
            },
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            row = s.get(SettingsRecord, "suppress.m-sup.cred.read.aws")
            assert row is not None
            assert json.loads(row.value)["by"]  # session id, non-empty
    finally:
        client.__exit__(None, None, None)


def test_unsuppress_route_removes_setting(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            suppression_service.add(
                s, machine_id="m-sup", signal_id="cred.read.aws",
                days=30, reason="x", by="admin",
            )
        token = _csrf(client, sid)
        r = client.post(
            "/machines/m-sup/unsuppress",
            data={"signal_id": "cred.read.aws", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            assert s.get(SettingsRecord, "suppress.m-sup.cred.read.aws") is None
    finally:
        client.__exit__(None, None, None)


def test_machine_detail_renders_active_suppressions(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            suppression_service.add(
                s, machine_id="m-sup", signal_id="cred.read.aws",
                days=30, reason="dev workflow", by="admin",
            )
        r = client.get("/machines/m-sup", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "Заглушённые сигналы" in body
        assert "cred.read.aws" in body
        assert "dev workflow" in body


    finally:
        client.__exit__(None, None, None)


def test_invalid_days_rejected(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        r = client.post(
            "/machines/m-sup/suppress",
            data={"signal_id": "x.y", "days": "0", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 400
        r2 = client.post(
            "/machines/m-sup/suppress",
            data={"signal_id": "x.y", "days": "9999", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r2.status_code == 400
    finally:
        client.__exit__(None, None, None)
