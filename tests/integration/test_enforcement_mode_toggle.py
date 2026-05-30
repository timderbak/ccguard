"""Admin UI toggle for enforcement_mode + /api/v1/policy injection."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.settings_service import (
    get_enforcement_mode,
    set_setting,
)
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-emt")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def _csrf(client: TestClient, sid: str) -> str:
    r = client.get("/settings", cookies={"ccg_session": sid})
    assert r.status_code == 200
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m is not None
    return m.group(1)


def test_settings_page_shows_current_mode(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/settings", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Режим работы" in r.text
        # default is observe.
        assert "observe" in r.text
    finally:
        client.__exit__(None, None, None)


def test_post_switches_to_enforce(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        r = client.post(
            "/settings/enforcement-mode",
            data={"mode": "enforce", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            assert get_enforcement_mode(s) == "enforce"
    finally:
        client.__exit__(None, None, None)


def test_post_back_to_observe(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            set_setting(s, "enforcement_mode", "enforce")
        token = _csrf(client, sid)
        r = client.post(
            "/settings/enforcement-mode",
            data={"mode": "observe", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            assert get_enforcement_mode(s) == "observe"
    finally:
        client.__exit__(None, None, None)


def test_invalid_mode_rejected(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        r = client.post(
            "/settings/enforcement-mode",
            data={"mode": "bogus", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 400
    finally:
        client.__exit__(None, None, None)


def test_policy_api_reflects_admin_toggle(client: TestClient, auth_headers) -> None:
    # Default in fresh DB → observe.
    r1 = client.get("/api/v1/policy", headers=auth_headers)
    assert r1.status_code == 200
    assert r1.json()["enforcement_mode"] == "observe"
    etag_before = r1.headers["ETag"]

    with Session(client.app.state.engine) as s:
        set_setting(s, "enforcement_mode", "enforce")

    r2 = client.get("/api/v1/policy", headers=auth_headers)
    assert r2.json()["enforcement_mode"] == "enforce"
    # ETag must change so agents invalidate their cached policy.
    assert r2.headers["ETag"] != etag_before
