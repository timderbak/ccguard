"""PI-pattern admin UI form on /admin/proposed-signals."""
from __future__ import annotations

import json
import re

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ProposedSignal, SettingsRecord
from ccguard.server.services import proposed_signal_service as svc
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-pi-ui")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def _csrf(client: TestClient, sid: str) -> str:
    r = client.get("/admin/proposed-signals", cookies={"ccg_session": sid})
    assert r.status_code == 200
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m is not None
    return m.group(1)


def test_admin_page_renders_pi_form(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/admin/proposed-signals", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "PI-паттерн вручную" in body
        assert 'action="/admin/proposed-signals/draft-pi-from-text"' in body
    finally:
        client.__exit__(None, None, None)


def test_post_pi_draft_creates_pi_pattern_proposal(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        draft = {
            "category": "tool_hijack_dans",
            "pattern": r"do anything now\s*\(",
            "description": "DANs hijack variant",
        }
        r = client.post(
            "/admin/proposed-signals/draft-pi-from-text",
            data={"draft_json": json.dumps(draft), "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            row = s.exec(select(ProposedSignal)).first()
            assert row is not None
            assert row.kind == "pi_pattern"
            assert row.source_kind == "manual-pi"
    finally:
        client.__exit__(None, None, None)


def test_pending_pane_shows_pi_badge_for_pi_drafts(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            svc.propose(
                s,
                draft={"category": "test_cat", "pattern": "x", "description": "x"},
                source_kind="manual-pi",
                kind="pi_pattern",
            )
        r = client.get("/admin/proposed-signals", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "test_cat" in body
        # The amber PI badge must render.
        assert "bg-amber-50 text-amber-700" in body
    finally:
        client.__exit__(None, None, None)


def test_post_pi_draft_with_bad_shape_returns_400(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        r = client.post(
            "/admin/proposed-signals/draft-pi-from-text",
            data={"draft_json": '{"id": "wrong.shape"}', "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 400
    finally:
        client.__exit__(None, None, None)
