"""Admin route /admin/proposed-signals/draft-from-llm — uses app.state.signal_drafter."""
from __future__ import annotations

import json
from dataclasses import dataclass

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ProposedSignal
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.settings_service import set_setting
from ccguard.server.main import create_app


@dataclass
class FakeDrafter:
    response: str
    calls: int = 0
    def draft(self, threat_text: str) -> str:
        self.calls += 1
        return self.response


_DRAFT = {
    "id": "cred.read.session_cookie",
    "attack_technique": "T1539",
    "pattern": r"cookies\.binarycookies",
    "description": "Browser cookies access",
}


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-llm")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "10")
        sid = create_session(s, user_id="admin")
    return client, sid


def _csrf(client: TestClient, sid: str) -> str:
    r = client.get("/admin/proposed-signals", cookies={"ccg_session": sid})
    import re as _re
    m = _re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m is not None
    return m.group(1)


def test_route_returns_503_when_drafter_not_configured(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        # app.state.signal_drafter is None by default — no ANTHROPIC_API_KEY in tests.
        r = client.post(
            "/admin/proposed-signals/draft-from-llm",
            data={"threat_text": "T1539 cookie theft", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 503
    finally:
        client.__exit__(None, None, None)


def test_route_drafts_via_app_state_drafter(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        client.app.state.signal_drafter = FakeDrafter(response=json.dumps(_DRAFT))
        token = _csrf(client, sid)
        r = client.post(
            "/admin/proposed-signals/draft-from-llm",
            data={
                "threat_text": "T1539 browser session cookie theft",
                "source_url": "https://attack.mitre.org/techniques/T1539/",
                "source_title": "MITRE T1539",
                "csrf_token": token,
            },
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303), r.text
        with Session(client.app.state.engine) as s:
            row = s.exec(select(ProposedSignal)).first()
            assert row is not None
            assert row.source_kind == "llm"
            assert row.source_title == "MITRE T1539"
            assert json.loads(row.draft_json)["id"] == "cred.read.session_cookie"
    finally:
        client.__exit__(None, None, None)


def test_route_returns_400_on_drafter_error(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        client.app.state.signal_drafter = FakeDrafter(response="not json")
        token = _csrf(client, sid)
        r = client.post(
            "/admin/proposed-signals/draft-from-llm",
            data={"threat_text": "x", "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 400
    finally:
        client.__exit__(None, None, None)
