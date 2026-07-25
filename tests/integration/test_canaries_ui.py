"""Веб-тесты приманок."""
from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import CanaryToken
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _login(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-canary")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _csrf(client, sid):
    r = client.get("/admin/canaries", cookies={"ccg_session": sid})
    assert r.status_code == 200
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m
    return m.group(1)


def test_page_renders_empty(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        r = client.get("/admin/canaries", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Приманки" in r.text
        assert "Приманок пока нет" in r.text


def test_create_shows_value_exactly_once(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        token = _csrf(client, sid)
        posted = client.post("/admin/canaries/create",
                             data={"csrf_token": token, "token_type": "aws_key"},
                             cookies={"ccg_session": sid}, follow_redirects=False)
        assert posted.status_code in (200, 303)
        # значение показывается на следующей загрузке страницы — и только на ней
        r = client.get("/admin/canaries", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "сохрани файл сейчас" in r.text
        m = re.search(r"AKIA[A-Z0-9]{16}", r.text)
        assert m, "значение приманки должно быть показано"
        value = m.group(0)
        # второй заход — значения больше нет нигде
        r2 = client.get("/admin/canaries", cookies={"ccg_session": sid})
        assert value not in r2.text
        assert "сохрани файл сейчас" not in r2.text


def test_created_canary_listed_and_armed(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        token = _csrf(client, sid)
        client.post("/admin/canaries/create",
                    data={"csrf_token": token, "token_type": "dotenv", "label": "тест"},
                    cookies={"ccg_session": sid}, follow_redirects=False)
        r = client.get("/admin/canaries", cookies={"ccg_session": sid})
        assert "взведена" in r.text
        assert "тест" in r.text
        with Session(client.app.state.engine) as s:
            row = s.exec(select(CanaryToken)).one()
            assert row.status == "armed"
            assert row.created_by == "admin"


def test_delete_removes_canary(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        token = _csrf(client, sid)
        client.post("/admin/canaries/create",
                    data={"csrf_token": token, "token_type": "aws_key"},
                    cookies={"ccg_session": sid}, follow_redirects=False)
        with Session(client.app.state.engine) as s:
            cid = s.exec(select(CanaryToken)).one().id
        r = client.post(f"/admin/canaries/{cid}/delete", data={"csrf_token": token},
                        cookies={"ccg_session": sid}, follow_redirects=False)
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            assert s.exec(select(CanaryToken)).all() == []


def test_triggered_canary_shown_in_red(monkeypatch, tmp_path):
    import json

    from ccguard.server.db.models import Machine, ToolUseEvent
    from ccguard.server.services import canary_service
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            now = datetime.now(UTC)
            s.add(Machine(machine_id="m1", machine_label="m1",
                          first_seen=now.replace(tzinfo=None), last_seen=now.replace(tzinfo=None),
                          agent_version="0.3.0"))
            s.commit()
            created = canary_service.create_canary(s, token_type="aws_key")
            s.add(ToolUseEvent(machine_id="m1", ts=now, tool_name="Read", fingerprint="a"*16,
                decision="allow", result_status="success",
                signals_json=json.dumps([f"cred.read.store_{created.token.indicator_id}"]),
                actor_user="alice"))
            s.commit()
            canary_service.tick(s)
            sid = create_session(s, user_id="admin")
        r = client.get("/admin/canaries", cookies={"ccg_session": sid})
        assert "СРАБОТАЛА" in r.text
        assert "alice" in r.text
        assert "ротируй" in r.text


def test_page_requires_auth(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        r = client.get("/admin/canaries", follow_redirects=False)
        assert r.status_code in (307, 401, 403)
