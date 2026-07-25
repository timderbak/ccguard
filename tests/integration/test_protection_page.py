"""Страница разбора: от «машина без защиты» до подписанного решения.

Проверяется рабочий путь целиком — открылся эпизод, оператор записал причину,
ИБ вынесла вердикт, — и главное свойство процесса: вернувшаяся защита не
снимает вопрос с повестки.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import Machine, ProtectionIncident, ToolUseEvent
from ccguard.server.main import create_app
from ccguard.server.services import protection_incident_service as pis
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-protection")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed(engine, machine_id: str, **kw) -> None:
    now = datetime.now(UTC)
    defaults = dict(
        machine_label="ui", last_seen=now, agent_version="0.3.0",
        last_heartbeat_at=now - timedelta(minutes=1),
        expected_interval_sec=900, hooks_intact=True,
    )
    defaults.update(kw)
    with Session(engine) as s:
        m = s.get(Machine, machine_id)
        if m is None:
            s.add(Machine(machine_id=machine_id, **defaults))
        else:
            for k, v in defaults.items():
                setattr(m, k, v)
            s.add(m)
        s.commit()


def _event(engine, machine_id: str, minutes_ago: int = 5) -> None:
    with Session(engine) as s:
        s.add(ToolUseEvent(
            machine_id=machine_id,
            ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            tool_name="Bash", fingerprint="e" * 16, decision="allow",
            result_status="success", signals_json=json.dumps([]),
        ))
        s.commit()


def _sync(engine) -> None:
    with Session(engine) as s:
        pis.sync(s)


def _incident_id(engine) -> int:
    with Session(engine) as s:
        row = s.exec(select(ProtectionIncident)).first()
        assert row is not None and row.id is not None
        return row.id


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def _csrf(client, sid: str) -> str:
    """CSRF-токен со страницы — форма без него не примется."""
    r = client.get("/admin/protection", cookies={"ccg_session": sid})
    marker = 'name="csrf_token" value="'
    i = r.text.index(marker) + len(marker)
    return r.text[i:r.text.index('"', i)]


def test_page_lists_a_machine_that_lost_protection(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-strip", hooks_intact=False)
        _sync(eng)
        r = client.get("/admin/protection", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "m-strip" in r.text
    assert "ждёт объяснения" in r.text
    assert "Записать причину" in r.text


def test_explanation_then_verdict_closes_the_episode(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-strip", hooks_intact=False)
        _sync(eng)
        inc_id = _incident_id(eng)
        sid = _sid(eng)
        client.cookies.set("ccg_session", sid)
        token = _csrf(client, sid)

        r1 = client.post(
            f"/admin/protection/{inc_id}/explain",
            data={"csrf_token": token, "explanation": "переустанавливал Claude Code"},
            follow_redirects=False,
        )
        assert r1.status_code == 303
        page = client.get("/admin/protection")
        assert "переустанавливал Claude Code" in page.text
        assert "ждёт вердикта" in page.text

        r2 = client.post(
            f"/admin/protection/{inc_id}/review",
            data={"csrf_token": token, "verdict": "accept", "note": "ок, плановое"},
            follow_redirects=False,
        )
        assert r2.status_code == 303
        final = client.get("/admin/protection")
    assert "Разобранные" in final.text
    assert "принято" in final.text
    assert "ок, плановое" in final.text


def test_returned_protection_does_not_remove_the_question(monkeypatch, tmp_path) -> None:
    # Снял хуки → вернул. Раз состояние снова зелёное, соблазн — считать вопрос
    # исчерпанным. Тогда объяснений требовали бы только от тех, кто забыл
    # вернуть, а самый интересный сценарий проходил бы бесследно.
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-back", hooks_intact=False)
        _sync(eng)
        _seed(eng, "m-back", hooks_intact=True)
        _event(eng, "m-back")
        _sync(eng)
        sid = _sid(eng)
        page = client.get("/admin/protection", cookies={"ccg_session": sid})
        card = client.get("/machines/m-back", cookies={"ccg_session": sid})
    assert "ждёт объяснения" in page.text
    assert "защита вернулась" in page.text
    # И на карточке самой машины вопрос тоже виден, хотя диагноз уже зелёный.
    assert "Защита работает" in card.text
    assert "ждёт объяснения" in card.text


def test_healthy_fleet_shows_no_pending_review(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-ok")
        _event(eng, "m-ok")
        _sync(eng)
        r = client.get("/admin/protection", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "Требуют разбора" not in r.text
    assert "под защитой" in r.text


def test_explain_rejects_blank_input(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-strip", hooks_intact=False)
        _sync(eng)
        inc_id = _incident_id(eng)
        sid = _sid(eng)
        client.cookies.set("ccg_session", sid)
        token = _csrf(client, sid)
        r = client.post(
            f"/admin/protection/{inc_id}/explain",
            data={"csrf_token": token, "explanation": "   "},
            follow_redirects=False,
        )
    assert r.status_code == 400


def test_verdict_on_missing_episode_is_404(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-ok")
        sid = _sid(eng)
        client.cookies.set("ccg_session", sid)
        token = _csrf(client, sid)
        r = client.post(
            "/admin/protection/4242/review",
            data={"csrf_token": token, "verdict": "accept"},
            follow_redirects=False,
        )
    assert r.status_code == 404


def test_page_requires_auth(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        r = client.get("/admin/protection")
    assert r.status_code in (401, 403, 307, 303)
