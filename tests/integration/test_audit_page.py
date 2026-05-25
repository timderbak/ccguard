"""Integration tests for the GET /audit page (TUA-03 first half, PLAN 01-04)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import ToolUseEvent
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        yield client, engine, sid


def _seed_event(
    session: Session,
    *,
    machine_id: str = "m1",
    tool_name: str = "Bash",
    decision: str = "allow",
    result_status: str = "success",
    fingerprint: str = "abcdef1234567890",
    ts: datetime | None = None,
) -> None:
    session.add(
        ToolUseEvent(
            machine_id=machine_id,
            ts=ts or datetime.now(UTC),
            tool_name=tool_name,
            fingerprint=fingerprint,
            decision=decision,
            result_status=result_status,
        )
    )


def test_audit_anonymous_redirects_to_login(admin_client) -> None:
    """No admin cookie → redirect to /login (HTML accept)."""
    client, _engine, _sid = admin_client
    r = client.get("/audit", headers={"Accept": "text/html"}, follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"] == "/login"


def test_audit_empty_db_renders_empty_state(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    assert "<title>ccguard — аудит</title>" in body
    assert '<h2 class="text-2xl font-semibold mb-6">Аудит</h2>' in body
    assert "Аудит-событий нет." in body
    # Sidebar link present (verifies base.html nav insertion)
    assert '<a href="/audit" class="block hover:bg-slate-800 px-3 py-2 rounded">Аудит</a>' in body
    # Russian copy regression
    assert "Активность за 24 часа" in body
    assert "Сбросить" in body
    assert "Фильтр" in body


def test_audit_default_timeframe_24h_selected(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # default selected on 24h option
    assert 'value="24h" selected' in r.text or 'value="24h"  selected' in r.text


def test_audit_filter_echoes_in_form(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get(
        "/audit?machine_id=foo&tool_name=Bash&decision=deny&timeframe=7d",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    body = r.text
    assert 'value="foo"' in body  # machine_id echo
    assert 'value="Bash"' in body  # tool_name echo
    assert 'value="deny" selected' in body or 'value="deny"  selected' in body
    assert 'value="7d"' in body and 'selected' in body


def test_audit_lists_seeded_events(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        for i in range(5):
            _seed_event(s, machine_id=f"machine-{i}", tool_name="Bash")
        s.commit()
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # 5 rows present — count border-b separator (also appears on header, so check >= 5 machine link substrings)
    for i in range(5):
        assert f"/machines/machine-{i}" in r.text
    # Empty-state row should NOT appear
    assert "Аудит-событий нет." not in r.text


def test_audit_filter_tool_name_mismatch_shows_empty_state(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s, tool_name="Bash")
        s.commit()
    r = client.get("/audit?tool_name=Edit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "Аудит-событий нет." in r.text


def test_audit_overflow_footer_when_total_exceeds_limit(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        for i in range(250):
            _seed_event(s, machine_id=f"m-{i:03d}")
        s.commit()
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "Показано 200 из 250 событий за период. Сузьте фильтры если нужно больше." in r.text


def test_audit_decision_color_classes_render(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s, machine_id="ma", decision="allow")
        _seed_event(s, machine_id="md", decision="deny")
        _seed_event(s, machine_id="me", decision="error")
        s.commit()
    r = client.get("/audit", cookies={"ccg_session": sid})
    body = r.text
    assert "text-emerald-600" in body
    assert "text-red-600" in body
    assert "text-amber-600" in body


def test_audit_timeframe_7d_expands_window(admin_client) -> None:
    client, engine, sid = admin_client
    three_days_ago = datetime.now(UTC) - timedelta(days=3)
    with Session(engine) as s:
        _seed_event(s, machine_id="old-machine", ts=three_days_ago)
        s.commit()
    # Default 24h: event not visible
    r_24h = client.get("/audit", cookies={"ccg_session": sid})
    assert "/machines/old-machine" not in r_24h.text
    assert "Аудит-событий нет." in r_24h.text
    # 7d: event visible
    r_7d = client.get("/audit?timeframe=7d", cookies={"ccg_session": sid})
    assert "/machines/old-machine" in r_7d.text


def test_audit_invalid_decision_silently_coerced_to_all(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s, decision="allow")
        s.commit()
    r = client.get("/audit?decision=bogus", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # Event should still render (filter cleared)
    assert "/machines/m1" in r.text


def test_audit_invalid_timeframe_silently_coerced_to_24h(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/audit?timeframe=bogus", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert 'value="24h"' in r.text and "selected" in r.text


def test_audit_machine_id_link_shows_first_12_chars(admin_client) -> None:
    client, engine, sid = admin_client
    long_id = "abcdefghijklmnopqrstuvwxyz"
    with Session(engine) as s:
        _seed_event(s, machine_id=long_id)
        s.commit()
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert f'href="/machines/{long_id}"' in r.text
    assert ">abcdefghijkl</a>" in r.text  # first 12 chars
