"""Integration tests for GET /_partials/audit/timeline (TUA-03, PLAN 01-05)."""

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


def test_timeline_partial_anonymous_redirects_or_401(admin_client) -> None:
    client, _engine, _sid = admin_client
    r = client.get(
        "/_partials/audit/timeline",
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307, 401)
    if r.status_code in (302, 307):
        assert r.headers["location"] == "/login"


def test_timeline_partial_empty_db_shows_empty_state(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/_partials/audit/timeline", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Нет данных за выбранный период." in r.text


def test_timeline_partial_is_fragment_not_full_page(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/_partials/audit/timeline", cookies={"ccg_session": sid})
    body = r.text.lower()
    assert "<html" not in body
    assert "<body" not in body
    assert "<!doctype" not in body


def test_timeline_partial_seeded_events_render_bar(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        for i in range(5):
            _seed_event(s, machine_id=f"m-{i}", tool_name="Bash")
        s.commit()
    r = client.get("/_partials/audit/timeline", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    # 24 bars total
    assert body.count('class="flex-1 bg-slate-700 rounded-sm"') == 24
    # exactly 1 bar with min-height: 2px (current hour has all 5 events)
    assert body.count("min-height: 2px") == 1
    # 23 empty bars
    assert body.count("min-height: 0") == 23


def test_timeline_partial_filter_tool_name_excludes_others(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s, tool_name="Bash", machine_id="mb")
        _seed_event(s, tool_name="Edit", machine_id="me")
        s.commit()
    r = client.get(
        "/_partials/audit/timeline?tool_name=Bash",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    body = r.text
    # Only the Bash event counts -> 1 non-empty bar
    assert body.count("min-height: 2px") == 1
    # tooltip count must be 1 (not 2)
    assert " — 1 событий" in body


def test_timeline_partial_filter_machine_id_substring(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s, machine_id="laptop-alice")
        _seed_event(s, machine_id="desktop-bob")
        s.commit()
    r = client.get(
        "/_partials/audit/timeline?machine_id=laptop",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    body = r.text
    assert body.count("min-height: 2px") == 1
    assert " — 1 событий" in body


def test_timeline_partial_filter_decision_exact(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s, machine_id="ma", decision="allow")
        _seed_event(s, machine_id="md", decision="deny")
        s.commit()
    r = client.get(
        "/_partials/audit/timeline?decision=deny",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert " — 1 событий" in r.text


def test_timeline_partial_invalid_decision_coerced_to_all(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s, decision="allow")
        s.commit()
    r = client.get(
        "/_partials/audit/timeline?decision=bogus",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    # event must still be counted -> non-empty bar
    assert "min-height: 2px" in r.text


def test_timeline_partial_timeframe_param_accepted_but_window_fixed_24h(admin_client) -> None:
    """Per UI-SPEC: timeline card always says 'Активность за 24 часа' regardless
    of timeframe filter. Accept the param but ignore for chart window."""
    client, engine, sid = admin_client
    three_days_ago = datetime.now(UTC) - timedelta(days=3)
    with Session(engine) as s:
        _seed_event(s, ts=three_days_ago)
        s.commit()
    # Even with timeframe=7d, partial only shows last 24h -> empty state
    r = client.get(
        "/_partials/audit/timeline?timeframe=7d",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert "Нет данных за выбранный период." in r.text


def test_audit_page_initial_render_has_real_bars(admin_client) -> None:
    """The page-level /audit route must compute buckets + max_count so the
    server-rendered initial paint already shows real bars (no flash-of-empty)."""
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_event(s)
        s.commit()
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "min-height: 2px" in r.text
    # Empty-state copy must NOT appear when data exists
    assert "Нет данных за выбранный период." not in r.text


def test_audit_page_htmx_polling_wiring(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    assert 'hx-get="/_partials/audit/timeline"' in body
    assert 'hx-trigger="every 30s"' in body
    assert 'hx-include="closest form"' in body
