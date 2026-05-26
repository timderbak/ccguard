"""Integration tests for the /audit page extension (Phase 04 / Plan 05).

Covers the new ``event_source=policy_apply`` filter value, the conditional
«Результат» column, and the locked Russian copy from 04-UI-SPEC.md.

The default (no query string) /audit view must remain byte-equal to v0.1
for the tool_use audience — regression assertions live in
``test_audit_page.py`` and are reinforced here for the specific layout
guarantees (column header set, no leaked policy_apply column).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import PolicyApplyEvent, ToolUseEvent
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


def _seed_apply(
    session: Session,
    *,
    machine_id: str = "m1",
    result: str = "success",
    applied_count: int = 3,
    snapshot_id: str = "abcdef1234567890",
    reason: str | None = None,
    failed_file: str | None = None,
    policy_revision: int = 7,
    ts: datetime | None = None,
) -> None:
    session.add(
        PolicyApplyEvent(
            machine_id=machine_id,
            ts=ts or datetime.now(UTC),
            result=result,
            applied_count=applied_count,
            snapshot_id=snapshot_id,
            reason=reason,
            failed_file=failed_file,
            policy_revision=policy_revision,
        )
    )


# ---------------- regression: default /audit unchanged ----------------


def test_default_audit_renders_tool_use_columns_without_policy_apply_extras(
    admin_client,
) -> None:
    """GET /audit (no query) renders existing v0.1 layout — no «События политики»
    leakage in the header, no policy_apply pill markup."""
    client, _engine, sid = admin_client
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    # Existing tool_use thead columns present
    assert "<th>Инструмент</th>" in body
    assert "<th>Решение</th>" in body
    assert "<th>Fingerprint</th>" in body
    # Existing tool_use empty-state copy preserved when no events
    assert "Аудит-событий нет." in body
    # The new option appears in the select but no policy_apply table content
    assert "События политики" in body  # filter option exists
    # No success/rollback pill markup in default view
    assert "bg-emerald-600" not in body
    assert "bg-red-600" not in body


def test_default_audit_has_event_source_filter_option(admin_client) -> None:
    """The event_source select contains the locked option «События политики»."""
    client, _engine, sid = admin_client
    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert 'name="event_source"' in r.text
    assert '<option value="policy_apply"' in r.text
    assert "События политики" in r.text


# ---------------- policy_apply branch: header + empty ----------------


def test_policy_apply_filter_renders_result_column_header(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    # «Результат» column header present in the policy_apply branch
    assert "<th>Результат</th>" in body
    # Selected attribute round-trips
    assert 'value="policy_apply"' in body and "selected" in body
    # Tool_use-specific headers must NOT appear in the policy_apply table
    assert "<th>Инструмент</th>" not in body
    assert "<th>Решение</th>" not in body
    assert "<th>Fingerprint</th>" not in body


def test_policy_apply_empty_state_locked_copy(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "Событий нет." in r.text


# ---------------- policy_apply branch: success pill ----------------


def test_policy_apply_success_event_renders_emerald_pill(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_apply(
            s,
            machine_id="laptop-success",
            result="success",
            applied_count=4,
            snapshot_id="0123456789abcdef",
        )
        s.commit()
    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    # Locked Tailwind classes per 04-UI-SPEC.md
    assert "bg-emerald-600" in body
    assert ">success<" in body
    # Locked details format string
    assert "applied=4, snapshot=01234567" in body
    # Machine link still uses the existing machine_id[:12] pattern
    assert "/machines/laptop-success" in body
    # Rollback pill absent
    assert "bg-red-600" not in body


# ---------------- policy_apply branch: rollback pill ----------------


def test_policy_apply_rollback_event_renders_red_pill_and_reason(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_apply(
            s,
            machine_id="laptop-rollback",
            result="rollback",
            applied_count=0,
            snapshot_id="fedcba9876543210",
            reason="checksum_mismatch",
            failed_file=".claude/skills/security-rules/SKILL.md",
        )
        s.commit()
    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    # Locked Tailwind classes
    assert "bg-red-600" in body
    assert ">rollback<" in body
    # reason= prefix highlighted in amber per UI-SPEC
    assert "text-amber-600" in body
    assert "reason=" in body
    assert "checksum_mismatch" in body
    assert "failed_file=.claude/skills/security-rules/SKILL.md" in body
    assert "snapshot=fedcba98" in body
    # Success pill absent
    assert "bg-emerald-600" not in body


# ---------------- ordering & combining with existing filters ----------------


def test_policy_apply_orders_by_ts_desc(admin_client) -> None:
    client, engine, sid = admin_client
    now = datetime.now(UTC)
    with Session(engine) as s:
        _seed_apply(s, machine_id="oldest", ts=now - timedelta(hours=2))
        _seed_apply(s, machine_id="middlee", ts=now - timedelta(hours=1))
        _seed_apply(s, machine_id="newest1", ts=now)
        s.commit()
    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    body = r.text
    # All three present; newest appears earliest in body
    pos_new = body.find("/machines/newest1")
    pos_mid = body.find("/machines/middlee")
    pos_old = body.find("/machines/oldest")
    assert pos_new != -1 and pos_mid != -1 and pos_old != -1
    assert pos_new < pos_mid < pos_old


def test_policy_apply_machine_filter_combines(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        _seed_apply(s, machine_id="alpha-host", result="success")
        _seed_apply(s, machine_id="beta-host", result="rollback",
                    reason="x", failed_file="y")
        s.commit()
    r = client.get(
        "/audit?event_source=policy_apply&machine_id=alpha",
        cookies={"ccg_session": sid},
    )
    body = r.text
    assert "/machines/alpha-host" in body
    assert "/machines/beta-host" not in body


def test_policy_apply_timeframe_filter_combines(admin_client) -> None:
    """timeframe=1h excludes a 3h-old policy_apply event; 7d includes it."""
    client, engine, sid = admin_client
    three_hours_ago = datetime.now(UTC) - timedelta(hours=3)
    with Session(engine) as s:
        _seed_apply(s, machine_id="stale-host", ts=three_hours_ago)
        s.commit()
    r_1h = client.get(
        "/audit?event_source=policy_apply&timeframe=1h",
        cookies={"ccg_session": sid},
    )
    assert "/machines/stale-host" not in r_1h.text
    assert "Событий нет." in r_1h.text
    r_7d = client.get(
        "/audit?event_source=policy_apply&timeframe=7d",
        cookies={"ccg_session": sid},
    )
    assert "/machines/stale-host" in r_7d.text


# ---------------- byte-equality guard: tool_use baseline unchanged ----------------


def test_default_audit_with_tool_use_events_layout_unchanged(admin_client) -> None:
    """When event_source is unset, the page still renders the existing
    tool_use table — seed a ToolUseEvent and confirm v0.1 markup persists."""
    client, engine, sid = admin_client
    with Session(engine) as s:
        s.add(
            ToolUseEvent(
                machine_id="tu-host",
                ts=datetime.now(UTC),
                tool_name="Bash",
                fingerprint="0123456789abcdef",
                decision="allow",
                result_status="success",
            )
        )
        s.commit()
    r = client.get("/audit", cookies={"ccg_session": sid})
    body = r.text
    # tool_use table columns intact (regression)
    assert "<th>Инструмент</th>" in body
    assert "<th>Решение</th>" in body
    assert "<th>Fingerprint</th>" in body
    assert "/machines/tu-host" in body
    # No policy_apply-specific markup leaks into the default branch
    assert "bg-emerald-600" not in body
    assert "bg-red-600" not in body


def test_explicit_event_source_tool_use_renders_tool_use_table(admin_client) -> None:
    """Passing event_source=tool_use (or empty) explicitly is treated as
    the default v0.1 branch — same layout."""
    client, _engine, sid = admin_client
    r = client.get("/audit?event_source=tool_use", cookies={"ccg_session": sid})
    body = r.text
    assert r.status_code == 200
    assert "<th>Инструмент</th>" in body
    assert "Аудит-событий нет." in body
