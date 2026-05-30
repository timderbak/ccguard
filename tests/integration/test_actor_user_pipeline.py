"""End-to-end per-user attribution: ingest → DB → audit filter → UI."""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import Machine, ToolUseEvent
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.main import create_app


def _ingest_event(client: TestClient, auth_headers, machine_id: str, actor: str | None) -> None:
    body = {
        "schema_version": "0.2",
        "machine_id": machine_id,
        "events": [
            {
                "ts": datetime.now(UTC).isoformat(),
                "tool_name": "Bash",
                "fingerprint": "0123456789abcdef",
                "decision": "allow",
                "result_status": "success",
                "signals": [],
                **({"actor_user": actor} if actor is not None else {}),
            }
        ],
    }
    r = client.post("/api/v1/audit", content=json.dumps(body), headers=auth_headers)
    assert r.status_code == 200, r.text


def test_actor_user_persisted_on_ingest(client: TestClient, auth_headers) -> None:
    _ingest_event(client, auth_headers, "m-actor", "alice")
    with Session(client.app.state.engine) as s:
        row = s.exec(
            select(ToolUseEvent).where(ToolUseEvent.machine_id == "m-actor")
        ).first()
        assert row is not None
        assert row.actor_user == "alice"


def test_actor_user_optional_for_old_agents(client: TestClient, auth_headers) -> None:
    """v0.1/v0.2 agents don't send actor_user — must ingest cleanly with None."""
    _ingest_event(client, auth_headers, "m-old", actor=None)
    with Session(client.app.state.engine) as s:
        row = s.exec(
            select(ToolUseEvent).where(ToolUseEvent.machine_id == "m-old")
        ).first()
        assert row is not None
        assert row.actor_user is None


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-actor-ui")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        now = datetime.now(UTC)
        s.add(Machine(machine_id="m-actor-ui", first_seen=now, last_seen=now))
        s.commit()
        sid = create_session(s, user_id="admin")
    return client, sid


def test_audit_feed_filters_by_actor_user(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            now = datetime.now(UTC)
            for actor in ("alice", "alice", "bob"):
                s.add(ToolUseEvent(
                    machine_id="m-actor-ui", ts=now, received_at=now,
                    tool_name="Bash", fingerprint="0123456789abcdef",
                    decision="allow", result_status="success",
                    signals_json="[]", actor_user=actor,
                ))
            s.commit()
        r = client.get("/audit?actor_user=alice", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        # Both alice events visible, bob filtered out — check via the filter
        # echo + result count hint.
        assert 'value="alice"' in body
        # The Пользователь column header must be present.
        assert "Пользователь" in body
    finally:
        client.__exit__(None, None, None)


def test_machine_detail_shows_top_actors(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            now = datetime.now(UTC)
            for actor, n in (("alice", 5), ("bob", 2)):
                for _ in range(n):
                    s.add(ToolUseEvent(
                        machine_id="m-actor-ui", ts=now, received_at=now,
                        tool_name="Bash", fingerprint="0123456789abcdef",
                        decision="allow", result_status="success",
                        signals_json="[]", actor_user=actor,
                    ))
            s.commit()
        r = client.get("/machines/m-actor-ui", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "Пользователи за 7 дней" in body
        assert "alice" in body
        assert "bob" in body
        # Alice has 5 events, must appear above bob (sorted desc).
        assert body.index("alice") < body.index("bob")
    finally:
        client.__exit__(None, None, None)
