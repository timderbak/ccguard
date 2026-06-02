"""Web routes for hook baseline accept / accept-all / reject (smoke).

UI rendering tests live in Task 16+. Here we exercise the POST endpoints and
the redirect contract; baseline rows are seeded directly via the service.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import HookBaseline, Machine
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.hook_baseline_service import compute_fingerprint

from tests.integration.conftest import VALID_TOKEN


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _login(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-hook")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed_machine_and_baseline(
    session: Session,
    machine_id: str,
    *,
    status: str = "pending",
    command: str = "cmd",
) -> HookBaseline:
    if session.get(Machine, machine_id) is None:
        session.add(Machine(
            machine_id=machine_id,
            machine_label="hook-bl-test",
            first_seen=_now(),
            last_seen=_now(),
            agent_version="0.2.0",
        ))
    row = HookBaseline(
        machine_id=machine_id,
        event_name="PreToolUse",
        matcher="Bash",
        command_string=command,
        file_path=None,
        file_content_hash=None,
        fingerprint=compute_fingerprint("PreToolUse", "Bash", command, None),
        status=status,
        first_seen_at=_now(),
        last_seen_at=_now(),
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def _csrf(client: TestClient, machine_id: str, sid: str) -> str:
    r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    marker = 'name="csrf_token" value="'
    assert marker in r.text
    return r.text.split(marker, 1)[1].split('"', 1)[0]


def test_accept_single_route_promotes_to_active(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        machine_id = "m-hbl-accept"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            row = _seed_machine_and_baseline(s, machine_id, status="pending")
            row_id = row.id
            sid = create_session(s, user_id="admin")

        token = _csrf(client, machine_id, sid)
        resp = client.post(
            f"/machines/{machine_id}/hook-baseline/{row_id}/accept",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == f"/machines/{machine_id}"

        with Session(engine) as s:
            fresh = s.exec(select(HookBaseline)).one()
            assert fresh.status == "active"
            assert fresh.accepted_by == "admin"


def test_accept_all_pending_route(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        machine_id = "m-hbl-bulk"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine_and_baseline(s, machine_id, status="pending", command="a")
            _seed_machine_and_baseline(s, machine_id, status="pending", command="b")
            sid = create_session(s, user_id="admin")

        token = _csrf(client, machine_id, sid)
        resp = client.post(
            f"/machines/{machine_id}/hook-baseline/accept-all-pending",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with Session(engine) as s:
            rows = s.exec(select(HookBaseline)).all()
            assert all(r.status == "active" for r in rows)


def test_reject_route_marks_removed(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        machine_id = "m-hbl-reject"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            row = _seed_machine_and_baseline(s, machine_id, status="pending")
            row_id = row.id
            sid = create_session(s, user_id="admin")

        token = _csrf(client, machine_id, sid)
        resp = client.post(
            f"/machines/{machine_id}/hook-baseline/{row_id}/reject",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with Session(engine) as s:
            fresh = s.exec(select(HookBaseline)).one()
            assert fresh.status == "removed"
