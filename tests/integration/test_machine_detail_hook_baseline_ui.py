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


def test_bootstrap_banner_shows_when_pending_exists(monkeypatch, tmp_path) -> None:
    """Banner shows pending count + accept-all-pending form when ≥1 pending row."""
    with _login(monkeypatch, tmp_path) as client:
        machine_id = "m-hbl-banner"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine_and_baseline(s, machine_id, status="pending", command="a")
            _seed_machine_and_baseline(s, machine_id, status="pending", command="b")
            sid = create_session(s, user_id="admin")

        r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
        assert r.status_code == 200
        # Pluralization: "2 хука" is the Russian few-form.
        assert "Найдено 2" in r.text
        assert f'action="/machines/{machine_id}/hook-baseline/accept-all-pending"' in r.text


def test_bootstrap_banner_hidden_when_no_pending(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        machine_id = "m-hbl-no-banner"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine_and_baseline(s, machine_id, status="active", command="a")
            sid = create_session(s, user_id="admin")

        r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "accept-all-pending" not in r.text


def test_content_drift_finding_renders_with_accept_button(monkeypatch, tmp_path) -> None:
    """hook.rug_pull.content finding should render a card with old/new hash + buttons."""
    import json as _json
    from ccguard.server.db.models import FindingRecord

    with _login(monkeypatch, tmp_path) as client:
        machine_id = "m-hbl-drift"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            row = _seed_machine_and_baseline(s, machine_id, status="active", command="cmd")
            row_id = row.id
            s.add(FindingRecord(
                machine_id=machine_id,
                rule_id="hook.rug_pull.content",
                severity="block",
                discovered_at=_now(),
                payload_json=_json.dumps({
                    "rule_id": "hook.rug_pull.content",
                    "severity": "block",
                    "title": "Содержимое хука изменилось без обновления settings.json",
                    "description": "Скрипт /opt/x.py для хука PreToolUse (Bash) поменялся.",
                    "event_name": "PreToolUse",
                    "matcher": "Bash",
                    "command": "cmd",
                    "old_file_content_hash": "OLDXXX",
                    "new_file_content_hash": "NEWYYY",
                    "file_path": "/opt/x.py",
                }),
            ))
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        assert "Содержимое хука изменилось" in r.text
        assert "OLDXXX" in r.text and "NEWYYY" in r.text
        assert f'/hook-baseline/{row_id}/accept' in r.text
        assert f'/hook-baseline/{row_id}/reject' in r.text


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
