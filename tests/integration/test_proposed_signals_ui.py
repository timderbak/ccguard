"""Proposed-signals admin UI: list + draft-from-paste + approve/reject."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ProposedSignal, SettingsRecord
from ccguard.server.services import proposed_signal_service as svc
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-proposed")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def _csrf(client: TestClient, sid: str) -> str:
    # Pull token from the rendered page.
    r = client.get("/admin/proposed-signals", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # Token appears as <input ... name="csrf_token" value="X">
    import re as _re

    m = _re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m is not None, "csrf token not in proposed-signals page"
    return m.group(1)


def test_admin_page_lists_pending(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            svc.propose(
                s,
                draft={
                    "id": "cred.read.browser",
                    "attack_technique": "T1555.003",
                    "pattern": r"login\s+data",
                    "description": "Access to browser stores",
                },
                source_kind="manual",
                source_title="manual paste",
            )
        r = client.get("/admin/proposed-signals", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Предложенные сигналы" in r.text
        assert "cred.read.browser" in r.text
        assert "T1555.003" in r.text
        assert "manual paste" in r.text
    finally:
        client.__exit__(None, None, None)


def test_draft_from_text_creates_pending(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        draft = {
            "id": "persist.launchd",
            "attack_technique": "T1543.001",
            "pattern": r"\b(launchctl|LaunchAgents/)",
            "description": "macOS launchd persistence",
        }
        r = client.post(
            "/admin/proposed-signals/draft-from-text",
            data={"draft_json": json.dumps(draft), "csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            row = s.exec(select(ProposedSignal)).first()
            assert row is not None
            assert row.status == "pending"
            assert json.loads(row.draft_json)["id"] == "persist.launchd"
    finally:
        client.__exit__(None, None, None)


def test_approve_writes_setting_override(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            row = svc.propose(
                s,
                draft={
                    "id": "cred.read.browser",
                    "attack_technique": "T1555.003",
                    "pattern": r"login\s+data",
                    "description": "x",
                },
                source_kind="manual",
            )
            row_id = row.id
        token = _csrf(client, sid)
        r = client.post(
            f"/admin/proposed-signals/{row_id}/approve",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            override = s.get(SettingsRecord, "catalog.override.cred.read.browser")
            assert override is not None
            assert json.loads(override.value)["pattern"] == r"login\s+data"
    finally:
        client.__exit__(None, None, None)


def test_reject_records_reason(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            row = svc.propose(
                s,
                draft={
                    "id": "cred.read.browser",
                    "attack_technique": "T1555.003",
                    "pattern": r"login\s+data",
                    "description": "x",
                },
                source_kind="manual",
            )
            row_id = row.id
        token = _csrf(client, sid)
        r = client.post(
            f"/admin/proposed-signals/{row_id}/reject",
            data={"csrf_token": token, "reason": "too noisy"},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            updated = s.get(ProposedSignal, row_id)
            assert updated is not None
            assert updated.status == "rejected"
            assert updated.rejection_reason == "too noisy"
    finally:
        client.__exit__(None, None, None)


def test_revert_unships_override(monkeypatch, tmp_path) -> None:
    # P3.3-7 rollback: approve then revert; the catalog.override.* row is gone.
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            row = svc.propose(
                s,
                draft={
                    "id": "cred.read.browser",
                    "attack_technique": "T1555.003",
                    "pattern": r"login\s+data",
                    "description": "x",
                },
                source_kind="manual",
            )
            row_id = row.id
            svc.approve(s, row_id, reviewed_by="admin")
        token = _csrf(client, sid)
        r = client.post(
            f"/admin/proposed-signals/{row_id}/revert",
            data={"csrf_token": token, "reason": "too noisy"},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            assert s.get(SettingsRecord, "catalog.override.cred.read.browser") is None
            updated = s.get(ProposedSignal, row_id)
            assert updated is not None
            assert updated.status == "reverted"
    finally:
        client.__exit__(None, None, None)


class _NoopMonitor:
    name = "test-noop"

    def poll(self, since):  # noqa: ANN001, ANN201
        return []


def test_trigger_discovery_runs_sweep(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        # Non-None drafter + a no-op monitor → sweep runs with no network/items.
        client.app.state.signal_drafter = object()
        client.app.state.discovery_monitors = [_NoopMonitor()]
        token = _csrf(client, sid)
        r = client.post(
            "/admin/proposed-signals/trigger-discovery",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
    finally:
        client.__exit__(None, None, None)


def test_trigger_discovery_503_without_drafter(monkeypatch, tmp_path) -> None:
    client, sid = _login(monkeypatch, tmp_path)
    try:
        client.app.state.signal_drafter = None
        token = _csrf(client, sid)
        r = client.post(
            "/admin/proposed-signals/trigger-discovery",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 503
    finally:
        client.__exit__(None, None, None)


def test_anonymous_user_blocked(monkeypatch, tmp_path) -> None:
    client, _ = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/admin/proposed-signals", follow_redirects=False)
        assert r.status_code in (307, 401)
    finally:
        client.__exit__(None, None, None)
