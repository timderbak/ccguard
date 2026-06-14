"""Fresh-instance policy onboarding: /policy renders a graceful empty-state with
a one-click 'load starter policy' CTA instead of a raw 503 JSON."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


@pytest.fixture
def admin_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[tuple[TestClient, str]]:
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/pol.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.delenv("CCGUARD_SERVER_CONFIG", raising=False)
    with TestClient(create_app()) as c:
        with Session(c.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        yield c, sid


def _csrf(client: TestClient, sid: str) -> str:
    # the csrf token is a signed value embedded in the rendered form, not a cookie
    import re
    body = client.get("/policy", cookies={"ccg_session": sid}).text
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
    assert m, "no csrf token in policy empty-state form"
    return m.group(1)


def test_policy_empty_state_not_503(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/policy", cookies={"ccg_session": sid})
    assert r.status_code == 200  # was a raw 503 before
    assert 'data-testid="policy-empty-state"' in r.text
    assert 'data-testid="bootstrap-default-btn"' in r.text


def test_policy_mandatory_also_graceful(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/policy/mandatory", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert 'data-testid="policy-empty-state"' in r.text


def test_bootstrap_default_publishes_and_editor_loads(admin_client) -> None:
    client, sid = admin_client
    token = _csrf(client, sid)
    r = client.post(
        "/policy/bootstrap-default",
        data={"csrf_token": token},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # now the editor renders the real policy, not the empty-state
    r2 = client.get("/policy", cookies={"ccg_session": sid})
    assert r2.status_code == 200
    assert 'data-testid="policy-empty-state"' not in r2.text

    from ccguard.server.services.policy_service import get_current_published
    with Session(client.app.state.engine) as s:
        assert get_current_published(s) is not None


def test_bootstrap_default_is_idempotent(admin_client) -> None:
    client, sid = admin_client
    token = _csrf(client, sid)
    for _ in range(2):
        client.post(
            "/policy/bootstrap-default",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
    from ccguard.server.db.models import PolicyVersion
    from sqlmodel import select
    with Session(client.app.state.engine) as s:
        published = s.exec(
            select(PolicyVersion).where(PolicyVersion.status == "published")
        ).all()
    assert len(published) == 1  # second POST is a no-op
