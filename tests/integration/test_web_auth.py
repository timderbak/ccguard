"""Web auth: login, session cookie, separation from API tokens."""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from ccguard.server.main import create_app
from ccguard.server.services.auth_service import hash_password


@pytest.fixture()
def admin_app(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Iterator[TestClient]:
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/auth.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.delenv("CCGUARD_SERVER_CONFIG", raising=False)
    with TestClient(create_app()) as c:
        yield c


def test_unauthenticated_get_root_redirects_to_login(admin_app: TestClient) -> None:
    r = admin_app.get("/", headers={"accept": "text/html"}, follow_redirects=False)
    assert r.status_code in (302, 303, 307)
    assert "/login" in r.headers["location"]


def test_login_with_correct_password_issues_cookie(admin_app: TestClient) -> None:
    r = admin_app.post(
        "/login",
        data={"username": "admin", "password": "hunter2"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    assert "ccg_session" in r.cookies


def test_login_with_wrong_password_rejected(admin_app: TestClient) -> None:
    r = admin_app.post(
        "/login",
        data={"username": "admin", "password": "wrong"},
        follow_redirects=False,
    )
    assert r.status_code == 401


def test_logout_without_csrf_rejected(admin_app: TestClient) -> None:
    r = admin_app.post(
        "/login",
        data={"username": "admin", "password": "hunter2"},
        follow_redirects=False,
    )
    sid = r.cookies["ccg_session"]
    r = admin_app.post("/logout", cookies={"ccg_session": sid}, follow_redirects=False)
    assert r.status_code == 403


def test_api_token_does_not_grant_web_access(admin_app: TestClient) -> None:
    r = admin_app.get(
        "/",
        headers={"X-CCGuard-Token": "demo", "accept": "text/html"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303, 307)
