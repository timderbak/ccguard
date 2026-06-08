"""UI: /coverage — карта покрытия (ТЗ-08) surfaced in the web app."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password

pytestmark = pytest.mark.integration


@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        yield client, sid


def test_coverage_requires_auth() -> None:
    with TestClient(create_app()) as client:
        r = client.get("/coverage", follow_redirects=False)
    assert r.status_code in (307, 401)  # redirect to /login or 401


def test_coverage_page_renders_taxonomy(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/coverage", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    body = r.text
    # page chrome + sections
    assert "Карта покрытия" in body
    assert "Покрытие по стадиям" in body
    # control-type breakdown (ТЗ-08 / ТЗ-09)
    assert "DETECT" in body
    assert "SCOPE" in body
    # seeded taxonomy is present: a stage + the paradox technique (covered via detector)
    assert "credential-access" in body
    assert "AML.T0051" in body  # IPI — covered by correlation, the ТЗ-08 headline
