"""UI Фаза 2: /attacks, /indicators, /correlations — детект-склад наружу."""
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


@pytest.mark.parametrize("path", ["/correlations", "/indicators", "/attacks"])
def test_detect_pages_require_auth(path: str) -> None:
    with TestClient(create_app()) as client:
        r = client.get(path, follow_redirects=False)
    assert r.status_code in (307, 401)


def test_correlations_lists_detectors(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/correlations", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    body = r.text
    assert "Корреляции" in body
    assert "staging_chain" in body  # a seeded detector_key
    assert "DETECT" in body  # control type


def test_indicators_lists_catalog(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/indicators", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    body = r.text
    assert "Индикаторы" in body
    assert "sensitive_path" in body  # a seeded indicator_type
    assert "T1552" in body  # a mapped technique


def test_attacks_lists_scenarios(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/attacks", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    body = r.text
    assert "Атаки по стадиям" in body
    assert "recon_to_exfil" in body  # a seeded scenario
    assert "exfiltration" in body  # a stage
