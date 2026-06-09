"""UI: coverage drilldown — technique detail + detector detail pages.

Surfaces the transparency content: how a technique is detected, by which
mechanics/correlations, related techniques, example attacks (seeded scenarios +
real public incidents), and per-detector plain-language explanations.
"""
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


@pytest.mark.parametrize("path", ["/coverage/AML.T0051", "/detectors/staging_chain"])
def test_detail_pages_require_auth(path: str) -> None:
    with TestClient(create_app()) as client:
        r = client.get(path, follow_redirects=False)
    assert r.status_code in (307, 401)


def test_technique_detail_renders_transparency(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/coverage/AML.T0051", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    body = r.text
    # identity + первоисточник
    assert "LLM Prompt Injection" in body
    assert "atlas.mitre.org" in body  # source URL surfaced
    # how we detect it + a clickable detector mechanic
    assert "Как мы это ловим" in body
    assert "/detectors/" in body
    # real public incident with stable source
    assert "Примеры атак" in body
    assert "2302.12173" in body  # Greshake indirect-PI paper


def test_technique_detail_unknown_404(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/coverage/NOPE.T9999", cookies={"ccg_session": sid})
    assert r.status_code == 404


def test_detector_detail_renders_explanation(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/detectors/staging_chain", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    body = r.text
    assert "Staging chain" in body  # detector name
    assert "ioa.staging_chain" in body  # rule_id emitted
    assert "Как работает" in body
    assert "content.read.external" in body  # a watched signal from the explanation
    assert "/coverage/" in body  # links back to a covered technique


def test_detector_detail_unknown_404(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/detectors/does-not-exist", cookies={"ccg_session": sid})
    assert r.status_code == 404


def test_coverage_map_tiles_link_to_detail(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/coverage", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert 'href="/coverage/AML.T0051"' in r.text


def test_correlations_link_to_detector_detail(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/correlations", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert 'href="/detectors/staging_chain"' in r.text
