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


def test_coverage_armed_badge_when_no_findings(admin_client) -> None:
    """P6: a registered detector that never fired reads as 'не стрелял', not a
    blind green badge — the map measures reality, not editorial intent."""
    client, sid = admin_client
    r = client.get("/coverage", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    assert "не стрелял" in r.text


def test_coverage_detecting_badge_when_finding_fired(admin_client) -> None:
    """A recent finding matching a detector's rule_ids flips its bound technique
    to 'ловит' (detecting)."""
    from datetime import UTC, datetime

    from sqlmodel import select

    from ccguard.server.db.models import Detector, FindingRecord

    client, sid = admin_client
    engine = client.app.state.engine
    with Session(engine) as s:
        det = next(
            (d for d in s.exec(select(Detector)).all() if d.rule_ids), None
        )
        assert det is not None, "seed should register detectors with rule_ids"
        rid = det.rule_ids.split(",")[0].strip()
        s.add(
            FindingRecord(
                machine_id="m1",
                rule_id=rid,
                severity="critical",
                discovered_at=datetime.now(UTC),
                payload_json="{}",
            )
        )
        s.commit()
    r = client.get("/coverage", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    assert "ловит" in r.text
