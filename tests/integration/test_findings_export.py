"""Выгрузка находок: кнопка в интерфейсе и машинный доступ по токену."""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _login(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-export")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed(s: Session) -> None:
    for sev, rid in (("critical", "canary.triggered"), ("warn", "cred.read.aws")):
        s.add(FindingRecord(machine_id="m1", inventory_id=None, rule_id=rid, severity=sev,
                            discovered_at=datetime.now(UTC),
                            payload_json=json.dumps({"title": f"находка {sev}"}, ensure_ascii=False)))
    s.commit()


def test_csv_download_has_attachment_headers(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _seed(s)
            sid = create_session(s, user_id="admin")
        r = client.get("/findings/export?format=csv", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        assert "attachment" in r.headers["content-disposition"]
        assert "ccguard-findings-" in r.headers["content-disposition"]
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert len(rows) == 2


def test_json_download(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _seed(s)
            sid = create_session(s, user_id="admin")
        r = client.get("/findings/export?format=json", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert json.loads(r.text)["count"] == 2


def test_export_respects_filters(monkeypatch, tmp_path):
    # Человек скачивает ровно то, что отобрал глазами на странице.
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _seed(s)
            sid = create_session(s, user_id="admin")
        r = client.get("/findings/export?format=csv&severity=critical", cookies={"ccg_session": sid})
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "canary.triggered"


def test_export_requires_auth(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        r = client.get("/findings/export", follow_redirects=False)
        assert r.status_code in (307, 401, 403)


def test_findings_page_has_export_buttons(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _seed(s)
            sid = create_session(s, user_id="admin")
        r = client.get("/findings", cookies={"ccg_session": sid})
        assert "/findings/export?format=csv" in r.text
        assert "/findings/export?format=json" in r.text


def test_export_buttons_carry_active_filter(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _seed(s)
            sid = create_session(s, user_id="admin")
        r = client.get("/findings?severity=critical", cookies={"ccg_session": sid})
        assert "severity=critical" in r.text


# --- машинный доступ (для SIEM) ---------------------------------------------


def test_api_export_requires_token(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        r = client.get("/api/v1/findings/export")
        assert r.status_code in (401, 403)


def test_api_export_csv_with_token(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _seed(s)
        r = client.get("/api/v1/findings/export?format=csv",
                       headers={"X-CCGuard-Token": VALID_TOKEN})
        assert r.status_code == 200
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert len(rows) == 2


def test_api_export_json_and_filters(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        with Session(client.app.state.engine) as s:
            _seed(s)
        r = client.get("/api/v1/findings/export?format=json&severity=critical",
                       headers={"X-CCGuard-Token": VALID_TOKEN})
        assert r.status_code == 200
        body = json.loads(r.text)
        assert body["count"] == 1


def test_api_rejects_bad_format(monkeypatch, tmp_path):
    with _login(monkeypatch, tmp_path) as client:
        r = client.get("/api/v1/findings/export?format=xml",
                       headers={"X-CCGuard-Token": VALID_TOKEN})
        assert r.status_code == 422
