"""Integration tests for /findings UI extension (Plan 03-05).

Covers:
  (i)  /findings renders new column headers "Риск" and "Действия"
  (j)  ?scope=llm filters to only rule_id LIKE 'llm.scan.%'
  (k)  ?scope=non_llm excludes llm.scan.* rows
  (l)  risk_score color bands (emerald/amber/red) rendered correctly,
       non-LLM rows show em-dash
  (m)  per-row form includes locked hx-confirm copy verbatim
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


@pytest.fixture
def admin_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[tuple[TestClient, str]]:
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/findings.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.delenv("CCGUARD_SERVER_CONFIG", raising=False)
    with TestClient(create_app()) as c:
        engine = c.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        yield c, sid


def _seed_findings(engine) -> None:
    now = datetime.now(UTC)
    with Session(engine) as s:
        # High-risk LLM finding (red)
        s.add(FindingRecord(
            machine_id="_server", inventory_id=None,
            rule_id="llm.scan.jailbreak", severity="critical",
            discovered_at=now,
            payload_json=json.dumps({
                "file_hash": "h" * 64, "risk_score": 85,
                "category": "jailbreak", "rationale": "x",
                "scope": "agent", "file_path": "/a.md",
                "model": "claude",
            }),
        ))
        # Low-risk LLM finding (emerald)
        s.add(FindingRecord(
            machine_id="_server", inventory_id=None,
            rule_id="llm.scan.benign", severity="info",
            discovered_at=now,
            payload_json=json.dumps({
                "file_hash": "g" * 64, "risk_score": 15,
                "category": "benign", "rationale": "x",
                "scope": "agent", "file_path": "/b.md",
                "model": "claude",
            }),
        ))
        # Mid-risk LLM finding (amber)
        s.add(FindingRecord(
            machine_id="_server", inventory_id=None,
            rule_id="llm.scan.data-exfil", severity="warn",
            discovered_at=now,
            payload_json=json.dumps({
                "file_hash": "i" * 64, "risk_score": 55,
                "category": "data-exfil", "rationale": "x",
                "scope": "agent", "file_path": "/c.md",
                "model": "claude",
            }),
        ))
        # Non-LLM finding (no risk_score in details)
        s.add(FindingRecord(
            machine_id="machine-abc", inventory_id=None,
            rule_id="agents.forbidden_tool", severity="warn",
            discovered_at=now,
            payload_json=json.dumps({"note": "no risk score"}),
        ))
        s.commit()


def test_findings_page_has_new_column_headers(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/findings", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "Риск" in r.text
    assert "Действия" in r.text


def test_scope_filter_llm_only_shows_llm_scan_rows(admin_client) -> None:
    client, sid = admin_client
    _seed_findings(client.app.state.engine)
    r = client.get("/findings?scope=llm", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "llm.scan.jailbreak" in r.text
    assert "agents.forbidden_tool" not in r.text


def test_scope_filter_non_llm_excludes_llm_scan_rows(admin_client) -> None:
    client, sid = admin_client
    _seed_findings(client.app.state.engine)
    r = client.get("/findings?scope=non_llm", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "agents.forbidden_tool" in r.text
    assert "llm.scan.jailbreak" not in r.text


def test_risk_badge_color_bands(admin_client) -> None:
    client, sid = admin_client
    _seed_findings(client.app.state.engine)
    r = client.get("/findings?scope=llm", cookies={"ccg_session": sid})
    body = r.text
    assert "bg-red-600" in body, "risk_score=85 → red"
    assert "bg-emerald-600" in body, "risk_score=15 → emerald"
    assert "bg-amber-600" in body, "risk_score=55 → amber"


def test_non_llm_row_renders_em_dash_in_new_cells(admin_client) -> None:
    client, sid = admin_client
    _seed_findings(client.app.state.engine)
    r = client.get("/findings?scope=non_llm", cookies={"ccg_session": sid})
    body = r.text
    # the em-dash placeholder appears for both the risk cell and the actions cell
    # (since the non-LLM row has no risk_score and no file_hash)
    assert "agents.forbidden_tool" in body
    assert "—" in body


def test_per_row_form_carries_locked_hx_confirm_copy(admin_client) -> None:
    client, sid = admin_client
    _seed_findings(client.app.state.engine)
    r = client.get("/findings?scope=llm", cookies={"ccg_session": sid})
    assert 'hx-confirm="Пересканировать этот файл? Списание из дневного бюджета."' in r.text


def test_scope_select_options_present(admin_client) -> None:
    client, sid = admin_client
    r = client.get("/findings", cookies={"ccg_session": sid})
    body = r.text
    assert "все типы" in body
    assert "только LLM-сканер" in body
    assert "кроме LLM-сканера" in body
