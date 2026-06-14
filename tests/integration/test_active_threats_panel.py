"""Overview 'active threats' panel — surface the catch on the landing.

The dashboard previously buried critical findings (only a count KPI). This panel
lists the actual block/critical findings with a plain-language label + machine
link, the moat finding (ioa.ai_trigger_escalation) called out with a MOAT badge.
Additive block — renders only when there ARE high-severity findings.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


@pytest.fixture
def admin_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[tuple[TestClient, str]]:
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/threats.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.delenv("CCGUARD_SERVER_CONFIG", raising=False)
    with TestClient(create_app()) as c:
        with Session(c.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        yield c, sid


def _finding(engine, *, machine: str, rule_id: str, severity: str, ago_min: int = 1) -> None:
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add(
            FindingRecord(
                machine_id=machine,
                inventory_id=None,
                rule_id=rule_id,
                severity=severity,
                discovered_at=now - timedelta(minutes=ago_min),
                payload_json=json.dumps({"narrative": "x"}),
            )
        )
        s.commit()


def test_panel_absent_when_no_high_severity(admin_client) -> None:
    client, sid = admin_client
    _finding(client.app.state.engine, machine="m1", rule_id="ioa.slow_chain", severity="warn")
    r = client.get("/", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert 'data-testid="active-threats"' not in r.text  # warn alone → no panel


def test_panel_surfaces_moat_finding_with_label_and_link(admin_client) -> None:
    client, sid = admin_client
    eng = client.app.state.engine
    _finding(eng, machine="dev-laptop-07", rule_id="ioa.ai_trigger_escalation", severity="critical")
    r = client.get("/", cookies={"ccg_session": sid})
    body = r.text
    assert 'data-testid="active-threats"' in body
    # plain-language label, not the raw rule_id
    assert "AI-триггер → эскалация" in body
    # moat callout badge
    assert ">MOAT<" in body
    # links to the machine detail
    assert "/machines/dev-laptop-07" in body


def test_panel_lists_multiple_and_excludes_warn(admin_client) -> None:
    client, sid = admin_client
    eng = client.app.state.engine
    _finding(eng, machine="m1", rule_id="ioa.ai_trigger_escalation", severity="critical", ago_min=1)
    _finding(eng, machine="m2", rule_id="mcp.rug_pull.tools_changed", severity="critical", ago_min=2)
    _finding(eng, machine="m3", rule_id="sensor.hooks_removed", severity="block", ago_min=3)
    _finding(eng, machine="m4", rule_id="ioa.slow_chain", severity="warn", ago_min=4)
    body = client.get("/", cookies={"ccg_session": sid}).text
    assert body.count('data-testid="active-threat-row"') == 3  # warn excluded
    assert "Подмена MCP-сервера (rug-pull)" in body
    assert "Security-хук удалён" in body


def test_moat_finding_sorts_first(admin_client) -> None:
    client, sid = admin_client
    eng = client.app.state.engine
    # seed a non-ioa critical MORE recently than the moat — moat must still lead
    _finding(eng, machine="m2", rule_id="mcp.rug_pull.tools_changed", severity="critical", ago_min=1)
    _finding(eng, machine="m1", rule_id="ioa.ai_trigger_escalation", severity="critical", ago_min=30)
    body = client.get("/", cookies={"ccg_session": sid}).text
    assert body.index("AI-триггер → эскалация") < body.index("Подмена MCP-сервера")
