"""Integration tests for GET /_partials/anomalies/overview (Plan 02-04)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("CCGUARD_DISABLE_SCHEDULER", "1")
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        yield client, engine, sid


def _seed_finding(
    session: Session,
    *,
    machine_id: str = "m1",
    rule_id: str = "anomaly.bash_calls_per_day",
    severity: str = "warn",
    observed_value: float = 42.0,
    sigma_distance: float = 3.4,
    discovered_at: datetime | None = None,
) -> None:
    session.add(
        FindingRecord(
            machine_id=machine_id,
            inventory_id=None,
            rule_id=rule_id,
            severity=severity,
            discovered_at=discovered_at or datetime.now(UTC),
            payload_json=json.dumps(
                {"observed_value": observed_value, "sigma_distance": sigma_distance}
            ),
        )
    )


def test_anomalies_overview_anonymous_redirects_or_401(admin_client) -> None:
    client, _engine, _sid = admin_client
    r = client.get(
        "/_partials/anomalies/overview",
        follow_redirects=False,
        headers={"accept": "text/html"},
    )
    assert r.status_code in (307, 401)
    if r.status_code == 307:
        assert r.headers["location"] == "/login"


def test_anomalies_overview_empty_state(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/_partials/anomalies/overview", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "Аномалии" in r.text
    assert "Аномалий нет." in r.text


def test_anomalies_overview_renders_top5_recent(admin_client) -> None:
    client, engine, sid = admin_client
    now = datetime.now(UTC)
    with Session(engine) as s:
        # Seed 7 anomalies; oldest 2 should not appear in top-5.
        for i in range(7):
            _seed_finding(
                s,
                machine_id=f"machine-{i:02d}",
                rule_id="anomaly.bash_calls_per_day",
                observed_value=10.0 + i,
                sigma_distance=3.0 + i * 0.1,
                discovered_at=now - timedelta(minutes=i),
            )
        # Seed a non-anomaly finding — must be excluded.
        s.add(
            FindingRecord(
                machine_id="other",
                inventory_id=None,
                rule_id="policy.violation",
                severity="warn",
                discovered_at=now,
                payload_json="{}",
            )
        )
        s.commit()
    r = client.get("/_partials/anomalies/overview", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # 5 newest machines present (00..04), oldest two (05, 06) absent.
    for i in range(5):
        assert f"machine-{i:02d}" in r.text
    assert "machine-05" not in r.text
    assert "machine-06" not in r.text
    # Non-anomaly rule excluded.
    assert "policy.violation" not in r.text
    # Metric parsed from rule_id is visible.
    assert "bash_calls_per_day" in r.text
    # Click-through href is well-formed.
    assert "/anomalies/machine-00/bash_calls_per_day" in r.text


def test_anomalies_overview_is_fragment_not_full_page(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/_partials/anomalies/overview", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "<html" not in r.text.lower()
    assert "<aside" not in r.text.lower()


def test_overview_page_includes_anomalies_card(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert '/_partials/anomalies/overview' in r.text
    assert 'hx-trigger="load, every 60s"' in r.text
    # Sidebar link present
    assert 'href="/anomalies"' in r.text


def test_overview_partial_handles_malformed_payload(admin_client) -> None:
    """A FindingRecord with non-JSON payload_json must not 500 the partial."""
    client, engine, sid = admin_client
    with Session(engine) as s:
        s.add(
            FindingRecord(
                machine_id="m-bad",
                inventory_id=None,
                rule_id="anomaly.new_mcp_per_week",
                severity="warn",
                discovered_at=datetime.now(UTC),
                payload_json="not-json",
            )
        )
        s.commit()
    r = client.get("/_partials/anomalies/overview", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "m-bad" in r.text
    assert "new_mcp_per_week" in r.text
