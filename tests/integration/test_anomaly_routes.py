"""Integration tests for anomaly routes (Plan 02-06 / Task 1).

Covers:
- /anomalies main page (auth + render)
- /_partials/anomalies/overview (empty + populated)
- /_partials/anomalies/matrix (no machines / warm-up cell / outlier cell)
- /anomalies/{machine_id}/{metric} drill-down (404 on unknown metric, baseline empty)
- Russian copy lockdown for UI-SPEC strings

Pattern lifted from tests/integration/test_anomalies_overview_partial.py — uses
its admin_client fixture shape (TestClient + engine + session id), inlined here
so this file is self-contained.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
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


# ---------------------------------------------------------------------------
# /anomalies feed page (auth + render)
# ---------------------------------------------------------------------------


def test_anomalies_feed_unauthenticated_redirects_or_401(admin_client) -> None:
    client, _engine, _sid = admin_client
    r = client.get("/anomalies", follow_redirects=False)
    assert r.status_code in (307, 401)
    if r.status_code == 307:
        assert r.headers["location"] == "/login"


def test_anomalies_feed_authed_renders_heading(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/anomalies", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # UI-SPEC: "Аномалии" heading on the page.
    assert "Аномалии" in r.text
    # HTMX hydration of the matrix partial is wired.
    assert "/_partials/anomalies/matrix" in r.text


# ---------------------------------------------------------------------------
# /_partials/anomalies/overview (empty + populated)
# ---------------------------------------------------------------------------


def test_overview_partial_empty_state_shows_anomalies_net(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/_partials/anomalies/overview", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # UI-SPEC: empty-state copy must be literal "Аномалий нет."
    assert "Аномалий нет." in r.text


def test_overview_partial_renders_seeded_finding(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        s.add(
            FindingRecord(
                machine_id="mtest-xyz-9999",
                inventory_id=None,
                rule_id="anomaly.bash_calls_per_day",
                severity="warn",
                discovered_at=datetime.now(UTC),
                payload_json=json.dumps(
                    {
                        "observed_value": 42.0,
                        "sigma_distance": 4.1,
                        "mean": 5.0,
                        "stdev": 2.0,
                    }
                ),
            )
        )
        s.commit()
    r = client.get("/_partials/anomalies/overview", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # First 12 chars of machine_id appear (UI-SPEC truncation).
    assert "mtest-xyz-99" in r.text
    # Metric label parsed from rule_id.
    assert "bash_calls_per_day" in r.text


# ---------------------------------------------------------------------------
# /_partials/anomalies/matrix (no machines / warm-up / outlier)
# ---------------------------------------------------------------------------


def test_matrix_partial_no_machines_shows_mashin_net(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/_partials/anomalies/matrix", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # UI-SPEC: when no machines exist, exact literal "Машин нет." must be rendered.
    assert "Машин нет." in r.text


def test_matrix_partial_warmup_cell_renders_nakoplenie(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        s.add(Machine(machine_id="m-warm-001"))
        s.add(
            MachineBaseline(
                machine_id="m-warm-001",
                metric="bash_calls_per_day",
                mean=0.0,
                stdev=0.0,
                sample_count=3,
                baseline_ready=False,
                recent_points_json="[1,2,3]",
            )
        )
        s.commit()
    r = client.get("/_partials/anomalies/matrix", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # UI-SPEC: warm-up cell label "накопление…".
    assert "накопление" in r.text
    assert "m-warm-001"[:12] in r.text


def test_matrix_partial_outlier_cell_renders_vybros_badge(admin_client) -> None:
    client, engine, sid = admin_client
    # Construct a baseline whose last point is far above mean+3*stdev.
    points = [5, 5, 6, 5, 4, 5, 6, 5, 5, 4, 5, 6, 5, 99]
    with Session(engine) as s:
        s.add(Machine(machine_id="m-out-002"))
        s.add(
            MachineBaseline(
                machine_id="m-out-002",
                metric="bash_calls_per_day",
                mean=5.0,
                stdev=0.8,
                sample_count=14,
                baseline_ready=True,
                recent_points_json=json.dumps(points),
            )
        )
        s.commit()
    r = client.get("/_partials/anomalies/matrix", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # UI-SPEC: outlier badge literal "выброс".
    assert "выброс" in r.text


# ---------------------------------------------------------------------------
# /anomalies/{machine_id}/{metric} drill-down
# ---------------------------------------------------------------------------


def test_anomaly_detail_unknown_metric_returns_404(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get(
        "/anomalies/anymachine/unknown_metric", cookies={"ccg_session": sid}
    )
    assert r.status_code == 404


def test_anomaly_detail_known_metric_renders_back_link_and_baseline_card(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        s.add(Machine(machine_id="mtest-detail"))
        s.commit()
    r = client.get(
        "/anomalies/mtest-detail/bash_calls_per_day", cookies={"ccg_session": sid}
    )
    assert r.status_code == 200
    # UI-SPEC back link
    assert "Все аномалии" in r.text
    # UI-SPEC Baseline card heading
    assert "Baseline" in r.text


def test_anomaly_detail_no_baseline_row_shows_warmup_copy(admin_client) -> None:
    client, engine, sid = admin_client
    # Seed the machine but NOT the baseline → baseline_ready=False → warm-up.
    with Session(engine) as s:
        s.add(Machine(machine_id="mtest-warm"))
        s.commit()
    r = client.get(
        "/anomalies/mtest-warm/bash_calls_per_day", cookies={"ccg_session": sid}
    )
    assert r.status_code == 200
    # UI-SPEC: "Недостаточно данных для baseline" line.
    assert "Недостаточно данных для baseline" in r.text


def test_anomaly_detail_malformed_recent_points_json_no_500(admin_client) -> None:
    """WR-07: a MachineBaseline with non-list / non-numeric / NaN
    recent_points_json must not 500 the detail route."""
    client, engine, sid = admin_client
    with Session(engine) as s:
        s.add(Machine(machine_id="mtest-bad-pts"))
        for malformed in ("null", "{}", '"oops"', '[1, "x", NaN, true, 3]'):
            s.add(
                MachineBaseline(
                    machine_id="mtest-bad-pts",
                    metric="bash_calls_per_day",
                    mean=1.0,
                    stdev=0.5,
                    sample_count=8,
                    baseline_ready=True,
                    recent_points_json=malformed,
                    updated_at=datetime.now(UTC),
                )
            )
            s.commit()
            r = client.get(
                "/anomalies/mtest-bad-pts/bash_calls_per_day",
                cookies={"ccg_session": sid},
            )
            assert r.status_code == 200, f"500 on payload={malformed!r}: {r.text[:200]}"
            # Clean up so the next iteration's insert doesn't violate UNIQUE.
            s.exec(
                MachineBaseline.__table__.delete().where(
                    MachineBaseline.machine_id == "mtest-bad-pts"
                )
            )
            s.commit()


def test_anomaly_detail_unknown_machine_id_404(admin_client) -> None:
    """WR-04: unknown machine_id returns 404 (mirrors machine_detail)."""
    client, _engine, sid = admin_client
    r = client.get(
        "/anomalies/totally-fake-id/bash_calls_per_day",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 404


def test_anomaly_detail_unauthenticated_redirects_or_401(admin_client) -> None:
    client, _engine, _sid = admin_client
    r = client.get(
        "/anomalies/m/bash_calls_per_day", follow_redirects=False
    )
    assert r.status_code in (307, 401)
