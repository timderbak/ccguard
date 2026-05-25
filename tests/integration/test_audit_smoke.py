"""Phase 1 closure smoke tests: 1000-event /audit render + cross-cutting regressions.

Mirrors :mod:`tests.integration.test_web_smoke` style but for the audit
subsystem. Covers:

  * Bulk-seed pagination + footer line + timeline bars rendered together.
  * Filter narrowing (tool_name, machine_id LIKE).
  * Decision color codepath.
  * HTMX wiring assertion (poll target + trigger + include scope).
  * Russian-copy lockdown (UI-SPEC strings present on rendered /audit).
  * Timeline partial empty + populated standalone renders.
  * Sidebar regression (base.html nav not broken).
  * Backward-compat smoke: v0.1 /api/v1/health, /api/v1/inventory,
    /api/v1/policy still reachable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.schemas import (
    InventoryReport,
    PermissionsSnapshot,
    Policy,
    PolicyMeta,
    SyncPayload,
)
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.conftest import random_fingerprint, seed_tool_use_events

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixture: admin-cookie-authenticated HTML client (matches existing audit_page
# tests so a single helper covers both page + partial smoke).
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        yield client, engine, sid


# ---------------------------------------------------------------------------
# 1. Bulk seed: 1000 events spread over 24h render correctly
# ---------------------------------------------------------------------------


def test_audit_1000_events_render_table_and_timeline(admin_client) -> None:
    client, engine, sid = admin_client
    base = datetime.now(UTC)
    with Session(engine) as s:
        seed_tool_use_events(s, count=1000, base_ts=base, ts_step_seconds=86)

    r = client.get("/audit", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text

    # The events table caps at 200 rows; each row has a `border-b` class.
    # Count `<tr class="border-b` occurrences — exactly 200.
    assert body.count('<tr class="border-b') == 200

    # Overflow footer line names the 1000 total.
    assert (
        "Показано 200 из 1000 событий за период. Сузьте фильтры если нужно больше."
        in body
    )

    # Timeline rendered with 24 bars and a healthy number of non-empty buckets
    # (1000 events spread over ~24h => most or all bars non-empty).
    assert body.count('class="flex-1 bg-slate-700 rounded-sm"') == 24
    # At least 10 buckets have data — a robust lower bound across timing jitter.
    assert body.count("min-height: 2px") >= 10


# ---------------------------------------------------------------------------
# 2. Filter narrowing on tool_name reduces visible counts and timeline buckets
# ---------------------------------------------------------------------------


def test_audit_filter_tool_name_narrows_table_and_timeline(admin_client) -> None:
    client, engine, sid = admin_client
    base = datetime.now(UTC)
    with Session(engine) as s:
        seed_tool_use_events(
            s, count=500, tool_name="Bash", base_ts=base, ts_step_seconds=60,
            machine_id="m-bash",
        )
        seed_tool_use_events(
            s, count=500, tool_name="Edit", base_ts=base, ts_step_seconds=60,
            machine_id="m-edit",
        )

    r = client.get("/audit?tool_name=Bash", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text

    # Footer reflects 500 (only Bash events matched).
    assert "из 500 событий" in body
    # No Edit machine link visible.
    assert "/machines/m-edit" not in body
    # Bash machine link visible.
    assert "/machines/m-bash" in body


# ---------------------------------------------------------------------------
# 3. Filter on machine_id (LIKE prefix) narrows table
# ---------------------------------------------------------------------------


def test_audit_filter_machine_id_prefix(admin_client) -> None:
    client, engine, sid = admin_client
    base = datetime.now(UTC)
    with Session(engine) as s:
        seed_tool_use_events(
            s, count=300, machine_id="laptop-a", base_ts=base, ts_step_seconds=60,
        )
        seed_tool_use_events(
            s, count=300, machine_id="laptop-b", base_ts=base, ts_step_seconds=60,
        )

    r = client.get("/audit?machine_id=laptop-a", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text

    # Table only shows laptop-a links.
    assert "/machines/laptop-a" in body
    assert "/machines/laptop-b" not in body
    # Footer reflects 300 total.
    assert "из 300 событий" in body


# ---------------------------------------------------------------------------
# 4. Decision color codepath: allow=emerald, deny=red, error=amber
# ---------------------------------------------------------------------------


def test_audit_decision_color_classes_present(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        seed_tool_use_events(s, count=3, decision="allow", machine_id="m-allow")
        seed_tool_use_events(s, count=3, decision="deny", machine_id="m-deny")
        seed_tool_use_events(s, count=3, decision="error", machine_id="m-err")

    r = client.get("/audit", cookies={"ccg_session": sid})
    body = r.text
    assert "text-emerald-600" in body
    assert "text-red-600" in body
    assert "text-amber-600" in body


# ---------------------------------------------------------------------------
# 5. HTMX wiring on the timeline card
# ---------------------------------------------------------------------------


def test_audit_page_htmx_polling_wiring_present(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/audit", cookies={"ccg_session": sid})
    body = r.text
    assert 'hx-get="/_partials/audit/timeline"' in body
    assert 'hx-trigger="every 30s"' in body
    assert 'hx-include="closest form"' in body


# ---------------------------------------------------------------------------
# 6. Russian copy lockdown — UI-SPEC strings must remain present
# ---------------------------------------------------------------------------


def test_audit_russian_copy_lockdown(admin_client) -> None:
    """The strings below are the contract surface to the user; changing them
    would silently break a non-English deployment. If a copy update is
    intentional, update this list in the same PR."""
    client, _engine, sid = admin_client
    r = client.get("/audit", cookies={"ccg_session": sid})
    body = r.text
    required = [
        "Аудит",
        "Активность за 24 часа",
        "Фильтр",
        "Сбросить",
        "все решения",
        "за 24 часа",
        "Когда",
        "Машина",
        "Инструмент",
        "Решение",
        "Результат",
        "Fingerprint",
    ]
    missing = [s for s in required if s not in body]
    assert not missing, f"Locked Russian copy missing from /audit: {missing}"


# ---------------------------------------------------------------------------
# 7. Timeline partial standalone (with data): 24 bars, no <html> wrapper
# ---------------------------------------------------------------------------


def test_timeline_partial_with_data_returns_fragment(admin_client) -> None:
    client, engine, sid = admin_client
    with Session(engine) as s:
        seed_tool_use_events(s, count=200, base_ts=datetime.now(UTC), ts_step_seconds=300)

    r = client.get("/_partials/audit/timeline", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    # 24 hourly bar divs.
    assert body.count('class="flex-1 bg-slate-700 rounded-sm"') == 24
    # No full-page HTML wrapper.
    lower = body.lower()
    assert "<html" not in lower
    assert "<!doctype" not in lower
    assert "<body" not in lower


# ---------------------------------------------------------------------------
# 8. Timeline partial standalone empty state
# ---------------------------------------------------------------------------


def test_timeline_partial_empty_db_shows_empty_state(admin_client) -> None:
    client, _engine, sid = admin_client
    r = client.get("/_partials/audit/timeline", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    assert "Нет данных за выбранный период." in body
    # When there's no data, no bar chart container.
    assert "flex items-end" not in body


# ---------------------------------------------------------------------------
# 9. Sidebar nav regression: Аудит + Находки + Политика + Машины all linked
# ---------------------------------------------------------------------------


def test_sidebar_nav_links_unchanged(admin_client) -> None:
    """base.html got an /audit nav insertion in PLAN 01-04 — make sure that
    edit didn't accidentally drop any of the existing nav entries."""
    client, _engine, sid = admin_client
    r = client.get("/", cookies={"ccg_session": sid})
    body = r.text
    # New audit link
    assert 'href="/audit"' in body
    # Pre-existing links from v0.1 layout.
    assert 'href="/findings"' in body
    assert 'href="/policy"' in body
    assert 'href="/machines"' in body


# ---------------------------------------------------------------------------
# 10. Backward-compat smoke: v0.1 endpoints still 200 from the API surface
# ---------------------------------------------------------------------------


def _minimal_inventory(machine_id: str = "compat-machine") -> InventoryReport:
    return InventoryReport(
        machine_id=machine_id,
        timestamp=datetime.now(UTC),
        agent_version="0.1.0",
        os="linux",
        permissions=PermissionsSnapshot(),
    )


def test_v01_health_endpoint_still_200(client: TestClient) -> None:
    # /health is unauthenticated by design (load balancer probe).
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_v01_inventory_endpoint_still_accepts_v01_payload(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    payload = SyncPayload(inventory=_minimal_inventory(), findings=[], audit_events=[])
    r = client.post(
        "/api/v1/inventory",
        json=payload.model_dump(mode="json"),
        headers=auth_headers,
    )
    assert r.status_code == 200, r.text


def test_v01_policy_endpoint_still_returns_seeded_policy(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r = client.get("/api/v1/policy", headers=auth_headers)
    # Either 200 with the test policy, or 304 on subsequent ETag requests —
    # the regression check is that the route still resolves and is not 404.
    assert r.status_code in (200, 304)
    assert r.status_code != 404


# ---------------------------------------------------------------------------
# 11. The new audit POST endpoint did NOT collide with v0.1 routing
# ---------------------------------------------------------------------------


def test_audit_endpoint_openapi_advertised(client: TestClient) -> None:
    r = client.get("/openapi.json")
    paths = r.json()["paths"]
    # Both old and new endpoints reachable in the same OpenAPI schema.
    assert "/api/v1/audit" in paths
    assert "/api/v1/inventory" in paths
    assert "/api/v1/policy" in paths
    assert "/health" in paths
