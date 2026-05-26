"""POST /api/v1/audit (policy_apply) → GET /audit page roundtrip (Plan 04-06).

Cross-cutting verification that the two halves shipped in plans 04-04 (POST
endpoint) and 04-05 (/audit page filter) compose correctly: a single test
POSTs a batch of one success + one rollback event through the public API,
then asserts the /audit page renders both with the locked Tailwind pills,
ordering, and combined-filter behaviors.

The point is not to re-test either side in isolation (those tests live in
``test_audit_policy_apply_endpoint.py`` and
``test_audit_page_policy_apply_filter.py``) but to prove the pipeline holds
when the same backing DB row is written by the public endpoint and read by
the web view.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.schemas import Policy, PolicyMeta
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


# ---------------------------------------------------------------------------
# fixture: one TestClient that holds BOTH an admin session (for /audit GET)
# AND an API token (for POST /api/v1/audit), so we can drive both ends from
# the same engine within a single test.
# ---------------------------------------------------------------------------


@pytest.fixture
def dual_client(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("CCGUARD_TOKENS", "test-token-abc")
    pol_path = tmp_path / "bootstrap_policy.yaml"
    pol_path.write_text(
        yaml.safe_dump(
            Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC))).model_dump(
                mode="json"
            )
        )
    )
    monkeypatch.setenv("CCGUARD_POLICY_PATH", str(pol_path))

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        yield client, sid


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


_API_HEADERS = {"X-CCGuard-Token": "test-token-abc"}


def _post_apply_batch(client: TestClient, events: list[dict]) -> None:
    body = {"event_source": "policy_apply", "events": events}
    r = client.post("/api/v1/audit", json=body, headers=_API_HEADERS)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["accepted"] is True
    assert out["stored"] == len(events)


def _success_event(machine_id: str = "host-success", ts: datetime | None = None) -> dict:
    return {
        "machine_id": machine_id,
        "ts": (ts or datetime.now(UTC)).isoformat(),
        "result": "success",
        "applied_count": 3,
        "snapshot_id": "0123456789abcdef",
        "reason": None,
        "failed_file": None,
        "policy_revision": 5,
    }


def _rollback_event(
    machine_id: str = "host-rollback",
    ts: datetime | None = None,
    reason: str = "PermissionError on agents dir",
    failed_file: str = ".claude/agents/x.md",
) -> dict:
    return {
        "machine_id": machine_id,
        "ts": (ts or datetime.now(UTC)).isoformat(),
        "result": "rollback",
        "applied_count": 1,
        "snapshot_id": "fedcba9876543210",
        "reason": reason,
        "failed_file": failed_file,
        "policy_revision": 5,
    }


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_post_audit_then_get_audit_renders_both_pills(dual_client) -> None:
    """A batch of 2 (success + rollback) posted through /api/v1/audit appears
    on /audit?event_source=policy_apply in the same request cycle, with the
    two locked Tailwind pills."""
    client, sid = dual_client
    _post_apply_batch(client, [_success_event(), _rollback_event()])

    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    assert r.status_code == 200
    body = r.text
    # both pills present
    assert "bg-emerald-600" in body
    assert "bg-red-600" in body
    assert ">success<" in body
    assert ">rollback<" in body
    # rollback row shows reason highlighted in amber
    assert "text-amber-600" in body
    assert "PermissionError" in body
    # machine links for both rows
    assert "/machines/host-success" in body
    assert "/machines/host-rollback" in body


def test_roundtrip_orders_newest_first(dual_client) -> None:
    client, sid = dual_client
    now = datetime.now(UTC)
    _post_apply_batch(
        client,
        [
            _success_event(machine_id="oldhost1", ts=now - timedelta(hours=2)),
            _success_event(machine_id="midhost1", ts=now - timedelta(hours=1)),
            _rollback_event(machine_id="newhost1", ts=now),
        ],
    )
    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    body = r.text
    pos_new = body.find("/machines/newhost1")
    pos_mid = body.find("/machines/midhost1")
    pos_old = body.find("/machines/oldhost1")
    assert pos_new != -1 and pos_mid != -1 and pos_old != -1
    assert pos_new < pos_mid < pos_old


def test_roundtrip_machine_filter_combines_with_event_source(dual_client) -> None:
    """machine_id filter narrows policy_apply results to a single host."""
    client, sid = dual_client
    _post_apply_batch(
        client,
        [
            _success_event(machine_id="alphaboxx"),
            _rollback_event(machine_id="betaboxxx"),
        ],
    )
    r = client.get(
        "/audit?event_source=policy_apply&machine_id=alpha",
        cookies={"ccg_session": sid},
    )
    body = r.text
    assert "/machines/alphaboxx" in body
    assert "/machines/betaboxxx" not in body


def test_roundtrip_timeframe_filter_narrows(dual_client) -> None:
    """timeframe=1h excludes 3h-old events; timeframe=7d includes them."""
    client, sid = dual_client
    long_ago = datetime.now(UTC) - timedelta(hours=3)
    _post_apply_batch(client, [_success_event(machine_id="stalehost", ts=long_ago)])
    r_1h = client.get(
        "/audit?event_source=policy_apply&timeframe=1h",
        cookies={"ccg_session": sid},
    )
    assert "/machines/stalehost" not in r_1h.text
    assert "Событий нет." in r_1h.text

    r_7d = client.get(
        "/audit?event_source=policy_apply&timeframe=7d",
        cookies={"ccg_session": sid},
    )
    assert "/machines/stalehost" in r_7d.text


def test_roundtrip_batch_of_one_still_works(dual_client) -> None:
    """Min batch size is 1 — a single success event renders correctly."""
    client, sid = dual_client
    _post_apply_batch(client, [_success_event(machine_id="solohostt")])
    r = client.get("/audit?event_source=policy_apply", cookies={"ccg_session": sid})
    body = r.text
    assert "bg-emerald-600" in body
    assert "/machines/solohostt" in body
    # no rollback pill leaked
    assert "bg-red-600" not in body


def test_default_audit_view_isolated_from_policy_apply_inserts(dual_client) -> None:
    """The default /audit view (no event_source filter) renders the tool_use
    table — posting policy_apply rows MUST NOT contaminate the v0.1 layout."""
    client, sid = dual_client
    _post_apply_batch(client, [_success_event(), _rollback_event()])
    r = client.get("/audit", cookies={"ccg_session": sid})
    body = r.text
    assert "<th>Инструмент</th>" in body
    assert "<th>Решение</th>" in body
    # No policy_apply pill markup in the default branch
    assert "bg-emerald-600" not in body
    assert "bg-red-600" not in body
    # Empty-state copy preserved (no tool_use events were posted)
    assert "Аудит-событий нет." in body
