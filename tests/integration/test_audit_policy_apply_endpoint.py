"""Integration tests for POST /api/v1/audit branch event_source=policy_apply (04-04).

Covers:
- success persist
- rollback persist with reason+failed_file
- v0.1 tool_use payload still works unchanged (regression)
- unknown event_source returns 400
- missing schema_version is accepted
- auth still enforced
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import PolicyApplyEvent, ToolUseEvent

MACHINE_ID = "laptop-policy-apply-test"


def _apply_event(**overrides) -> dict:
    base = {
        "machine_id": MACHINE_ID,
        "ts": datetime.now(UTC).isoformat(),
        "result": "success",
        "applied_count": 3,
        "snapshot_id": "20260526-120000",
        "reason": None,
        "failed_file": None,
        "policy_revision": 7,
    }
    base.update(overrides)
    return base


def _apply_batch(events: list[dict] | None = None, *, schema_version: str | None = None) -> dict:
    body: dict = {
        "event_source": "policy_apply",
        "events": events or [_apply_event()],
    }
    if schema_version is not None:
        body["schema_version"] = schema_version
    return body


# -------------------- AUTH --------------------

def test_policy_apply_missing_token_returns_401(client: TestClient) -> None:
    r = client.post("/api/v1/audit", json=_apply_batch())
    assert r.status_code == 401


# -------------------- HAPPY PATH --------------------

def test_policy_apply_success_persists_one_row(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r = client.post("/api/v1/audit", json=_apply_batch(), headers=auth_headers)
    assert r.status_code == 200, r.text

    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        rows = list(s.exec(select(PolicyApplyEvent)))
        assert len(rows) == 1
        row = rows[0]
        assert row.machine_id == MACHINE_ID
        assert row.result == "success"
        assert row.applied_count == 3
        assert row.snapshot_id == "20260526-120000"
        assert row.policy_revision == 7
        assert row.reason is None
        assert row.failed_file is None


def test_policy_apply_rollback_persists_reason_and_failed_file(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    ev = _apply_event(
        result="rollback",
        applied_count=1,
        reason="PermissionError on agents dir",
        failed_file="/home/u/.claude/agents/x.md",
    )
    r = client.post("/api/v1/audit", json=_apply_batch([ev]), headers=auth_headers)
    assert r.status_code == 200, r.text

    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        rows = list(s.exec(select(PolicyApplyEvent)))
        assert len(rows) == 1
        row = rows[0]
        assert row.result == "rollback"
        assert row.reason == "PermissionError on agents dir"
        assert row.failed_file == "/home/u/.claude/agents/x.md"
        assert row.applied_count == 1


def test_policy_apply_missing_schema_version_accepted(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # D-1: server tolerates payloads without schema_version
    r = client.post("/api/v1/audit", json=_apply_batch(), headers=auth_headers)
    assert r.status_code == 200, r.text


# -------------------- ERROR PATHS --------------------

def test_policy_apply_unknown_event_source_returns_400(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    body = _apply_batch()
    body["event_source"] = "policy_apply_v2"
    r = client.post("/api/v1/audit", json=body, headers=auth_headers)
    assert r.status_code == 400
    assert "event_source" in r.json()["detail"].lower()


def test_policy_apply_invalid_result_value_returns_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    ev = _apply_event(result="maybe")
    r = client.post("/api/v1/audit", json=_apply_batch([ev]), headers=auth_headers)
    assert r.status_code == 422


# -------------------- BACKWARD COMPAT --------------------

def test_legacy_tool_use_payload_still_works(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """A v0.1-style payload (no event_source) must keep working unchanged."""
    legacy = {
        "schema_version": "0.2",
        "machine_id": MACHINE_ID,
        "events": [{
            "ts": datetime.now(UTC).isoformat(),
            "tool_name": "Bash",
            "fingerprint": "0123456789abcdef",
            "decision": "allow",
            "result_status": "success",
        }],
    }
    r = client.post("/api/v1/audit", json=legacy, headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    # legacy response shape
    assert body.get("accepted") is True
    assert body.get("stored") == 1

    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        tool_rows = list(s.exec(select(ToolUseEvent)))
        apply_rows = list(s.exec(select(PolicyApplyEvent)))
        assert len(tool_rows) == 1
        assert len(apply_rows) == 0


def test_explicit_tool_use_event_source_routes_to_legacy(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Explicit event_source='tool_use' should route to the legacy handler."""
    body = {
        "event_source": "tool_use",
        "schema_version": "0.2",
        "machine_id": MACHINE_ID,
        "events": [{
            "ts": datetime.now(UTC).isoformat(),
            "tool_name": "Read",
            "fingerprint": "fedcba9876543210",
            "decision": "allow",
            "result_status": "success",
        }],
    }
    r = client.post("/api/v1/audit", json=body, headers=auth_headers)
    assert r.status_code == 200, r.text
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        tool_rows = list(s.exec(select(ToolUseEvent)))
        apply_rows = list(s.exec(select(PolicyApplyEvent)))
        assert len(tool_rows) == 1
        assert len(apply_rows) == 0
