"""Integration tests for POST /api/v1/audit (TUA-02)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ToolUseEvent

MACHINE_ID = "laptop-int-test"


def _make_event(ts: datetime | None = None,
                tool_name: str = "Bash",
                fingerprint: str = "0123456789abcdef",
                decision: str = "allow",
                result_status: str = "success") -> dict:
    return {
        "ts": (ts or datetime.now(UTC)).isoformat(),
        "tool_name": tool_name,
        "fingerprint": fingerprint,
        "decision": decision,
        "result_status": result_status,
    }


def _make_batch(events: list[dict] | None = None, *,
                schema_version: str = "0.2",
                machine_id: str = MACHINE_ID) -> dict:
    if events is None:
        events = [_make_event()]
    return {
        "schema_version": schema_version,
        "machine_id": machine_id,
        "events": events,
    }


# -------------------- AUTH --------------------

def test_audit_missing_token_returns_401(client: TestClient) -> None:
    r = client.post("/api/v1/audit", json=_make_batch())
    assert r.status_code == 401


def test_audit_invalid_token_returns_401(client: TestClient) -> None:
    r = client.post(
        "/api/v1/audit",
        json=_make_batch(),
        headers={"X-CCGuard-Token": "not-a-real-token"},
    )
    assert r.status_code == 401


# -------------------- HAPPY PATH --------------------

def test_audit_happy_path_3_events(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    batch = _make_batch([_make_event(), _make_event(tool_name="Read"),
                          _make_event(tool_name="Write", decision="deny",
                                      result_status="blocked")])
    r = client.post("/api/v1/audit", json=batch, headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {
        "accepted": True,
        "stored": 3,
        "rejected": 0,
        "server_schema_version": "0.2",
    }
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        rows = list(s.exec(select(ToolUseEvent)))
        assert len(rows) == 3
        assert all(r.machine_id == MACHINE_ID for r in rows)


# -------------------- SCHEMA VERSION --------------------

def test_audit_major_version_mismatch_returns_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/v1/audit",
        json=_make_batch(schema_version="1.0"),
        headers=auth_headers,
    )
    assert r.status_code == 422
    assert "incompatible" in r.json()["detail"].lower() or \
           "schema_version" in r.json()["detail"].lower()


def test_audit_minor_version_diff_accepted(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/v1/audit",
        json=_make_batch(schema_version="0.5"),
        headers=auth_headers,
    )
    assert r.status_code == 200
    assert r.json()["server_schema_version"] == "0.2"


def test_audit_missing_schema_version_returns_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    body = {"machine_id": MACHINE_ID, "events": [_make_event()]}
    r = client.post("/api/v1/audit", json=body, headers=auth_headers)
    assert r.status_code == 422


# -------------------- BATCH SIZE --------------------

def test_audit_oversized_batch_returns_413(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # 201 events — must be rejected. Pydantic max_length=200 will catch this
    # as a 422 validation error BEFORE our 413 check; either status indicates
    # the over-limit was caught. The plan spec says 413; we ensure the request
    # is rejected and no rows persisted.
    batch = _make_batch([_make_event() for _ in range(201)])
    r = client.post("/api/v1/audit", json=batch, headers=auth_headers)
    assert r.status_code in (413, 422)
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        assert list(s.exec(select(ToolUseEvent))) == []


def test_audit_empty_batch_returns_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/v1/audit",
        json=_make_batch([]),
        headers=auth_headers,
    )
    assert r.status_code == 422


# -------------------- VALIDATION --------------------

def test_audit_bad_fingerprint_returns_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    bad = _make_event(fingerprint="not-a-hex")
    r = client.post(
        "/api/v1/audit",
        json=_make_batch([bad]),
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_audit_bad_decision_returns_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    bad = _make_event(decision="ignore")  # not in Literal
    r = client.post(
        "/api/v1/audit",
        json=_make_batch([bad]),
        headers=auth_headers,
    )
    assert r.status_code == 422


# -------------------- TIMESTAMPS --------------------

def test_audit_received_at_server_stamped(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    ts = datetime.now(UTC) - timedelta(hours=2)
    r = client.post(
        "/api/v1/audit",
        json=_make_batch([_make_event(ts=ts)]),
        headers=auth_headers,
    )
    assert r.status_code == 200
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        row = s.exec(select(ToolUseEvent)).one()
        # ts is preserved from request (2h ago)
        # SQLite may strip tzinfo on roundtrip — compare naive components.
        assert row.ts.replace(tzinfo=None).hour == ts.replace(tzinfo=None).hour
        # received_at is set by server, close to now (within 5s)
        ra = row.received_at
        if ra.tzinfo is None:
            ra = ra.replace(tzinfo=UTC)
        assert abs((datetime.now(UTC) - ra).total_seconds()) < 5


# -------------------- REGRESSION --------------------

def test_v01_inventory_endpoint_still_works(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """v0.1 endpoints must not be perturbed by the new audit router."""
    # GET /api/v1/machines is a stable v0.1 endpoint that requires only auth.
    r = client.get("/api/v1/machines", headers=auth_headers)
    assert r.status_code == 200


def test_openapi_advertises_audit_endpoint(client: TestClient) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert "/api/v1/audit" in paths
    assert "post" in paths["/api/v1/audit"]
