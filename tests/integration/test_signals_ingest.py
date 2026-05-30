"""POST /api/v1/audit persists per-event signals into ToolUseEvent.

Per-test DB isolation is guaranteed by the function-scoped `client` fixture in
tests/integration/conftest.py, which creates a fresh tmp_path (and thus a new
SQLite database) for each test. Tests can safely assume no leftover rows from
prior test runs.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ToolUseEvent


def test_ingest_persists_signals(client: TestClient, auth_headers: dict[str, str]) -> None:
    body = {
        "schema_version": "0.2",
        "machine_id": "m-test",
        "events": [
            {
                "ts": "2026-05-30T10:00:00+00:00",
                "tool_name": "Bash",
                "fingerprint": "0123456789abcdef",
                "decision": "allow",
                "result_status": "success",
                "signals": ["cred.read.aws", "egress.network_tool"],
            }
        ],
    }
    resp = client.post("/api/v1/audit", content=json.dumps(body), headers=auth_headers)
    assert resp.status_code == 200, resp.text

    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        row = session.exec(select(ToolUseEvent)).first()
    assert row is not None
    assert json.loads(row.signals_json) == ["cred.read.aws", "egress.network_tool"]


def test_ingest_v01_agent_without_signals_defaults_empty(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    body = {
        "schema_version": "0.2",
        "machine_id": "m-test",
        "events": [
            {
                "ts": "2026-05-30T10:00:00+00:00",
                "tool_name": "Bash",
                "fingerprint": "fedcba9876543210",
                "decision": "allow",
                "result_status": "success",
            }
        ],
    }
    resp = client.post("/api/v1/audit", content=json.dumps(body), headers=auth_headers)
    assert resp.status_code == 200, resp.text

    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        row = session.exec(select(ToolUseEvent)).first()
    assert row is not None
    assert json.loads(row.signals_json) == []
