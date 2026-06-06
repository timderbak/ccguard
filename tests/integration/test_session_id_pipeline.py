"""ТЗ-01: session_id end-to-end (hook → buffer → /audit → ToolUseEvent) + DB migration.

Covers acceptance criteria #1 (old agent without session_id ingests as NULL)
and #2 (new agent threads session_id all the way to ToolUseEvent.session_id),
plus the additive-column migration on a pre-session-id server DB.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlmodel import Session, select

from ccguard.agent.audit_hook import hook_main
from ccguard.agent.audit_hook.buffer import ToolBufferDB
from ccguard.server.db.models import ToolUseEvent
from ccguard.server.db.session import init_db, make_engine


def _event(session_id: str | None) -> dict:
    e = {
        "ts": datetime.now(UTC).isoformat(),
        "tool_name": "Bash",
        "fingerprint": "0123456789abcdef",
        "decision": "allow",
        "result_status": "success",
        "signals": ["cred.read.aws"],
    }
    if session_id is not None:
        e["session_id"] = session_id
    return e


def _post(client: TestClient, headers: dict[str, str], machine_id: str, event: dict) -> None:
    body = {"schema_version": "0.2", "machine_id": machine_id, "events": [event]}
    resp = client.post("/api/v1/audit", content=json.dumps(body), headers=headers)
    assert resp.status_code == 200, resp.text


# --- API persistence --------------------------------------------------------


def test_post_audit_persists_session_id(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    _post(client, auth_headers, "m-sid", _event("abc"))
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        row = s.exec(select(ToolUseEvent).where(ToolUseEvent.machine_id == "m-sid")).one()
    assert row.session_id == "abc"


def test_post_audit_without_session_id_is_null(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Acceptance #1: a v0.1 event (no session_id) ingests cleanly as NULL."""
    _post(client, auth_headers, "m-old", _event(None))
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        row = s.exec(select(ToolUseEvent).where(ToolUseEvent.machine_id == "m-old")).one()
    assert row.session_id is None


# --- end-to-end hook → buffer → API → DB ------------------------------------


def test_hook_to_db_threads_session_id(
    client: TestClient,
    auth_headers: dict[str, str],
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Acceptance #2: session_id flows hook → buffer → (flusher-shaped batch) → DB."""
    cc_home = tmp_path / ".ccguard"
    cc_home.mkdir()
    monkeypatch.setenv("CCGUARD_AGENT_HOME", str(cc_home))
    monkeypatch.setattr(hook_main, "maybe_spawn_flusher", lambda **_k: None)

    hook_main.main_cli(
        json.dumps(
            {
                "session_id": "e2e-sess",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "tool_response": {},
            }
        )
    )

    # Drain the buffer exactly as the flusher does and POST through the API.
    with ToolBufferDB(cc_home / "audit_buffer.db") as buf:
        rows = buf.drain()
    assert len(rows) == 1
    event = {
        "ts": rows[0]["ts"],
        "tool_name": rows[0]["tool_name"],
        "fingerprint": rows[0]["fingerprint"],
        "decision": rows[0]["decision"],
        "result_status": rows[0]["result_status"],
        "signals": rows[0]["signals"],
        "session_id": rows[0]["session_id"],
    }
    _post(client, auth_headers, "m-e2e", event)

    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        row = s.exec(select(ToolUseEvent).where(ToolUseEvent.machine_id == "m-e2e")).one()
    assert row.session_id == "e2e-sess"


# --- additive-column migration on a pre-session-id server DB ----------------


def test_init_db_adds_session_id_column_to_legacy_table(tmp_path: Path) -> None:
    """create_all is a no-op on an existing tooluseevent table — init_db must
    ALTER in the session_id column (mirrors the ScanResult rationale columns)."""
    db_path = tmp_path / "legacy.db"
    engine = make_engine(f"sqlite:///{db_path}")
    # Build a pre-session-id tooluseevent table (no session_id column) + one row.
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE tooluseevent ("
                "  id INTEGER PRIMARY KEY,"
                "  machine_id TEXT NOT NULL,"
                "  ts TEXT NOT NULL,"
                "  received_at TEXT NOT NULL,"
                "  tool_name TEXT NOT NULL,"
                "  fingerprint TEXT NOT NULL,"
                "  decision TEXT NOT NULL,"
                "  result_status TEXT NOT NULL,"
                "  signals_json TEXT NOT NULL DEFAULT '[]',"
                "  actor_user TEXT"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO tooluseevent"
                "(machine_id, ts, received_at, tool_name, fingerprint, decision, result_status) "
                "VALUES ('m', '2026-06-06T00:00:00', '2026-06-06T00:00:00', "
                "'Bash', '0123456789abcdef', 'allow', 'success')"
            )
        )

    init_db(engine)

    with engine.begin() as conn:
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(tooluseevent)"))}
        assert "session_id" in cols
        legacy = conn.execute(text("SELECT session_id FROM tooluseevent")).fetchone()
    assert legacy[0] is None  # legacy row → NULL session_id
