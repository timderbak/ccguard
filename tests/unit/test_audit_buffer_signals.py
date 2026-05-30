"""Buffer carries the signals JSON column round-trip."""
from __future__ import annotations

import sqlite3

from ccguard.agent.audit_hook.buffer import ToolBufferDB


def test_insert_and_drain_signals(tmp_path):
    db = tmp_path / "audit_buffer.db"
    with ToolBufferDB(db) as buf:
        buf.insert(
            ts="2026-05-30T10:00:00+00:00",
            tool_name="Bash",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals=["cred.read.aws", "egress.network_tool"],
        )
        rows = buf.drain(10)
    assert rows[0]["signals"] == ["cred.read.aws", "egress.network_tool"]


def test_insert_defaults_signals_to_empty(tmp_path):
    db = tmp_path / "audit_buffer.db"
    with ToolBufferDB(db) as buf:
        buf.insert(
            ts="2026-05-30T10:00:00+00:00",
            tool_name="Bash",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
        )
        rows = buf.drain(10)
    assert rows[0]["signals"] == []


def test_forward_migration_adds_signals_column(tmp_path):
    """Pre-existing DB without signals column gets it via ALTER TABLE on open."""
    db = tmp_path / "audit_buffer.db"

    # Manually create a DB with the old schema (no signals column).
    conn = sqlite3.connect(str(db))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          tool_name TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          decision TEXT NOT NULL,
          result_status TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_events_id ON events(id);
    """)
    conn.execute(
        "INSERT INTO events(ts, tool_name, fingerprint, decision, result_status) "
        "VALUES ('2026-05-30T09:00:00+00:00', 'Read', 'aabbccdd', 'allow', 'success')"
    )
    conn.commit()
    conn.close()

    # Open with ToolBufferDB — migration should add the column.
    with ToolBufferDB(db) as buf:
        buf.insert(
            ts="2026-05-30T10:00:00+00:00",
            tool_name="Bash",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals=["entropy.high"],
        )
        rows = buf.drain(100)

    # Old row migrated with default empty list; new row carries signals.
    assert rows[0]["signals"] == []
    assert rows[1]["signals"] == ["entropy.high"]
