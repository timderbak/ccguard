"""Local SQLite WAL buffer for PostToolUse audit events (TUA-01, TUA-02).

Backs ``~/.ccguard/audit_buffer.db``. Uses stdlib ``sqlite3`` (not SQLModel) to
keep agent hot-path cold-start under 20ms.

Concurrency model (T-01-02 mitigation):

* ``PRAGMA journal_mode=WAL`` — readers don't block writers.
* ``PRAGMA busy_timeout=5000`` — wait up to 5s for a competing writer.
* ``BEGIN IMMEDIATE`` — acquire the write lock upfront; fail fast if contended.
* Short single-INSERT transactions — minimize lock-hold time so 5+ concurrent
  PostToolUse hooks on the same machine don't lose events.

DoS containment (T-01-03): :meth:`ToolBufferDB.trim_to_cap` is invoked by the
flusher to drop the oldest rows once the table exceeds the configured cap
(default 10 000 rows).

File-mode note (T-01-04): the parent directory ``~/.ccguard/`` is created with
mode 0700 by ``ccguard.agent.config``; the buffer DB file inherits the parent's
ACL. This module does not chmod the DB file itself.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import TypedDict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  decision TEXT NOT NULL,
  result_status TEXT NOT NULL,
  signals TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_id ON events(id);
"""


class BufferRow(TypedDict):
    id: int
    ts: str
    tool_name: str
    fingerprint: str
    decision: str
    result_status: str
    signals: list[str]


class ToolBufferDB:
    """Context-manager wrapper around the agent-local sqlite buffer.

    Usage::

        with ToolBufferDB(path) as buf:
            buf.insert(ts=..., tool_name=..., fingerprint=...,
                       decision=..., result_status=...)
    """

    path: Path
    conn: sqlite3.Connection

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self) -> ToolBufferDB:
        # isolation_level=None — manual transaction management via BEGIN IMMEDIATE.
        self.conn = sqlite3.connect(
            str(self.path), timeout=5.0, isolation_level=None
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        # WR-04: run DDL only when the events table is missing. executescript
        # issues an implicit COMMIT that can briefly contend with concurrent
        # BEGIN IMMEDIATE writers on every hook invocation; gating on a cheap
        # sqlite_master probe keeps the hot path free of that overhead once
        # the schema has been initialized.
        cur = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        )
        if cur.fetchone() is None:
            self.conn.executescript(_SCHEMA)
        else:
            # Forward-add the signals column on buffer DBs created before
            # Behavioral Detection Stage 1. ADD COLUMN is fast metadata-only;
            # guarded so we only pay it once.
            cols = {
                r[1] for r in self.conn.execute("PRAGMA table_info(events)").fetchall()
            }
            if "signals" not in cols:
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN signals TEXT NOT NULL DEFAULT '[]'"
                )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.conn.close()

    # --- write path -----------------------------------------------------

    def insert(
        self,
        *,
        ts: str,
        tool_name: str,
        fingerprint: str,
        decision: str,
        result_status: str,
        signals: list[str] | None = None,
    ) -> None:
        """Insert a single event under BEGIN IMMEDIATE + COMMIT."""
        signals_json = json.dumps(signals or [])
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute(
                "INSERT INTO events"
                "(ts, tool_name, fingerprint, decision, result_status, signals) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ts, tool_name, fingerprint, decision, result_status, signals_json),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    # --- read path ------------------------------------------------------

    def row_count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM events")
        return int(cur.fetchone()[0])

    def drain(self, limit: int = 200, *, after_id: int = 0) -> list[BufferRow]:
        """Return the oldest ``limit`` rows by id ASC. Does NOT delete.

        ``after_id`` lets the flusher skip past rows it already tried (and
        failed) within a single flush invocation — WR-02 mitigation so a
        transiently-failing first batch does not block draining of subsequent
        batches whose rows are still in the buffer.
        """
        cur = self.conn.execute(
            "SELECT id, ts, tool_name, fingerprint, decision, result_status, signals "
            "FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (after_id, limit),
        )
        out: list[BufferRow] = []
        for row in cur.fetchall():
            try:
                signals = json.loads(row[6]) if row[6] else []
                if not isinstance(signals, list):
                    signals = []
            except (ValueError, TypeError):
                signals = []
            out.append(
                BufferRow(
                    id=int(row[0]),
                    ts=str(row[1]),
                    tool_name=str(row[2]),
                    fingerprint=str(row[3]),
                    decision=str(row[4]),
                    result_status=str(row[5]),
                    signals=signals,
                )
            )
        return out

    # --- delete path ----------------------------------------------------

    def delete_ids(self, ids: list[int]) -> None:
        """Remove rows by id. No-op on empty list."""
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute(
                f"DELETE FROM events WHERE id IN ({placeholders})",
                tuple(ids),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def trim_to_cap(self, cap: int = 10_000) -> int:
        """Drop the oldest rows so total <= cap. Returns rows deleted."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            count = int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            excess = count - cap
            if excess <= 0:
                self.conn.execute("COMMIT")
                return 0
            # Atomic single-DELETE with subquery picking oldest `excess` ids.
            self.conn.execute(
                "DELETE FROM events WHERE id IN ("
                "  SELECT id FROM events ORDER BY id ASC LIMIT ?"
                ")",
                (excess,),
            )
            self.conn.execute("COMMIT")
            return excess
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
