"""Local SQLite WAL buffer for prompt-injection findings (PI-01).

Backs ``~/.ccguard/findings_buffer.db``. Clone-not-extend of the audit_hook
buffer per Phase 5 D-1: a distinct DB file + table keeps the audit and findings
flush pipelines independently testable, deployable, and rotatable.

Hot-path contract (Phase 5 plan 03 enforce.decide() integration):

* ``emit_finding`` MUST return in under 10 ms — the PreToolUse shim has a 100 ms
  total budget and the prompt-injection regex scan consumes most of it.
* ``mask_secrets`` is applied to ``matched_pattern`` BEFORE persist (T-05-04-01)
  so the local DB never holds plaintext API keys / JWTs that the scanner picked
  up incidentally. ``mask_secrets`` also enforces the 200-char truncation
  (T-05-04-02), so this module relies on the existing util rather than
  re-implementing length capping.

Concurrency: cached module-level connection in WAL mode with busy_timeout=5000.
Concurrent PreToolUse hooks on the same machine are rare (a single Claude Code
session is single-threaded at the agent level), but WAL keeps readers
non-blocking with the flusher subprocess.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from ccguard.agent.config import default_config_dir
from ccguard.agent.masking import mask_secrets

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings_buffer (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    matched_pattern TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_buffer_undelivered
    ON findings_buffer(delivered) WHERE delivered = 0;
"""

_conn_lock = threading.Lock()
_cached_conn: sqlite3.Connection | None = None
_cached_path: Path | None = None


def _buffer_path() -> Path:
    return default_config_dir() / "findings_buffer.db"


def _get_conn() -> sqlite3.Connection:
    """Return a cached sqlite3.Connection in WAL mode.

    The connection is initialized lazily on first emit so the import cost of
    this module stays near zero on the PreToolUse hot path.
    """
    global _cached_conn, _cached_path

    target = _buffer_path()
    with _conn_lock:
        if _cached_conn is not None and _cached_path == target:
            return _cached_conn

        # HOME changed (test isolation, agent reconfig). Close the old conn.
        if _cached_conn is not None:
            try:
                _cached_conn.close()
            except sqlite3.Error:
                pass

        target.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(target), timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        # DDL is idempotent; cheap and safe to run on every cold start because
        # _get_conn is only called once per process.
        conn.executescript(_SCHEMA)
        _cached_conn = conn
        _cached_path = target
        return conn


def emit_finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    source: str,
    matched_pattern: str,
    tool_name: str,
) -> None:
    """Append a finding row to the local WAL buffer.

    Keyword-only signature is intentional (test 9): the call shape will evolve
    across Phase 5 plans (LlamaGuard scores added in plan 06, classifier
    metadata in plan 07). Positional binding would silently bind new args to
    wrong columns; kwargs force every call site to migrate explicitly.

    Security contract:
      * ``matched_pattern`` is passed through :func:`mask_secrets` so plaintext
        API-key shapes (sk-..., AKIA..., JWT triples, etc.) are replaced with
        ``***MASKED***`` before they touch disk (T-05-04-01).
      * :func:`mask_secrets` also caps the resulting string at 200 chars
        (T-05-04-02) so a runaway scanner can't bloat the buffer DB.
    """
    masked = mask_secrets(matched_pattern) or ""
    ts = datetime.now(UTC).isoformat()
    conn = _get_conn()
    # Single-statement INSERT under autocommit (isolation_level=None) — the
    # narrowest possible lock-hold for the hot path.
    conn.execute(
        "INSERT INTO findings_buffer "
        "(ts, rule_id, severity, title, source, matched_pattern, tool_name) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, rule_id, severity, title, source, masked, tool_name),
    )


def _reset_for_tests() -> None:
    """Drop the cached connection. Test-only — never call from agent code."""
    global _cached_conn, _cached_path
    with _conn_lock:
        if _cached_conn is not None:
            try:
                _cached_conn.close()
            except sqlite3.Error:
                pass
        _cached_conn = None
        _cached_path = None
