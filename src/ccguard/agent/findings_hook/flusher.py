"""Detached subprocess flusher for findings_buffer (PI-01).

Reads undelivered rows from ``~/.ccguard/findings_buffer.db``, POSTs them in
batches to ``/api/v1/findings`` and marks them delivered. Clone-not-extend of
:mod:`ccguard.agent.audit_hook.flusher` per Phase 5 D-1, but with two
important differences from the audit pipeline:

* **In-place marking** (``delivered=1``) rather than ``DELETE``. The findings
  buffer doubles as a local audit trail of what the agent emitted — useful for
  debugging false positives — and is cheap to rotate via ``trim`` later.
* **DLQ-style guard** (T-05-04-03): a row whose ``retry_count`` reaches 3 gets
  ``delivered=1`` even though it never got a 2xx. This breaks retry loops on
  payloads the server permanently rejects (e.g. 400) so a single bad row can
  never wedge the queue.

Trigger: agent code calls ``flush()`` directly (oneshot via
``flusher_main.main``), or the future scheduler invokes
``python -m ccguard.agent.findings_hook.flusher_main``.
"""

from __future__ import annotations

import json
import time
from typing import Final

import httpx

from ccguard.agent.config import default_config_dir, load_or_create

_BATCH_SIZE: Final[int] = 100
_MAX_ATTEMPTS: Final[int] = 3  # network/5xx retries per flush() call
_BACKOFF_SECONDS: Final[tuple[int, ...]] = (1, 2)
_DLQ_THRESHOLD: Final[int] = 3  # retry_count >= DLQ_THRESHOLD → mark delivered
_HTTP_TIMEOUT_S: Final[float] = 10.0


def _buffer_path():  # type: ignore[no-untyped-def]
    return default_config_dir() / "findings_buffer.db"


def _open_conn():  # type: ignore[no-untyped-def]
    import sqlite3

    path = _buffer_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    # Schema may not exist yet if flush() is called before any emit_finding;
    # mirror the same CREATE IF NOT EXISTS as buffer.py.
    conn.executescript(
        """
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
    )
    return conn


def _read_undelivered(conn, limit: int) -> list[dict]:  # type: ignore[no-untyped-def]
    cur = conn.execute(
        "SELECT id, ts, rule_id, severity, title, source, matched_pattern, "
        "tool_name, retry_count "
        "FROM findings_buffer WHERE delivered = 0 ORDER BY id ASC LIMIT ?",
        (limit,),
    )
    rows = []
    for r in cur.fetchall():
        rows.append(
            {
                "id": int(r[0]),
                "ts": str(r[1]),
                "rule_id": str(r[2]),
                "severity": str(r[3]),
                "title": str(r[4]),
                "source": str(r[5]),
                "matched_pattern": str(r[6]),
                "tool_name": str(r[7]),
                "retry_count": int(r[8]),
            }
        )
    return rows


def _mark_delivered(conn, ids: list[int]) -> None:  # type: ignore[no-untyped-def]
    if not ids:
        return
    placeholders = ",".join("?" for _ in ids)
    conn.execute(
        f"UPDATE findings_buffer SET delivered = 1 WHERE id IN ({placeholders})",
        tuple(ids),
    )


def _bump_retry(
    conn,  # type: ignore[no-untyped-def]
    ids: list[int],
    status: int | None = None,
) -> None:
    """Bump retry_count and DLQ-mark on a permanent rejection.

    WR-02: discriminate 4xx (permanent — server rejected payload, no retry
    can recover) from 5xx / network failures (transient — bump and retry
    on the next flush()):

    * ``status`` in [400, 500): the server validated the request and
      refused it. Retrying the same bytes is futile, so DLQ-mark
      immediately by setting ``delivered=1`` AND bumping ``retry_count``
      (the bump preserves the local-buffer accounting so trim/audit can
      tell the row was rejected, not delivered).
    * ``status`` is None (network exception) or in [500, 600): bump
      ``retry_count``; let the row stay in the buffer for the next
      flush(). The DLQ threshold catches repeated 5xx so a permanently
      degraded server cannot wedge the queue.
    """
    if not ids:
        return
    placeholders = ",".join("?" for _ in ids)
    conn.execute(
        f"UPDATE findings_buffer SET retry_count = retry_count + 1 "
        f"WHERE id IN ({placeholders})",
        tuple(ids),
    )
    # 4xx → DLQ immediately (no point retrying a permanent rejection).
    if status is not None and 400 <= status < 500:
        conn.execute(
            f"UPDATE findings_buffer SET delivered = 1 "
            f"WHERE id IN ({placeholders})",
            tuple(ids),
        )
        return
    # 5xx / network: bump-and-retry, with DLQ-threshold safety net.
    conn.execute(
        f"UPDATE findings_buffer SET delivered = 1 "
        f"WHERE id IN ({placeholders}) AND retry_count >= ?",
        (*ids, _DLQ_THRESHOLD),
    )


def flush() -> None:
    """Drain undelivered findings → POST batches → mark delivered.

    Best-effort: any persistent failure leaves rows undelivered with bumped
    ``retry_count``; subsequent ``flush()`` calls retry until the DLQ
    threshold breaks the loop.
    """
    cfg, _ = load_or_create()
    server_url = cfg.server.url.rstrip("/")
    token = cfg.server.token
    url = f"{server_url}/api/v1/findings"
    headers = {
        "X-CCGuard-Token": token,
        "Content-Type": "application/json",
    }

    conn = _open_conn()
    try:
        # Resolve machine_id once per flush. derive_machine_id is the same util
        # the audit flusher uses; falling back to "unknown" lets us continue
        # even if the install_salt is missing (test path stubs this out).
        try:
            from ccguard.agent.machine_id import derive_machine_id

            machine_id = derive_machine_id(cfg.install_salt)
        except Exception:
            machine_id = "unknown"

        while True:
            rows = _read_undelivered(conn, limit=_BATCH_SIZE)
            if not rows:
                return

            wire_rows = [
                {
                    "ts": r["ts"],
                    "rule_id": r["rule_id"],
                    "severity": r["severity"],
                    "title": r["title"],
                    "source": r["source"],
                    "matched_pattern": r["matched_pattern"],
                    "tool_name": r["tool_name"],
                }
                for r in rows
            ]
            envelope = {
                "schema_version": "1",
                "machine_id": machine_id,
                "findings": wire_rows,
            }
            body_bytes = json.dumps(envelope).encode("utf-8")

            ok, status = _post_with_retry(url, headers, body_bytes)

            ids = [r["id"] for r in rows]
            if ok:
                _mark_delivered(conn, ids)
                # Next loop iteration will try to read more undelivered rows.
                continue

            # Failure path: bump retry_count for this batch. WR-02: pass
            # the HTTP status so _bump_retry can DLQ 4xx immediately while
            # letting 5xx/network failures retry until the DLQ threshold.
            _bump_retry(conn, ids, status=status)
            # Stop after first failure — do NOT keep posting other batches on
            # a likely-degraded path. The next flush() call retries.
            return
    finally:
        conn.close()


def _post_with_retry(
    url: str, headers: dict, body_bytes: bytes
) -> tuple[bool, int | None]:
    """Inline retry helper that posts pre-serialized bytes.

    Split out so ``flush()`` can construct the envelope once and reuse it
    across attempts without re-serializing. Mirrors _post_batch contract.
    """
    last_status: int | None = None
    for attempt in range(_MAX_ATTEMPTS):
        if attempt > 0:
            time.sleep(_BACKOFF_SECONDS[attempt - 1])
        try:
            with httpx.Client(timeout=_HTTP_TIMEOUT_S) as client:
                resp = client.post(url, content=body_bytes, headers=headers)
            last_status = resp.status_code
            if 200 <= resp.status_code < 300:
                return True, resp.status_code
        except Exception:
            last_status = None
            continue
    return False, last_status
