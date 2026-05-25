"""Unit tests for ccguard.agent.audit_hook.buffer (TUA-01, T-01-02, T-01-03)."""

from __future__ import annotations

import multiprocessing as mp
import sqlite3
from pathlib import Path

import pytest

from ccguard.agent.audit_hook.buffer import ToolBufferDB
from tests.conftest import multiprocessing_buffer_worker


def _insert(buf: ToolBufferDB, i: int = 0) -> None:
    buf.insert(
        ts=f"2026-05-25T12:00:{i % 60:02d}Z",
        tool_name="Bash",
        fingerprint="0123456789abcdef",
        decision="allow",
        result_status="success",
    )


# --- Schema init + parent dir creation --------------------------------------


def test_creates_parent_dirs(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c" / "audit.db"
    assert not nested.parent.exists()
    with ToolBufferDB(nested) as buf:
        _insert(buf)
        assert buf.row_count() == 1
    assert nested.exists()


def test_schema_creates_events_table(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path):
        pass
    conn = sqlite3.connect(str(audit_buffer_path))
    try:
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "events" in names
        idx = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert "idx_events_id" in idx
    finally:
        conn.close()


def test_pragmas_set_on_connect(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        jm = buf.conn.execute("PRAGMA journal_mode").fetchone()[0]
        sync = buf.conn.execute("PRAGMA synchronous").fetchone()[0]
        bt = buf.conn.execute("PRAGMA busy_timeout").fetchone()[0]
    assert str(jm).lower() == "wal"
    # synchronous=NORMAL is value 1.
    assert int(sync) == 1
    assert int(bt) == 5000


# --- Insert + row_count -----------------------------------------------------


def test_insert_increments_row_count(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        _insert(buf, 1)
        assert buf.row_count() == 1
        _insert(buf, 2)
        assert buf.row_count() == 2


# --- WAL persistence across reopen ------------------------------------------


def test_reopen_preserves_rows(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        for i in range(5):
            _insert(buf, i)
        assert buf.row_count() == 5
    # Reopen.
    with ToolBufferDB(audit_buffer_path) as buf:
        assert buf.row_count() == 5


# --- drain ------------------------------------------------------------------


def test_drain_returns_oldest_first_and_does_not_delete(
    audit_buffer_path: Path,
) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        for i in range(10):
            buf.insert(
                ts=f"2026-05-25T00:00:{i:02d}Z",
                tool_name="Bash",
                fingerprint=f"fp{i:014x}",
                decision="allow",
                result_status="success",
            )
        rows = buf.drain(limit=5)
        assert len(rows) == 5
        # id ASC ordering preserved.
        assert [r["id"] for r in rows] == sorted(r["id"] for r in rows)
        assert rows[0]["ts"].endswith(":00Z")
        # drain does not mutate.
        assert buf.row_count() == 10


def test_drain_limit_caps_result(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        for i in range(3):
            _insert(buf, i)
        assert len(buf.drain(limit=50)) == 3


def test_drain_returns_typed_dict_shape(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        _insert(buf)
        [row] = buf.drain()
        assert set(row.keys()) == {
            "id",
            "ts",
            "tool_name",
            "fingerprint",
            "decision",
            "result_status",
        }


# --- delete_ids -------------------------------------------------------------


def test_delete_ids_removes_only_those_ids(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        for i in range(5):
            _insert(buf, i)
        ids = [r["id"] for r in buf.drain()]
        # Delete the first two.
        buf.delete_ids(ids[:2])
        assert buf.row_count() == 3
        remaining_ids = {r["id"] for r in buf.drain()}
        assert remaining_ids == set(ids[2:])


def test_delete_ids_empty_is_noop(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        _insert(buf)
        buf.delete_ids([])
        assert buf.row_count() == 1


# --- trim_to_cap ------------------------------------------------------------


def test_trim_to_cap_drops_oldest(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        for i in range(150):
            _insert(buf, i)
        deleted = buf.trim_to_cap(cap=100)
        assert deleted == 50
        assert buf.row_count() == 100
        # Surviving rows are the *newest* 100 (highest ids).
        surviving = buf.drain(limit=200)
        ids = sorted(r["id"] for r in surviving)
        # Oldest survivor id is 51 (we inserted 150 rows with ids 1..150,
        # 50 oldest dropped → 51..150 remain).
        assert ids[0] == 51
        assert ids[-1] == 150


def test_trim_to_cap_noop_when_under_cap(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        for i in range(5):
            _insert(buf, i)
        assert buf.trim_to_cap(cap=10_000) == 0
        assert buf.row_count() == 5


def test_trim_to_cap_empty_table(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        assert buf.trim_to_cap(cap=100) == 0
        assert buf.row_count() == 0


# --- Robust parameter binding (NUL byte in tool_name) -----------------------


def test_nul_in_tool_name_does_not_crash(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        buf.insert(
            ts="2026-05-25T00:00:00Z",
            tool_name="Bash\x00weird",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
        )
        assert buf.row_count() == 1


# --- Concurrency: 5 processes × 20 inserts (T-01-02 mitigation test) -------


def test_concurrent_writers_preserve_all_rows(audit_buffer_path: Path) -> None:
    # Initialize the schema once from the parent so workers don't race on DDL.
    with ToolBufferDB(audit_buffer_path):
        pass

    ctx = mp.get_context("spawn")
    with ctx.Pool(processes=5) as pool:
        results = pool.starmap(
            multiprocessing_buffer_worker,
            [(str(audit_buffer_path), 20) for _ in range(5)],
        )

    # Each worker reports its own success count.
    assert sum(results) == 100, f"per-worker success counts: {results}"

    # Final on-disk row count must equal 5 × 20 = 100 exactly.
    with ToolBufferDB(audit_buffer_path) as buf:
        assert buf.row_count() == 100


# --- Rollback on insert failure --------------------------------------------


def test_insert_rolls_back_on_error(audit_buffer_path: Path) -> None:
    with ToolBufferDB(audit_buffer_path) as buf:
        _insert(buf, 0)
        # Force a constraint failure by binding wrong arity through low-level
        # call. We do this by monkey-patching `conn.execute` to fail on the
        # INSERT, then asserting state is consistent afterwards.
        with pytest.raises(Exception):  # noqa: B017
            buf.insert(
                ts=None,  # type: ignore[arg-type]
                tool_name="Bash",
                fingerprint="0123456789abcdef",
                decision="allow",
                result_status="success",
            )
        # Row count should be 1 (the first insert) — no partial state.
        assert buf.row_count() == 1
