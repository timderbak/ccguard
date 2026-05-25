"""hook_main.main_cli: stdin → fingerprint → buffer.insert → spawn flusher."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ccguard.agent.audit_hook import hook_main


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cc_home = tmp_path / ".ccguard"
    cc_home.mkdir()
    monkeypatch.setenv("CCGUARD_AGENT_HOME", str(cc_home))
    return cc_home


@pytest.fixture
def mock_spawn(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    m = MagicMock()
    monkeypatch.setattr(hook_main, "maybe_spawn_flusher", m)
    return m


def _buffer_rows(home: Path) -> list[tuple]:
    db = home / "audit_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        cur = conn.execute(
            "SELECT id, ts, tool_name, fingerprint, decision, result_status FROM events"
        )
        return cur.fetchall()
    finally:
        conn.close()


def test_happy_path_inserts_row_and_spawns_flusher(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    stdin = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "tool_response": {},
        }
    )
    rc = hook_main.main_cli(stdin)
    assert rc == 0
    rows = _buffer_rows(_isolated_home)
    assert len(rows) == 1
    _id, _ts, tool_name, fp, decision, result_status = rows[0]
    assert tool_name == "Bash"
    assert decision == "allow"
    assert result_status == "success"
    # 16-char lowercase hex
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)
    mock_spawn.assert_called_once()
    assert mock_spawn.call_args.kwargs["row_count_hint"] == 1


def test_decision_is_always_allow(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    stdin = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "tool_response": {"error": "blocked by something else"},
        }
    )
    hook_main.main_cli(stdin)
    rows = _buffer_rows(_isolated_home)
    assert rows[0][4] == "allow"  # decision column


def test_result_status_error_on_error_field(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    stdin = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"error": "boom"},
        }
    )
    hook_main.main_cli(stdin)
    rows = _buffer_rows(_isolated_home)
    assert rows[0][5] == "error"


def test_result_status_error_on_success_false(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    stdin = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"success": False},
        }
    )
    hook_main.main_cli(stdin)
    rows = _buffer_rows(_isolated_home)
    assert rows[0][5] == "error"


def test_result_status_blocked_on_interrupted(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    stdin = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"interrupted": True},
        }
    )
    hook_main.main_cli(stdin)
    rows = _buffer_rows(_isolated_home)
    assert rows[0][5] == "blocked"


def test_malformed_json_fails_open(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    rc = hook_main.main_cli("{not valid json")
    assert rc == 0
    db = _isolated_home / "audit_buffer.db"
    assert not db.exists() or _buffer_rows(_isolated_home) == []
    mock_spawn.assert_not_called()


def test_empty_stdin_fails_open(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    rc = hook_main.main_cli("")
    assert rc == 0


def test_missing_tool_name_uses_placeholder(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    stdin = json.dumps({"tool_input": {"x": 1}, "tool_response": {}})
    hook_main.main_cli(stdin)
    rows = _buffer_rows(_isolated_home)
    assert rows[0][2] == "(unknown)"


def test_top_level_non_dict_fails_open(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    rc = hook_main.main_cli(json.dumps([1, 2, 3]))
    assert rc == 0
    mock_spawn.assert_not_called()


def test_raw_tool_input_never_in_buffer(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    """Privacy invariant: original command string MUST NOT leak into any row cell."""
    secret = "git status --some-very-unique-flag-DEADBEEF"
    stdin = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": secret},
            "tool_response": {},
        }
    )
    hook_main.main_cli(stdin)
    # Read every cell of every row and concat — secret should not appear anywhere.
    db = _isolated_home / "audit_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        cur = conn.execute("SELECT * FROM events")
        for row in cur.fetchall():
            for cell in row:
                assert secret not in str(cell)
                assert "DEADBEEF" not in str(cell)
    finally:
        conn.close()


def test_execution_under_100ms(
    _isolated_home: Path, mock_spawn: MagicMock
) -> None:
    """Lenient wall-clock budget (real budget is <20ms; CI noise tolerance)."""
    stdin = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "tool_response": {},
        }
    )
    # Warm: first call creates DB schema.
    hook_main.main_cli(stdin)
    t0 = time.perf_counter()
    hook_main.main_cli(stdin)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < 100, f"hook took {elapsed_ms:.1f}ms (budget 100ms)"


def test_internal_exception_swallowed(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any unexpected exception inside the body must surface as return 0."""

    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("explode")

    monkeypatch.setattr(hook_main, "compute_fingerprint", boom)
    stdin = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {}}
    )
    assert hook_main.main_cli(stdin) == 0
