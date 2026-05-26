"""Unit tests for ccguard.agent.findings_hook.buffer (PI-01, T-05-04-01..02).

Mirrors :mod:`tests.unit.test_audit_buffer` style. The findings buffer is a
distinct SQLite DB and table — clone-not-extend per D-1 — so we re-verify
schema, WAL mode, masking, truncation and the kwargs-only API contract.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cc_home = tmp_path / ".ccguard"
    cc_home.mkdir()
    # The findings_hook respects CCGUARD_AGENT_HOME (existing project-wide
    # override used by ccguard.agent.config.default_config_dir).
    monkeypatch.setenv("CCGUARD_AGENT_HOME", str(cc_home))
    monkeypatch.setenv("HOME", str(tmp_path))
    return cc_home


def _reset_conn_cache() -> None:
    """Drop any cached sqlite3.Connection between tests with different HOMEs."""
    from ccguard.agent.findings_hook import buffer as buf_mod

    buf_mod._reset_for_tests()


@pytest.fixture(autouse=True)
def _reset_module_cache() -> None:
    _reset_conn_cache()
    yield
    _reset_conn_cache()


# --- Test 1: file creation + WAL mode ---------------------------------------


def test_emit_finding_creates_db_in_ccguard_home(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    db = _isolated_home / "findings_buffer.db"
    assert not db.exists()

    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="role-swap pattern matched",
        source="regex",
        matched_pattern="please act as system administrator",
        tool_name="Bash",
    )

    assert db.exists()


# --- Test 2: emit inserts exactly one row in findings_buffer ----------------


def test_emit_finding_inserts_one_row(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="role-swap pattern matched",
        source="regex",
        matched_pattern="suspicious text",
        tool_name="Bash",
    )

    db = _isolated_home / "findings_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        n = conn.execute("SELECT COUNT(*) FROM findings_buffer").fetchone()[0]
        assert n == 1
        row = conn.execute(
            "SELECT rule_id, severity, title, source, matched_pattern, tool_name, "
            "delivered, retry_count FROM findings_buffer"
        ).fetchone()
        assert row[0] == "prompt_injection.role_swap"
        assert row[1] == "warn"
        assert row[2] == "role-swap pattern matched"
        assert row[3] == "regex"
        assert row[4] == "suspicious text"
        assert row[5] == "Bash"
        assert row[6] == 0  # delivered default
        assert row[7] == 0  # retry_count default
    finally:
        conn.close()


# --- Test 3: emit_finding completes < 10 ms (hot-path budget) ---------------


def test_emit_finding_under_10ms(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    # Warm-up: first call pays connection + schema init cost. The hot-path
    # budget applies to steady-state emits, which is what the Phase 5 plan
    # 03 enforce.decide() integration will be making.
    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="warm",
        source="regex",
        matched_pattern="warm",
        tool_name="Bash",
    )

    start = time.perf_counter()
    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="hot",
        source="regex",
        matched_pattern="hot",
        tool_name="Bash",
    )
    elapsed = time.perf_counter() - start
    assert elapsed < 0.010, f"emit_finding took {elapsed * 1000:.2f} ms (>10 ms)"


# --- Test 4: mask_secrets() applied BEFORE persist (T-05-04-01) -------------


def test_emit_finding_masks_secrets_in_matched_pattern(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    secret = "sk-ant-api03-" + "A" * 40
    payload = f"prompt contains an API key {secret} embedded"

    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="leak",
        source="regex",
        matched_pattern=payload,
        tool_name="Bash",
    )

    db = _isolated_home / "findings_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        stored = conn.execute("SELECT matched_pattern FROM findings_buffer").fetchone()[0]
    finally:
        conn.close()
    assert secret not in stored
    assert "***MASKED***" in stored


# --- Test 5: matched_pattern truncated to 200 chars (T-05-04-02) ------------


def test_emit_finding_truncates_matched_pattern(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    long_value = "x" * 1000
    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="long",
        source="regex",
        matched_pattern=long_value,
        tool_name="Bash",
    )
    db = _isolated_home / "findings_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        stored = conn.execute("SELECT matched_pattern FROM findings_buffer").fetchone()[0]
    finally:
        conn.close()
    # mask_secrets() truncates to 200 and appends "...[truncated]". The exact
    # length is implementation-defined; the security contract is "<=216 chars".
    assert len(stored) <= 220
    assert stored.startswith("x" * 200)


# --- Test 6: schema init idempotent -----------------------------------------


def test_init_is_idempotent(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    for i in range(3):
        emit_finding(
            rule_id="prompt_injection.role_swap",
            severity="warn",
            title=f"row-{i}",
            source="regex",
            matched_pattern="x",
            tool_name="Bash",
        )
    db = _isolated_home / "findings_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM findings_buffer").fetchone()[0] == 3
    finally:
        conn.close()


# --- Test 7: WAL journal mode confirmed -------------------------------------


def test_wal_journal_mode(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="x",
        source="regex",
        matched_pattern="x",
        tool_name="Bash",
    )
    db = _isolated_home / "findings_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert str(mode).lower() == "wal"


# --- Test 8: full schema columns --------------------------------------------


def test_schema_columns_present(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="x",
        source="regex",
        matched_pattern="x",
        tool_name="Bash",
    )
    db = _isolated_home / "findings_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(findings_buffer)").fetchall()}
    finally:
        conn.close()
    assert cols >= {
        "id",
        "ts",
        "rule_id",
        "severity",
        "title",
        "source",
        "matched_pattern",
        "tool_name",
        "delivered",
        "retry_count",
    }


# --- Test 9: kwargs-only signature (defensive against shape drift) ----------


def test_emit_finding_rejects_positional_args(_isolated_home: Path) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    with pytest.raises(TypeError):
        emit_finding(  # type: ignore[misc]
            "prompt_injection.role_swap", "warn", "t", "regex", "x", "Bash"
        )


# --- Test 10: CCGUARD_AGENT_HOME override respected for test isolation ------


def test_ccguard_agent_home_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    other = tmp_path / "alt"
    other.mkdir()
    monkeypatch.setenv("CCGUARD_AGENT_HOME", str(other))
    # Reset cached connection so it picks up the new HOME.
    from ccguard.agent.findings_hook import buffer as buf_mod

    buf_mod._reset_for_tests()

    from ccguard.agent.findings_hook.buffer import emit_finding

    emit_finding(
        rule_id="prompt_injection.role_swap",
        severity="warn",
        title="x",
        source="regex",
        matched_pattern="x",
        tool_name="Bash",
    )

    assert (other / "findings_buffer.db").exists()
