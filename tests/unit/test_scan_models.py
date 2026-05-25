"""Unit tests for Plan 03-01 Task 2: ScanResult, LLMCallLog, SettingsRecord seeding.

Covers:
- ScanResult UPSERT by ``file_hash`` is idempotent (count stays 1, latest value wins).
- LLMCallLog rows insert + query by ts range with composite (ts, model) index usable.
- ``seed_llm_settings`` creates ``llm_scanner_enabled`` and ``daily_call_budget``
  exactly once across repeated startup invocations.
- ``seed_llm_settings`` does NOT overwrite admin-modified values on subsequent startup.
- Tables registered with ``create_all`` (importable + create_all yields tables).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import inspect
from sqlmodel import Session, select

from ccguard.server.db.models import (
    LLMCallLog,
    ScanResult,
    SettingsRecord,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.settings_service import (
    get_setting,
    seed_llm_settings,
    set_setting,
)


@pytest.fixture
def engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


# ---- create_all registration ----------------------------------------------


def test_scan_result_and_llm_call_log_tables_registered(engine) -> None:
    insp = inspect(engine)
    names = set(insp.get_table_names())
    assert "scanresult" in names, names
    assert "llmcalllog" in names, names
    assert "settingsrecord" in names, names


def test_scan_result_file_hash_is_unique(engine) -> None:
    insp = inspect(engine)
    unique_cols: set[str] = set()
    for uq in insp.get_unique_constraints("scanresult"):
        unique_cols.update(uq["column_names"])
    # SQLModel ``Field(unique=True)`` may render via either a UNIQUE constraint
    # or a UNIQUE index — accept both.
    if "file_hash" not in unique_cols:
        for idx in insp.get_indexes("scanresult"):
            if idx.get("unique") and "file_hash" in idx["column_names"]:
                unique_cols.add("file_hash")
                break
    assert "file_hash" in unique_cols


# ---- ScanResult UPSERT idempotency ----------------------------------------


def _make_scan(file_hash: str, *, risk: int, rationale: str) -> ScanResult:
    return ScanResult(
        file_hash=file_hash,
        file_path="/home/u/.claude/agents/example.md",
        scope="agent",
        risk_score=risk,
        category="benign",
        rationale=rationale,
        scanned_at=datetime.now(UTC),
        model="claude-haiku-4-5",
        ttl_expires_at=datetime.now(UTC) + timedelta(days=14),
    )


def test_scan_result_upsert_by_file_hash_is_idempotent(engine) -> None:
    with Session(engine) as s:
        first = _make_scan("h0", risk=10, rationale="first")
        s.add(first)
        s.commit()
        first_id = first.id
        assert first_id is not None

        # Second write with same file_hash — emulate upsert by id-lookup then merge.
        existing = s.exec(select(ScanResult).where(ScanResult.file_hash == "h0")).one()
        existing.risk_score = 75
        existing.rationale = "second"
        s.add(existing)
        s.commit()

        rows = s.exec(select(ScanResult).where(ScanResult.file_hash == "h0")).all()
        assert len(rows) == 1
        assert rows[0].id == first_id
        assert rows[0].risk_score == 75
        assert rows[0].rationale == "second"


def test_scan_result_duplicate_insert_violates_unique(engine) -> None:
    from sqlalchemy.exc import IntegrityError

    with Session(engine) as s:
        s.add(_make_scan("h-dup", risk=1, rationale="a"))
        s.commit()

    with Session(engine) as s2:
        s2.add(_make_scan("h-dup", risk=2, rationale="b"))
        with pytest.raises(IntegrityError):
            s2.commit()


# ---- LLMCallLog insert + query --------------------------------------------


def test_llm_call_log_insert_and_query_by_ts_range(engine) -> None:
    base = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)
    with Session(engine) as s:
        for i in range(5):
            s.add(
                LLMCallLog(
                    ts=base + timedelta(minutes=i),
                    file_hash=f"h{i}",
                    model="claude-haiku-4-5",
                    input_tokens=100 + i,
                    output_tokens=20 + i,
                    cost_estimate_cents=1,
                )
            )
        s.commit()

        # Query window covers entries i=1..3.
        lo = base + timedelta(minutes=1)
        hi = base + timedelta(minutes=3)
        rows = s.exec(
            select(LLMCallLog).where(LLMCallLog.ts >= lo, LLMCallLog.ts <= hi)
        ).all()
        assert len(rows) == 3
        assert {r.file_hash for r in rows} == {"h1", "h2", "h3"}


# ---- seed_llm_settings ----------------------------------------------------


def test_seed_llm_settings_creates_both_keys_once(engine) -> None:
    with Session(engine) as s:
        seed_llm_settings(s)
        seed_llm_settings(s)  # idempotent
        seed_llm_settings(s)
        rows = s.exec(
            select(SettingsRecord).where(
                SettingsRecord.key.in_(["llm_scanner_enabled", "daily_call_budget"])
            )
        ).all()
        assert len(rows) == 2
        kv = {r.key: r.value for r in rows}
        assert kv == {"llm_scanner_enabled": "false", "daily_call_budget": "100"}


def test_seed_llm_settings_does_not_overwrite_admin_edit(engine) -> None:
    with Session(engine) as s:
        seed_llm_settings(s)
        # Admin tunes the budget.
        set_setting(s, "daily_call_budget", "200")
        # Server restart re-seeds — must preserve admin value.
        seed_llm_settings(s)
        assert get_setting(s, "daily_call_budget") == "200"
        # Other key remains untouched.
        assert get_setting(s, "llm_scanner_enabled") == "false"


def test_get_setting_returns_none_for_missing_key(engine) -> None:
    with Session(engine) as s:
        assert get_setting(s, "nonexistent_key") is None
