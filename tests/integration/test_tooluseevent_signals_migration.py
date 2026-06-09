"""Regression: init_db must add ``signals_json`` to a pre-ТЗ-09 tooluseevent.

A DB whose ``tooluseevent`` table was created before the chain-engine signal
tags (ТЗ-09) lacks the ``signals_json`` column. ``create_all`` is a no-op on
existing tables, so without an explicit additive ALTER every query that selects
the full ToolUseEvent model (e.g. the /audit page's ``list_events``) raises
``OperationalError: no such column: tooluseevent.signals_json`` → the audit page
500s. This test pins the heal.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlmodel import Session, select

from ccguard.server.db.models import ToolUseEvent
from ccguard.server.db.session import init_db, make_engine

pytestmark = pytest.mark.integration


def test_init_db_heals_legacy_tooluseevent_without_signals_json(tmp_path) -> None:
    engine = make_engine(f"sqlite:///{tmp_path}/legacy.db")
    # Simulate a pre-feature schema: tooluseevent missing the additive columns
    # signals_json (ТЗ-09) AND actor_user (per-user attribution).
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE tooluseevent ("
                "id INTEGER PRIMARY KEY, machine_id VARCHAR NOT NULL, ts TIMESTAMP, "
                "received_at TIMESTAMP, tool_name VARCHAR, fingerprint VARCHAR, "
                "decision VARCHAR, result_status VARCHAR)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO tooluseevent (machine_id, tool_name, decision) "
                "VALUES ('m1', 'Bash', 'allow')"
            )
        )

    # init_db must add the columns (additive ALTERs), not crash.
    init_db(engine)

    with engine.connect() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(tooluseevent)"))}
    assert "signals_json" in cols
    assert "actor_user" in cols

    # The exact query that used to 500 the audit page must now run, and the
    # legacy row must be backfilled with the NOT NULL default.
    with Session(engine) as s:
        rows = s.exec(select(ToolUseEvent)).all()
    assert len(rows) == 1
    assert rows[0].signals_json == "[]"
