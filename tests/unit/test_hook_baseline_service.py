"""HookBaseline model + DDL + fingerprint smoke tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, create_engine, select

from ccguard.server.db.models import HookBaseline
from ccguard.server.db.session import init_db


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite://", echo=False, connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as s:
        yield s


def test_hook_baseline_row_round_trip(session):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row = HookBaseline(
        machine_id="machine-A",
        event_name="PreToolUse",
        matcher="Bash",
        command_string="python /opt/script.py",
        file_path="/opt/script.py",
        file_content_hash="aaaa",
        fingerprint="ffff",
        status="pending",
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(row)
    session.commit()
    got = session.exec(select(HookBaseline)).one()
    assert got.machine_id == "machine-A"
    assert got.status == "pending"
    assert got.fingerprint == "ffff"
