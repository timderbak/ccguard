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


def _now_for_test() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


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


# --- update_and_detect: no-change path (Task 5) -------------------------------

from ccguard.schemas.inventory import HookEntry
from ccguard.server.services.hook_baseline_service import (
    compute_fingerprint,
    update_and_detect,
)


def _entry(event="PreToolUse", matcher="Bash", command="python /opt/x.py",
           file_path="/opt/x.py", file_hash="aaaa") -> HookEntry:
    return HookEntry(
        event=event,
        matcher=matcher,
        type="command",
        command=command,
        source="/root/.claude/settings.json",
        is_ccguard_owned=False,
        command_file_path=file_path,
        command_file_hash=file_hash,
        file_unreadable_reason=None,
    )


def test_update_and_detect_no_change_bumps_last_seen(session):
    e = _entry()
    # First call: creates row in pending.
    findings = update_and_detect(session, machine_id="machine-A", current_hooks=[e])
    session.commit()
    assert findings == []
    row = session.exec(select(HookBaseline)).one()
    first_seen = row.last_seen_at
    assert row.status == "pending"

    # Manually promote to active (simulating admin accept) so the next call
    # is in steady state.
    row.status = "active"
    session.add(row)
    session.commit()

    # Second call with the same entry — should NOT create a new row, should
    # NOT emit any finding, just bump last_seen_at.
    import time
    time.sleep(0.01)
    findings2 = update_and_detect(session, machine_id="machine-A", current_hooks=[e])
    session.commit()
    assert findings2 == []
    rows = session.exec(select(HookBaseline)).all()
    assert len(rows) == 1
    assert rows[0].last_seen_at > first_seen
    assert rows[0].status == "active"


# --- Task 6: bootstrap + post-bootstrap new-hook detection -------------------


def test_first_sync_creates_pending_no_findings(session):
    """Bootstrap: machine has no prior baseline → all hooks become pending,
    no hook.new findings (would drown user in noise on initial join)."""
    findings = update_and_detect(session, machine_id="machine-A", current_hooks=[
        _entry(matcher="Bash"),
        _entry(matcher="Write|Edit"),
    ])
    session.commit()

    assert findings == []
    rows = session.exec(select(HookBaseline)).all()
    assert len(rows) == 2
    assert all(r.status == "pending" for r in rows)


def test_post_bootstrap_new_hook_emits_warn_finding(session):
    """Once at least one baseline is active on this machine, every later new
    slot raises a warn-level hook.new finding."""
    # Seed: one active baseline already in place.
    seed = HookBaseline(
        machine_id="machine-A", event_name="PreToolUse", matcher="Bash",
        command_string="seeded-cmd", file_path=None, file_content_hash=None,
        fingerprint=compute_fingerprint("PreToolUse", "Bash", "seeded-cmd", None),
        status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id="machine-A", current_hooks=[
        _entry(matcher="Write"),  # new slot
    ])
    session.commit()

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "hook.new"
    assert f.severity == "warn"
    new_row = session.exec(
        select(HookBaseline).where(HookBaseline.matcher == "Write")
    ).one()
    assert new_row.status == "pending"  # still pending until admin clicks accept
