"""accept_baseline / accept_all_pending / reject_and_mark."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, create_engine, select

from ccguard.server.db.models import HookBaseline
from ccguard.server.db.session import init_db
from ccguard.server.services.hook_baseline_service import (
    accept_baseline,
    accept_all_pending,
    reject_and_mark,
    compute_fingerprint,
)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite://", echo=False, connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as s:
        yield s


def _row(session, status="pending", command="cmd", machine_id="machine-A"):
    r = HookBaseline(
        machine_id=machine_id, event_name="PreToolUse", matcher="Bash",
        command_string=command, file_path=None, file_content_hash=None,
        fingerprint=compute_fingerprint("PreToolUse", "Bash", command, None),
        status=status, first_seen_at=_now(), last_seen_at=_now(),
    )
    session.add(r); session.commit(); session.refresh(r)
    return r


def test_accept_baseline_pending_to_active(session):
    r = _row(session, status="pending")
    accept_baseline(session, machine_id="machine-A", baseline_id=r.id, accepting_user="admin")
    session.commit()
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "active"
    assert fresh.accepted_by == "admin"
    assert fresh.accepted_at is not None


def test_accept_baseline_accepted_drift_to_active(session):
    """Re-accept after drift returns row to active and clears the drift flag."""
    r = _row(session, status="accepted_drift")
    accept_baseline(session, machine_id="machine-A", baseline_id=r.id, accepting_user="admin")
    session.commit()
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "active"


def test_accept_baseline_wrong_machine_raises(session):
    r = _row(session, status="pending")
    with pytest.raises(LookupError):
        accept_baseline(session, machine_id="other-machine", baseline_id=r.id, accepting_user="admin")


def test_accept_all_pending_promotes_only_pending(session):
    _row(session, status="pending", command="cmd1")
    _row(session, status="pending", command="cmd2")
    _row(session, status="active", command="cmd3")
    _row(session, status="missing", command="cmd4")

    promoted = accept_all_pending(session, machine_id="machine-A", accepting_user="admin")
    session.commit()

    assert promoted == 2
    rows = {r.command_string: r for r in session.exec(select(HookBaseline)).all()}
    assert rows["cmd1"].status == "active" and rows["cmd1"].accepted_by == "admin"
    assert rows["cmd2"].status == "active"
    assert rows["cmd3"].status == "active"  # unchanged
    assert rows["cmd4"].status == "missing"  # unchanged


def test_accept_all_pending_scoped_to_machine(session):
    _row(session, status="pending", command="other-cmd", machine_id="machine-B")
    _row(session, status="pending", command="my-cmd", machine_id="machine-A")

    promoted = accept_all_pending(session, machine_id="machine-A", accepting_user="admin")
    session.commit()

    assert promoted == 1
    rows = {r.command_string: r for r in session.exec(select(HookBaseline)).all()}
    assert rows["my-cmd"].status == "active"
    assert rows["other-cmd"].status == "pending"


def test_reject_and_mark_sets_status_removed(session):
    r = _row(session, status="pending")
    reject_and_mark(session, machine_id="machine-A", baseline_id=r.id)
    session.commit()
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "removed"


def test_reject_and_mark_wrong_machine_raises(session):
    r = _row(session, status="pending")
    with pytest.raises(LookupError):
        reject_and_mark(session, machine_id="other-machine", baseline_id=r.id)
