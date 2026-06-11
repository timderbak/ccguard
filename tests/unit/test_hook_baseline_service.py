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
        # keep the seeded hook in the sync so it is not flagged as removed (P7)
        _entry(matcher="Bash", command="seeded-cmd", file_path=None, file_hash=None),
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


# --- Task 7: content drift = block --------------------------------------------


def test_content_drift_emits_block_finding(session):
    """Same slot, file_content_hash changed → block-severity finding."""
    fp_old = compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "OLDHASH")
    seed = HookBaseline(
        machine_id="machine-A", event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/x.py", file_path="/opt/x.py",
        file_content_hash="OLDHASH", fingerprint=fp_old, status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id="machine-A", current_hooks=[
        _entry(file_hash="NEWHASH"),  # same slot, different file content
    ])
    session.commit()

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "hook.rug_pull.content"
    assert f.severity == "block"
    # Old hash + new hash both in payload so UI can show the diff.
    assert "OLDHASH" in f.payload_json and "NEWHASH" in f.payload_json
    # Row stays put (slot didn't move) but fingerprint refreshed to new value.
    row = session.exec(select(HookBaseline)).one()
    assert row.fingerprint == compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "NEWHASH")
    assert row.file_content_hash == "NEWHASH"
    assert row.status == "active"  # status doesn't auto-flip; finding alerts


# --- Task 8: command drift = warn ---------------------------------------------


def test_command_drift_emits_warn_finding(session):
    """Same event+matcher slot, command_string changed → warn finding (visible
    config change, less stealthy than content drift)."""
    fp_old = compute_fingerprint("PreToolUse", "Bash", "python /opt/old.py", "X")
    seed = HookBaseline(
        machine_id="machine-A", event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/old.py", file_path="/opt/old.py",
        file_content_hash="X", fingerprint=fp_old, status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id="machine-A", current_hooks=[
        _entry(command="python /opt/new.py", file_path="/opt/new.py", file_hash="X"),
    ])
    session.commit()

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "hook.rug_pull.command"
    assert f.severity == "warn"
    # We do NOT also emit hook.new — command drift supersedes.
    # And we DON'T leave an orphan row at the old command_string.
    rows = session.exec(select(HookBaseline)).all()
    assert len(rows) == 1
    assert rows[0].command_string == "python /opt/new.py"
    assert rows[0].status == "active"


# --- Task 9 / P7: removed ACTIVE hook = status=missing + hook.removed finding -


def test_removed_active_hook_marks_missing_and_emits_finding(session):
    """P7: an ACTIVE hook gone from this sync → status=missing AND a
    hook.removed finding (possible tamper / defense-evasion). A pending row
    going missing stays silent (covered in tests/unit/test_baseline_removal.py)."""
    seed = HookBaseline(
        machine_id="machine-A", event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/x.py", file_path="/opt/x.py",
        file_content_hash="X",
        fingerprint=compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "X"),
        status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id="machine-A", current_hooks=[])
    session.commit()

    assert [f.rule_id for f in findings] == ["hook.removed"]
    row = session.exec(select(HookBaseline)).one()
    assert row.status == "missing"


# --- Task 10: hook.unreadable warn (content_hash transition Some → None) ------


def test_file_became_unreadable_emits_warn(session):
    """If we had a content_hash and now we don't (permission denied / file
    moved), raise a hook.unreadable warn so admin sees they can't trust this
    hook's drift detection anymore."""
    seed = HookBaseline(
        machine_id="machine-A", event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/x.py", file_path="/opt/x.py",
        file_content_hash="HAD_HASH",
        fingerprint=compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "HAD_HASH"),
        status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    e = HookEntry(
        event="PreToolUse", matcher="Bash", type="command",
        command="python /opt/x.py", source="/root/.claude/settings.json",
        is_ccguard_owned=False, command_file_path="/opt/x.py",
        command_file_hash=None, file_unreadable_reason="permission_denied",
    )

    findings = update_and_detect(session, machine_id="machine-A", current_hooks=[e])
    session.commit()

    assert len(findings) == 1
    assert findings[0].rule_id == "hook.unreadable"
    assert findings[0].severity == "warn"
