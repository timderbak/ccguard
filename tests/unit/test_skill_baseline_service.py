"""Unit tests for skill_baseline_service: bootstrap, new, drift, removal, accept."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlmodel import Session, create_engine, select

from ccguard.schemas import SkillEntry
from ccguard.server.db.models import FindingRecord, SkillBaseline
from ccguard.server.db.session import init_db
from ccguard.server.services.skill_baseline_service import (
    accept_all_pending,
    accept_baseline,
    compute_fingerprint,
    reject_and_mark,
    update_and_detect,
)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite://", echo=False, connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as s:
        yield s


def _skill(
    name: str = "demo",
    dir_hash: str = "AAA",
    origin: str = "local",
    parent_plugin: str | None = None,
    source_marketplace: str | None = None,
    has_scripts: bool = False,
) -> SkillEntry:
    return SkillEntry(
        name=name,
        path=f"/tmp/skills/{name}",
        origin=origin,  # type: ignore[arg-type]
        dir_hash=dir_hash,
        has_referenced_scripts=has_scripts,
        parent_plugin=parent_plugin,
        source_marketplace=source_marketplace,
    )


def test_fingerprint_changes_with_dir_hash():
    a = compute_fingerprint("s", "local", None, "AAA")
    b = compute_fingerprint("s", "local", None, "BBB")
    assert a != b


def test_fingerprint_local_vs_plugin_with_same_name_differ():
    a = compute_fingerprint("s", "local", None, "X")
    b = compute_fingerprint("s", "plugin", "myplug", "X")
    assert a != b


def test_first_sync_bootstrap_is_silent(session):
    findings = update_and_detect(session, "m-1", [_skill()])
    session.commit()
    rows = session.exec(select(SkillBaseline)).all()
    assert len(rows) == 1
    assert rows[0].status == "pending"
    assert findings == []


def test_new_skill_after_bootstrap_emits_warn(session):
    # Bootstrap one and promote to active.
    update_and_detect(session, "m-2", [_skill(name="s1")])
    row = session.exec(select(SkillBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    # Now a new slot appears.
    findings = update_and_detect(session, "m-2", [_skill(name="s1"), _skill(name="s2-new")])
    session.commit()
    assert len(findings) == 1
    assert findings[0].rule_id == "skill.new"
    assert findings[0].severity == "warn"


def test_content_drift_with_scripts_emits_block(session):
    update_and_detect(session, "m-3", [_skill(name="x", dir_hash="A", has_scripts=True)])
    row = session.exec(select(SkillBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    findings = update_and_detect(
        session, "m-3", [_skill(name="x", dir_hash="B", has_scripts=True)]
    )
    session.commit()
    block_findings = [f for f in findings if f.rule_id == "skill.rug_pull.content"]
    assert len(block_findings) == 1
    assert block_findings[0].severity == "block"
    payload = json.loads(block_findings[0].payload_json)
    assert payload["old_dir_hash"] == "A"
    assert payload["new_dir_hash"] == "B"


def test_content_drift_text_only_emits_warn(session):
    update_and_detect(session, "m-4", [_skill(name="x", dir_hash="A", has_scripts=False)])
    row = session.exec(select(SkillBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    findings = update_and_detect(
        session, "m-4", [_skill(name="x", dir_hash="B", has_scripts=False)]
    )
    session.commit()
    text_findings = [f for f in findings if f.rule_id == "skill.drift.text"]
    assert len(text_findings) == 1
    assert text_findings[0].severity == "warn"


def test_removed_skill_marked_missing(session):
    update_and_detect(session, "m-5", [_skill(name="x")])
    row = session.exec(select(SkillBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    update_and_detect(session, "m-5", [])  # x исчез
    session.commit()
    fresh = session.exec(select(SkillBaseline)).one()
    assert fresh.status == "missing"


def test_same_name_local_vs_plugin_are_separate_slots(session):
    """Skill `foo` локально и `foo` из плагина — два разных baseline'а."""
    skills = [
        _skill(name="foo", origin="local"),
        _skill(name="foo", origin="plugin", parent_plugin="myplug",
               source_marketplace="mm"),
    ]
    update_and_detect(session, "m-6", skills)
    session.commit()
    rows = session.exec(select(SkillBaseline)).all()
    assert len(rows) == 2


def test_accept_baseline_promotes_to_active(session):
    update_and_detect(session, "m-7", [_skill()])
    session.commit()
    row = session.exec(select(SkillBaseline)).one()
    accept_baseline(session, "m-7", row.id, "admin")
    session.commit()
    fresh = session.exec(select(SkillBaseline)).one()
    assert fresh.status == "active"
    assert fresh.accepted_by == "admin"


def test_accept_all_pending_bulk_promotes(session):
    update_and_detect(session, "m-8", [_skill(name="a"), _skill(name="b")])
    session.commit()
    n = accept_all_pending(session, "m-8", "admin")
    session.commit()
    assert n == 2
    rows = session.exec(select(SkillBaseline)).all()
    assert all(r.status == "active" for r in rows)


def test_reject_marks_removed(session):
    update_and_detect(session, "m-9", [_skill()])
    session.commit()
    row = session.exec(select(SkillBaseline)).one()
    reject_and_mark(session, "m-9", row.id)
    session.commit()
    fresh = session.exec(select(SkillBaseline)).one()
    assert fresh.status == "removed"
