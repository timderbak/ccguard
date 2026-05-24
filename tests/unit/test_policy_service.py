"""Unit tests for policy_service draft/publish/rollback flow."""
from __future__ import annotations

import pytest
from sqlmodel import Session, select

from ccguard.server.db.models import PolicyVersion
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import policy_service

SAMPLE_YAML = """\
meta:
  schema_version: 1
  revision: 1
  updated_at: '2026-01-01T00:00:00Z'
hooks:
  severity: warn
  allowlist_commands: []
  deny_unknown: true
"""

SAMPLE_YAML_V2 = """\
meta:
  schema_version: 1
  revision: 2
  updated_at: '2026-01-02T00:00:00Z'
hooks:
  severity: block
  allowlist_commands: []
  deny_unknown: true
"""


@pytest.fixture
def db():
    engine = make_engine("sqlite://")
    init_db(engine)
    with Session(engine) as s:
        yield s


def test_save_draft_creates_row(db) -> None:
    row = policy_service.save_draft(db, yaml_text=SAMPLE_YAML, user_id="admin")
    assert row.id is not None
    assert row.status == "draft"
    assert row.revision == 1
    assert row.created_by == "admin"


def test_save_draft_replaces_existing_draft(db) -> None:
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML, user_id="admin")
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML_V2, user_id="admin")
    drafts = db.exec(
        select(PolicyVersion).where(PolicyVersion.status == "draft")
    ).all()
    assert len(drafts) == 1
    assert "revision: 2" in drafts[0].yaml_text


def test_publish_promotes_draft_and_archives_old(db) -> None:
    # First publish
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML, user_id="admin")
    pub1 = policy_service.publish_draft(db, user_id="admin")
    assert pub1.status == "published"
    assert pub1.published_at is not None

    # Second publish: old should archive
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML_V2, user_id="admin")
    pub2 = policy_service.publish_draft(db, user_id="admin")
    assert pub2.status == "published"
    assert pub2.revision > pub1.revision

    db.refresh(pub1)
    assert pub1.status == "archived"


def test_publish_with_no_draft_raises(db) -> None:
    with pytest.raises(ValueError, match="no draft"):
        policy_service.publish_draft(db, user_id="admin")


def test_rollback_creates_new_draft_from_version(db) -> None:
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML, user_id="admin")
    pub1 = policy_service.publish_draft(db, user_id="admin")
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML_V2, user_id="admin")
    policy_service.publish_draft(db, user_id="admin")

    draft = policy_service.rollback_to(db, version_id=pub1.id, user_id="admin")
    assert draft.status == "draft"
    assert draft.yaml_text == pub1.yaml_text
    assert f"rollback to rev {pub1.revision}" in draft.comment

    # Only 1 draft
    drafts = db.exec(
        select(PolicyVersion).where(PolicyVersion.status == "draft")
    ).all()
    assert len(drafts) == 1


def test_get_current_published_returns_latest_revision(db) -> None:
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML, user_id="admin")
    policy_service.publish_draft(db, user_id="admin")
    policy_service.save_draft(db, yaml_text=SAMPLE_YAML_V2, user_id="admin")
    pub2 = policy_service.publish_draft(db, user_id="admin")

    current = policy_service.get_current_published(db)
    assert current is not None
    assert current.id == pub2.id
    assert current.revision == pub2.revision


def test_diff_policies_shows_changes() -> None:
    diff = policy_service.diff_policies(SAMPLE_YAML, SAMPLE_YAML_V2)
    joined = "\n".join(diff)
    assert "severity" in joined
    assert any(line.startswith("-") and "warn" in line for line in diff)
    assert any(line.startswith("+") and "block" in line for line in diff)
