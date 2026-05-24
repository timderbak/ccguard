"""Policy version service: draft / publish / rollback / diff."""
from __future__ import annotations

import difflib
from datetime import UTC, datetime

import yaml
from sqlmodel import Session, select

from ccguard.schemas import Policy
from ccguard.server.db.models import PolicyVersion


def validate_yaml(yaml_text: str) -> Policy:
    """Parse and validate YAML against Policy schema. Raises on failure."""
    data = yaml.safe_load(yaml_text)
    return Policy.model_validate(data)


def get_draft(session: Session) -> PolicyVersion | None:
    return session.exec(
        select(PolicyVersion).where(PolicyVersion.status == "draft")
    ).first()


def get_current_published(session: Session) -> PolicyVersion | None:
    return session.exec(
        select(PolicyVersion)
        .where(PolicyVersion.status == "published")
        .order_by(PolicyVersion.revision.desc())
    ).first()


def _next_revision(session: Session) -> int:
    rows = session.exec(select(PolicyVersion.revision)).all()
    return (max(rows) if rows else 0) + 1


def save_draft(
    session: Session,
    *,
    yaml_text: str,
    user_id: str,
    comment: str | None = None,
) -> PolicyVersion:
    """Validate YAML and upsert the single draft row."""
    validate_yaml(yaml_text)
    existing = get_draft(session)
    if existing is not None:
        existing.yaml_text = yaml_text
        existing.comment = comment
        existing.created_by = user_id
        existing.created_at = datetime.now(UTC)
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing

    row = PolicyVersion(
        revision=_next_revision(session),
        status="draft",
        yaml_text=yaml_text,
        comment=comment,
        created_by=user_id,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def publish_draft(session: Session, *, user_id: str) -> PolicyVersion:
    draft = get_draft(session)
    if draft is None:
        raise ValueError("no draft to publish")

    current = get_current_published(session)
    if current is not None:
        current.status = "archived"
        session.add(current)

    draft.status = "published"
    draft.published_at = datetime.now(UTC)
    draft.created_by = user_id
    session.add(draft)
    session.commit()
    session.refresh(draft)
    return draft


def rollback_to(
    session: Session,
    *,
    version_id: int,
    user_id: str,
) -> PolicyVersion:
    target = session.get(PolicyVersion, version_id)
    if target is None:
        raise ValueError(f"version {version_id} not found")

    comment = f"rollback to rev {target.revision}"
    return save_draft(
        session,
        yaml_text=target.yaml_text,
        user_id=user_id,
        comment=comment,
    )


def diff_policies(before_yaml: str, after_yaml: str) -> list[str]:
    return list(
        difflib.unified_diff(
            before_yaml.splitlines(),
            after_yaml.splitlines(),
            fromfile="published",
            tofile="draft",
            lineterm="",
        )
    )
