"""ProposedSignal CRUD + approve/reject lifecycle (Rule Discovery Agent · E1).

The flow:

1. ``propose(...)`` validates draft shape and writes a ``pending`` row.
2. ``approve(...)`` re-validates, compiles the regex (refuses on syntax errors —
   leaves the row pending so the admin can edit), then writes a SettingsRecord
   override at ``catalog.override.<id>``. The override is the dynamic-catalog
   contract; E4 pushes it to agents via policy sync.
3. ``reject(...)`` records a reason; no override is written.

Status transitions are one-way: ``pending`` → ``approved`` | ``rejected``.
Re-reviewing a non-pending row raises NotPending so the UI can show a clear
error rather than silently re-stamping a reviewed decision.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import ProposedSignal, SettingsRecord

# Mirror catalog.py's id format constraint.
_ID_RE = re.compile(r"^[a-z0-9]+(\.[a-z0-9_]+)+$")
_ATTACK_RE = re.compile(r"^(T\d{4}(\.\d{3})?|ATLAS\..+)$")
_REQUIRED_KEYS = ("id", "attack_technique", "pattern", "description")
_PI_REQUIRED_KEYS = ("category", "pattern", "description")
_PI_CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_OVERRIDE_KEY_PREFIX = "catalog.override."
_PI_OVERRIDE_KEY_PREFIX = "pi.override."


class InvalidDraft(ValueError):
    """Draft fails shape or regex validation."""


class NotPending(ValueError):
    """Tried to approve/reject a row that is not in pending status."""


def _validate_shape(draft: dict[str, Any]) -> None:
    for k in _REQUIRED_KEYS:
        if k not in draft or not isinstance(draft[k], str) or not draft[k].strip():
            raise InvalidDraft(f"missing or empty required key: {k}")
    if not _ID_RE.fullmatch(draft["id"]):
        raise InvalidDraft(f"id {draft['id']!r} does not match kebab-namespaced format")
    if not _ATTACK_RE.fullmatch(draft["attack_technique"]):
        raise InvalidDraft(
            f"attack_technique {draft['attack_technique']!r} must be T#### or ATLAS.<name>"
        )


def _validate_regex(pattern: str) -> None:
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise InvalidDraft(f"pattern does not compile: {e}") from e


def _validate_pi_shape(draft: dict[str, Any]) -> None:
    """PI patterns have a different shape: {category, pattern, description}."""
    for k in _PI_REQUIRED_KEYS:
        if k not in draft or not isinstance(draft[k], str) or not draft[k].strip():
            raise InvalidDraft(f"missing or empty required key: {k}")
    if not _PI_CATEGORY_RE.fullmatch(draft["category"]):
        raise InvalidDraft(
            f"category {draft['category']!r} must be lowercase snake_case (3-64 chars)"
        )


def propose(
    session: Session,
    *,
    draft: dict[str, Any],
    source_kind: str,
    source_url: str | None = None,
    source_title: str | None = None,
    llm_rationale: str | None = None,
    kind: str = "signal",
) -> ProposedSignal:
    """Persist a new pending draft. Shape is validated; regex is not — admins
    sometimes want to massage a near-miss pattern before approving.

    ``kind="signal"`` (default) validates the behavioral signal shape.
    ``kind="pi_pattern"`` validates the prompt-injection pattern shape.
    """
    if kind == "pi_pattern":
        _validate_pi_shape(draft)
    else:
        _validate_shape(draft)
    row = ProposedSignal(
        draft_json=json.dumps(draft, ensure_ascii=False, sort_keys=True),
        source_kind=source_kind,
        source_url=source_url,
        source_title=source_title,
        llm_rationale=llm_rationale,
        status="pending",
        kind=kind,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def approve(session: Session, row_id: int, *, reviewed_by: str) -> ProposedSignal:
    """Approve a pending draft. Validates the regex compiles; on failure leaves
    the row pending so the admin can edit and retry. On success writes a
    SettingsRecord override that the agent picks up on next policy sync."""
    row = session.get(ProposedSignal, row_id)
    if row is None or row.status != "pending":
        raise NotPending(f"draft {row_id} is not pending")
    draft = json.loads(row.draft_json)

    if row.kind == "pi_pattern":
        _validate_pi_shape(draft)
        _validate_regex(draft["pattern"])
        override_key = f"{_PI_OVERRIDE_KEY_PREFIX}{draft['category']}"
    else:
        _validate_shape(draft)
        _validate_regex(draft["pattern"])
        override_key = f"{_OVERRIDE_KEY_PREFIX}{draft['id']}"

    existing = session.get(SettingsRecord, override_key)
    now = datetime.now(UTC)
    if existing is None:
        session.add(SettingsRecord(key=override_key, value=row.draft_json))
    else:
        existing.value = row.draft_json
        existing.updated_at = now
        session.add(existing)

    row.status = "approved"
    row.reviewed_by = reviewed_by
    row.reviewed_at = now
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def reject(
    session: Session, row_id: int, *, reviewed_by: str, reason: str
) -> ProposedSignal:
    row = session.get(ProposedSignal, row_id)
    if row is None or row.status != "pending":
        raise NotPending(f"draft {row_id} is not pending")
    row.status = "rejected"
    row.reviewed_by = reviewed_by
    row.reviewed_at = datetime.now(UTC)
    row.rejection_reason = reason
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def list_pending(session: Session, limit: int = 100) -> list[ProposedSignal]:
    stmt = (
        select(ProposedSignal)
        .where(ProposedSignal.status == "pending")
        .order_by(ProposedSignal.created_at.asc())  # type: ignore[attr-defined]
        .limit(limit)
    )
    return list(session.exec(stmt))


def list_reviewed(session: Session, limit: int = 50) -> list[ProposedSignal]:
    stmt = (
        select(ProposedSignal)
        .where(ProposedSignal.status != "pending")
        .order_by(ProposedSignal.reviewed_at.desc())  # type: ignore[attr-defined]
        .limit(limit)
    )
    return list(session.exec(stmt))
