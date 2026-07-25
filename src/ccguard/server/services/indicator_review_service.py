"""Admin review for pending ``ThreatIndicator`` rows (Path-2 approval gate).

Path-2 auto-collection (e.g. :mod:`ccguard.server.services.ioc_feed_service`)
inserts indicators with ``status="pending"`` — never auto-live. This is the
human gate that turns a fetched IOC into an enforced one:

* **approve** → ``pending`` → ``active`` (the serve paths — e.g.
  :func:`indicator_override_service.load_suspicious_host_rules` — read only
  ``active`` + ``enabled`` rows, so the indicator ships on the next policy sync).
* **reject** → ``pending`` → ``rejected`` (kept for provenance / de-dup, never
  served, so the same IOC re-fetched next sweep isn't re-proposed).

Mirrors :func:`proposed_signal_service.approve` / ``reject`` for the indicator
store; deliberately tiny (a status flip + review stamp), no override plumbing —
serving is already wired on the ``active`` status.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator


class NotPending(ValueError):
    """Raised when approving/rejecting a row that isn't pending (missing / already reviewed)."""


def list_pending(session: Session, limit: int = 200) -> list[ThreatIndicator]:
    """Pending indicators, oldest first (review-queue order)."""
    stmt = (
        select(ThreatIndicator)
        .where(ThreatIndicator.status == "pending")
        .order_by(ThreatIndicator.created_at.asc())  # type: ignore[attr-defined]
        .limit(limit)
    )
    return list(session.exec(stmt))


def _review(session: Session, row_id: int, *, status: str, reviewed_by: str) -> ThreatIndicator:
    row = session.get(ThreatIndicator, row_id)
    if row is None or row.status != "pending":
        raise NotPending(f"indicator {row_id} is not pending")
    now = datetime.now(UTC)
    row.status = status
    row.enabled = status == "active"
    row.reviewed_by = reviewed_by
    row.reviewed_at = now
    row.updated_at = now
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def approve(session: Session, row_id: int, *, reviewed_by: str) -> ThreatIndicator:
    """Promote a pending indicator to ``active`` (served on next sync)."""
    return _review(session, row_id, status="active", reviewed_by=reviewed_by)


def reject(session: Session, row_id: int, *, reviewed_by: str) -> ThreatIndicator:
    """Mark a pending indicator ``rejected`` — kept for provenance, never served."""
    return _review(session, row_id, status="rejected", reviewed_by=reviewed_by)
