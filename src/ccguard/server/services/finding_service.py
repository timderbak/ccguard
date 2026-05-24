"""Finding queries with filters and pagination."""

from __future__ import annotations

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord


def query_findings(
    session: Session,
    *,
    severity: str | None = None,
    rule_id: str | None = None,
    machine_id: str | None = None,
    limit: int = 50,
) -> list[FindingRecord]:
    stmt = select(FindingRecord)
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity)
    if rule_id:
        stmt = stmt.where(FindingRecord.rule_id == rule_id)
    if machine_id:
        stmt = stmt.where(FindingRecord.machine_id == machine_id)
    stmt = stmt.order_by(FindingRecord.discovered_at.desc()).limit(limit)  # type: ignore[attr-defined]
    return list(session.exec(stmt))
