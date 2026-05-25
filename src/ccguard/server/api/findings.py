"""GET /api/v1/findings — все findings со всех машин с фильтрами."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import FindingRecord, Machine

router = APIRouter(prefix="/api/v1")


@router.get("/findings")
def list_findings(
    severity: str | None = Query(default=None, pattern="^(info|warn|block|critical)$"),
    rule_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object]:
    stmt = select(FindingRecord)
    if severity is not None:
        stmt = stmt.where(FindingRecord.severity == severity)
    if rule_id is not None:
        stmt = stmt.where(FindingRecord.rule_id == rule_id)
    stmt = stmt.order_by(FindingRecord.discovered_at.desc()).limit(limit)  # type: ignore[union-attr]
    rows = session.exec(stmt).all()

    label_cache: dict[str, str | None] = {}
    items: list[dict[str, object]] = []
    for r in rows:
        if r.machine_id not in label_cache:
            m = session.get(Machine, r.machine_id)
            label_cache[r.machine_id] = m.machine_label if m else None
        items.append(
            {
                "machine_id": r.machine_id,
                "machine_label": label_cache[r.machine_id],
                "discovered_at": r.discovered_at.isoformat(),
                "finding": json.loads(r.payload_json),
            }
        )
    return {"findings": items, "total": len(items)}
