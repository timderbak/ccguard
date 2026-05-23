"""GET /api/v1/machines и /api/v1/machines/{id}."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, select

from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import AuditRecord, FindingRecord, InventorySnapshot, Machine

router = APIRouter(prefix="/api/v1")


def _summarize_findings(session: Session, machine_id: str) -> dict[str, int]:
    """Сводка severity по последнему inventory машины."""
    latest = session.exec(
        select(InventorySnapshot)
        .where(InventorySnapshot.machine_id == machine_id)
        .order_by(InventorySnapshot.id.desc())  # type: ignore[union-attr]
        .limit(1)
    ).first()
    if latest is None:
        return {"info": 0, "warn": 0, "block": 0}
    rows = session.exec(
        select(FindingRecord).where(FindingRecord.inventory_id == latest.id)
    ).all()
    summary = {"info": 0, "warn": 0, "block": 0}
    for r in rows:
        if r.severity in summary:
            summary[r.severity] += 1
    return summary


@router.get("/machines")
def list_machines(
    severity: str | None = Query(default=None, pattern="^(info|warn|block)$"),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object]:
    machines = session.exec(select(Machine).limit(limit)).all()
    items: list[dict[str, object]] = []
    for m in machines:
        summary = _summarize_findings(session, m.machine_id)
        if severity is not None and summary.get(severity, 0) == 0:
            continue
        items.append(
            {
                "machine_id": m.machine_id,
                "machine_label": m.machine_label,
                "last_seen": m.last_seen.isoformat(),
                "agent_version": m.agent_version,
                "findings_summary": summary,
            }
        )
    return {"machines": items, "total": len(items)}


@router.get("/machines/{machine_id}")
def get_machine(
    machine_id: str,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object]:
    machine = session.get(Machine, machine_id)
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="machine not found")
    latest = session.exec(
        select(InventorySnapshot)
        .where(InventorySnapshot.machine_id == machine_id)
        .order_by(InventorySnapshot.id.desc())  # type: ignore[union-attr]
        .limit(1)
    ).first()
    findings_rows = (
        session.exec(
            select(FindingRecord).where(
                FindingRecord.inventory_id == (latest.id if latest else -1)
            )
        ).all()
        if latest
        else []
    )
    audit_rows = session.exec(
        select(AuditRecord)
        .where(AuditRecord.machine_id == machine_id)
        .order_by(AuditRecord.received_at.desc())  # type: ignore[union-attr]
        .limit(50)
    ).all()
    return {
        "machine_id": machine.machine_id,
        "machine_label": machine.machine_label,
        "last_seen": machine.last_seen.isoformat(),
        "agent_version": machine.agent_version,
        "inventory": json.loads(latest.payload_json) if latest else None,
        "findings": [json.loads(r.payload_json) for r in findings_rows],
        "recent_audit_events": [
            {
                "timestamp": r.timestamp.isoformat(),
                "tool_name": r.tool_name,
                "decision": r.decision,
                "rule_id": r.rule_id,
                "reason": r.reason,
                "fail_open": r.fail_open,
                "tool_input_fingerprint": r.tool_input_fingerprint,
            }
            for r in audit_rows
        ],
    }
