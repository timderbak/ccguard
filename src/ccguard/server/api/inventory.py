"""POST /api/v1/inventory — приём SyncPayload от агента."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlmodel import Session

from ccguard.schemas import SyncPayload
from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import AuditRecord, FindingRecord, InventorySnapshot, Machine

router = APIRouter(prefix="/api/v1")


@router.post("/inventory")
def post_inventory(
    payload: SyncPayload,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object]:
    inv = payload.inventory
    now = datetime.now(UTC)

    machine = session.get(Machine, inv.machine_id)
    if machine is None:
        machine = Machine(
            machine_id=inv.machine_id,
            machine_label=inv.machine_label,
            first_seen=now,
            last_seen=now,
            agent_version=inv.agent_version,
        )
        session.add(machine)
    else:
        machine.last_seen = now
        machine.machine_label = inv.machine_label or machine.machine_label
        machine.agent_version = inv.agent_version
        session.add(machine)

    snapshot = InventorySnapshot(
        machine_id=inv.machine_id,
        received_at=now,
        payload_json=inv.model_dump_json(),
    )
    session.add(snapshot)
    session.flush()  # чтобы получить snapshot.id

    findings_stored = 0
    for f in payload.findings:
        rec = FindingRecord(
            machine_id=inv.machine_id,
            inventory_id=snapshot.id or 0,
            rule_id=f.rule_id,
            severity=f.severity,
            payload_json=f.model_dump_json(),
        )
        session.add(rec)
        findings_stored += 1

    audit_stored = 0
    for a in payload.audit_events:
        rec_a = AuditRecord(
            machine_id=inv.machine_id,
            received_at=now,
            timestamp=a.timestamp,
            tool_name=a.tool_name,
            decision=a.decision,
            rule_id=a.rule_id,
            reason=a.reason,
            fail_open=a.fail_open,
            tool_input_fingerprint=a.tool_input_fingerprint,
        )
        session.add(rec_a)
        audit_stored += 1

    session.commit()

    return {
        "accepted": True,
        "machine_id": inv.machine_id,
        "stored_inventory_id": snapshot.id,
        "stored_findings_count": findings_stored,
        "stored_audit_count": audit_stored,
    }
