"""POST /api/v1/inventory — приём SyncPayload от агента."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlmodel import Session

from ccguard.schemas import SyncPayload
from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import AuditRecord, FindingRecord, InventorySnapshot, Machine
from ccguard.server.services import (
    agent_baseline_service,
    hook_baseline_service,
    mcp_baseline_service,
    memory_baseline_service,
    sandbox_baseline_service,
    skill_baseline_service,
)

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
            agent_kind=inv.agent_kind,
        )
        session.add(machine)
    else:
        machine.last_seen = now
        machine.machine_label = inv.machine_label or machine.machine_label
        machine.agent_version = inv.agent_version
        machine.agent_kind = inv.agent_kind
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

    # MCP rug-pull detection. Side-effect: creates/updates baselines and
    # appends FindingRecord rows to the session — committed below with the
    # rest. We count emitted findings so the response can report them.
    mcp_rug_findings = mcp_baseline_service.update_and_detect(
        session,
        machine_id=inv.machine_id,
        current_mcps=list(inv.mcp_servers),
        inventory_id=snapshot.id,
    )
    findings_stored += len(mcp_rug_findings)

    # Hook TOFU baseline + drift detection. Same shape as the MCP path above:
    # service appends FindingRecords to the session, we count them for the
    # response. See ccguard.server.services.hook_baseline_service.
    hook_findings = hook_baseline_service.update_and_detect(
        session,
        machine_id=inv.machine_id,
        current_hooks=list(inv.hooks),
        inventory_id=snapshot.id,
    )
    findings_stored += len(hook_findings)

    # Skill TOFU baseline. Same contract as hooks/MCP — service mutates
    # session, we count findings for the response.
    skill_findings = skill_baseline_service.update_and_detect(
        session,
        machine_id=inv.machine_id,
        current_skills=list(inv.skills),
        inventory_id=snapshot.id,
    )
    findings_stored += len(skill_findings)

    agent_findings = agent_baseline_service.update_and_detect(
        session,
        machine_id=inv.machine_id,
        current_agents=list(inv.agents),
        inventory_id=snapshot.id,
    )
    findings_stored += len(agent_findings)

    # Память/инструкции (ASI06). Поле опционально: агент v0.1/v0.2 его не шлёт,
    # тогда список пуст и baseline просто ничего не трогает (graceful degradation).
    memory_findings = memory_baseline_service.update_and_detect(
        session,
        machine_id=inv.machine_id,
        current_memory=list(inv.memory_files),
        inventory_id=snapshot.id,
    )
    findings_stored += len(memory_findings)

    # Песочница (sandbox): дрейф периметра и детект его ОСЛАБЛЕНИЯ (ASI03/T1562).
    # Поле опционально: агент v0.1/v0.2 шлёт None, тогда сервис — no-op.
    sandbox_findings = sandbox_baseline_service.update_and_detect(
        session,
        machine_id=inv.machine_id,
        sandbox=inv.sandbox,
        inventory_id=snapshot.id,
    )
    findings_stored += len(sandbox_findings)

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
