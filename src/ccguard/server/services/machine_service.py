"""Machine compliance status + fleet queries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, InventorySnapshot, Machine
from ccguard.server.services.policy_service import get_current_published

ComplianceStatus = Literal["compliant", "policy-old", "stale", "blocking"]

_STALE_THRESHOLD = timedelta(days=7)


def compliance_status(
    *,
    last_seen: datetime,
    agent_policy_revision: int | None,
    current_published_revision: int,
    block_findings_count: int,
) -> ComplianceStatus:
    if block_findings_count > 0:
        return "blocking"
    # Make `last_seen` UTC-aware if naive (SQLite strips tz on roundtrip).
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age = datetime.now(UTC) - last_seen
    if age > _STALE_THRESHOLD:
        return "stale"
    if agent_policy_revision is None or agent_policy_revision < current_published_revision:
        return "policy-old"
    return "compliant"


@dataclass
class MachineRow:
    machine_id: str
    machine_label: str | None
    last_seen: datetime
    agent_version: str | None
    agent_policy_revision: int | None
    warn_count: int
    block_count: int
    status: ComplianceStatus


def list_machines_with_status(session: Session) -> list[MachineRow]:
    current = get_current_published(session)
    current_rev = current.revision if current else 0
    machines = list(session.exec(select(Machine)))
    out: list[MachineRow] = []
    for m in machines:
        latest_inv = session.exec(
            select(InventorySnapshot)
            .where(InventorySnapshot.machine_id == m.machine_id)
            .order_by(InventorySnapshot.received_at.desc())  # type: ignore[attr-defined]
        ).first()
        agent_rev: int | None = None
        if latest_inv is not None:
            try:
                data = json.loads(latest_inv.payload_json)
                agent_rev = int(data.get("meta", {}).get("revision", 0)) or None
            except (ValueError, KeyError):
                agent_rev = None
        warn_count = 0
        block_count = 0
        if latest_inv is not None and latest_inv.id is not None:
            findings = list(
                session.exec(
                    select(FindingRecord).where(FindingRecord.inventory_id == latest_inv.id)
                )
            )
            for f in findings:
                if f.severity == "warn":
                    warn_count += 1
                elif f.severity == "block":
                    block_count += 1
        out.append(
            MachineRow(
                machine_id=m.machine_id,
                machine_label=m.machine_label,
                last_seen=m.last_seen,
                agent_version=m.agent_version,
                agent_policy_revision=agent_rev,
                warn_count=warn_count,
                block_count=block_count,
                status=compliance_status(
                    last_seen=m.last_seen,
                    agent_policy_revision=agent_rev,
                    current_published_revision=current_rev,
                    block_findings_count=block_count,
                ),
            )
        )
    return out


def get_latest_inventory_json(session: Session, machine_id: str) -> dict[str, object] | None:
    inv = session.exec(
        select(InventorySnapshot)
        .where(InventorySnapshot.machine_id == machine_id)
        .order_by(InventorySnapshot.received_at.desc())  # type: ignore[attr-defined]
    ).first()
    if inv is None:
        return None
    try:
        return json.loads(inv.payload_json)
    except ValueError:
        return None


def get_findings_for_machine(
    session: Session, machine_id: str, limit: int = 200
) -> list[FindingRecord]:
    return list(
        session.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == machine_id)
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
    )
