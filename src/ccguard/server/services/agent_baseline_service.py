"""TOFU baseline + drift detection for Claude Code custom subagents.

Sibling of skill_baseline_service. Slot identity is
(machine_id, name, origin, parent_plugin); fingerprint composes those plus
file_hash. Severity matrix:

  * new (after bootstrap)                            → warn  (agent.new)
  * bootstrap (no active rows on machine)            → silent
  * removed, was pending (never accepted)            → silent (missing)
  * removed, was active/accepted_drift (P7)          → warn  (agent.removed)
  * drift, tools contain Bash/Write/Edit/NotebookEdit → block (agent.rug_pull.dangerous)
  * drift, only safe tools (or no tools)             → warn  (agent.drift.text)

Design: docs/superpowers/specs/2026-06-02-skills-agents-baseline-design.md
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlmodel import Session, select

from ccguard.schemas.inventory import AgentEntry
from ccguard.server.db.models import AgentBaseline, FindingRecord

# Tools whose presence makes a subagent capable of side effects on the
# host. If any of these is in `tools:` frontmatter, drift is block-level.
DANGEROUS_TOOLS: frozenset[str] = frozenset({
    "Bash", "Write", "Edit", "NotebookEdit",
})


def compute_fingerprint(
    name: str,
    origin: str,
    parent_plugin: str | None,
    file_hash: str,
) -> str:
    pp = parent_plugin or ""
    raw = f"{name}|{origin}|{pp}|{file_hash}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _tools_csv(tools: list[str] | None) -> str | None:
    """Sorted, comma-joined for storage. None → None."""
    if not tools:
        return None
    return ",".join(sorted(set(tools)))


def _has_dangerous(tools: list[str] | None) -> bool:
    if not tools:
        return False
    return bool(set(tools) & DANGEROUS_TOOLS)


# Bulk-removal grouping threshold (anti alert-fatigue).
_REMOVAL_GROUP_THRESHOLD: int = 3


def _make_finding(
    *,
    machine_id: str,
    inventory_id: int | None,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    payload: dict,
) -> FindingRecord:
    payload_full = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        **payload,
    }
    return FindingRecord(
        machine_id=machine_id,
        inventory_id=inventory_id,
        rule_id=rule_id,
        severity=severity,
        discovered_at=_now(),
        payload_json=json.dumps(payload_full, ensure_ascii=False),
    )


def update_and_detect(
    session: Session,
    machine_id: str,
    current_agents: list[AgentEntry],
    *,
    inventory_id: int | None = None,
) -> list[FindingRecord]:
    """Reconcile current agents against AgentBaseline. Mutates session."""
    now = _now()
    findings: list[FindingRecord] = []
    seen_slots: set[tuple[str, str, str]] = set()

    for ag in current_agents:
        origin = ag.origin
        parent = ag.parent_plugin or ""
        slot = (ag.name, origin, parent)
        seen_slots.add(slot)
        new_fp = compute_fingerprint(ag.name, origin, ag.parent_plugin, ag.file_hash)

        existing = session.exec(
            select(AgentBaseline).where(
                AgentBaseline.machine_id == machine_id,
                AgentBaseline.name == ag.name,
                AgentBaseline.origin == origin,
                AgentBaseline.parent_plugin == (ag.parent_plugin or None),
            )
        ).one_or_none()

        if existing is not None and existing.fingerprint == new_fp:
            existing.last_seen_at = now
            if existing.status == "missing":
                existing.status = "active"
            session.add(existing)
            continue

        if existing is None:
            has_active = session.exec(
                select(AgentBaseline)
                .where(
                    AgentBaseline.machine_id == machine_id,
                    AgentBaseline.status == "active",
                )
                .limit(1)
            ).first()

            row = AgentBaseline(
                machine_id=machine_id,
                name=ag.name,
                origin=origin,
                parent_plugin=ag.parent_plugin,
                source_marketplace=ag.source_marketplace,
                file_hash=ag.file_hash,
                tools_csv=_tools_csv(ag.tools),
                model=ag.model,
                path=ag.path,
                fingerprint=new_fp,
                status="pending",
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(row)

            if has_active is not None:
                source_label = (
                    f"{ag.parent_plugin}@{ag.source_marketplace}"
                    if ag.parent_plugin else "local"
                )
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="agent.new",
                    severity="warn",
                    title=f"Новый субагент «{ag.name}»",
                    description=(
                        f"Источник: {source_label}. "
                        f"Tools: {', '.join(ag.tools) if ag.tools else 'не указаны'}. "
                        "Если ты сам его поставил — подтверди baseline."
                    ),
                    payload={
                        "name": ag.name,
                        "origin": origin,
                        "parent_plugin": ag.parent_plugin,
                        "source_marketplace": ag.source_marketplace,
                        "path": ag.path,
                        "tools": ag.tools,
                        "model": ag.model,
                    },
                ))
            continue

        # Drift.
        if existing.file_hash != ag.file_hash:
            if _has_dangerous(ag.tools):
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="agent.rug_pull.dangerous",
                    severity="block",
                    title=f"Изменился субагент «{ag.name}» с опасными tools",
                    description=(
                        "Промпт субагента изменился, а у него есть права на "
                        f"{', '.join(sorted(set(ag.tools or []) & DANGEROUS_TOOLS))}. "
                        "Drift в таком агенте = риск supply chain rug pull. "
                        "Проверь diff и подтверди если изменение ожидаемое."
                    ),
                    payload={
                        "name": ag.name,
                        "origin": origin,
                        "parent_plugin": ag.parent_plugin,
                        "source_marketplace": ag.source_marketplace,
                        "old_file_hash": existing.file_hash,
                        "new_file_hash": ag.file_hash,
                        "path": ag.path,
                        "tools": ag.tools,
                    },
                ))
            else:
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="agent.drift.text",
                    severity="warn",
                    title=f"Изменился субагент «{ag.name}»",
                    description=(
                        "Промпт изменился; tools без Bash/Write/Edit/NotebookEdit, "
                        "риск ниже. Просмотри diff."
                    ),
                    payload={
                        "name": ag.name,
                        "origin": origin,
                        "parent_plugin": ag.parent_plugin,
                        "source_marketplace": ag.source_marketplace,
                        "old_file_hash": existing.file_hash,
                        "new_file_hash": ag.file_hash,
                        "path": ag.path,
                        "tools": ag.tools,
                    },
                ))

        existing.file_hash = ag.file_hash
        existing.tools_csv = _tools_csv(ag.tools)
        existing.model = ag.model
        existing.path = ag.path
        existing.source_marketplace = ag.source_marketplace
        existing.fingerprint = new_fp
        existing.last_seen_at = now
        session.add(existing)

    all_rows = session.exec(
        select(AgentBaseline).where(AgentBaseline.machine_id == machine_id)
    ).all()
    removed: list[AgentBaseline] = []
    for r in all_rows:
        slot = (r.name, r.origin, r.parent_plugin or "")
        if slot not in seen_slots and r.status not in ("missing", "removed"):
            # P7: a CONFIRMED subagent disappearing is a supply-chain removal.
            if r.status in ("active", "accepted_drift"):
                removed.append(r)
            r.status = "missing"
            session.add(r)

    # Bulk removal → one grouped finding instead of one-per-agent (anti fatigue).
    if len(removed) > _REMOVAL_GROUP_THRESHOLD:
        names = ", ".join(r.name for r in removed[:8])
        findings.append(
            _make_finding(
                machine_id=machine_id,
                inventory_id=inventory_id,
                rule_id="agent.removed",
                severity="warn",
                title=f"Удалено {len(removed)} принятых subagent'ов",
                description=(
                    f"{len(removed)} принятых subagent'ов исчезли за один sync "
                    f"(возможно массовое удаление плагина): {names}"
                    + ("…" if len(removed) > 8 else "")
                ),
                payload={"removed_count": len(removed)},
            )
        )
    else:
        for r in removed:
            findings.append(
                _make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="agent.removed",
                    severity="warn",
                    title="Принятый subagent удалён",
                    description=(
                        f"Subagent `{r.name}` был принят в baseline, но исчез из "
                        "конфигурации. Removal зафиксирован (supply-chain артефакт удалён)."
                    ),
                    payload={"name": r.name, "origin": r.origin},
                )
            )

    for f in findings:
        session.add(f)
    return findings


# --- Accept / reject (identical shape to skill_baseline_service) ---------


def accept_baseline(
    session: Session,
    machine_id: str,
    baseline_id: int,
    accepting_user: str,
) -> AgentBaseline:
    row = session.exec(
        select(AgentBaseline).where(
            AgentBaseline.id == baseline_id,
            AgentBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(
            f"AgentBaseline id={baseline_id} for machine={machine_id} not found"
        )
    row.status = "active"
    row.accepted_at = _now()
    row.accepted_by = accepting_user
    session.add(row)
    return row


def accept_all_pending(
    session: Session,
    machine_id: str,
    accepting_user: str,
) -> int:
    rows = session.exec(
        select(AgentBaseline).where(
            AgentBaseline.machine_id == machine_id,
            AgentBaseline.status == "pending",
        )
    ).all()
    now = _now()
    for r in rows:
        r.status = "active"
        r.accepted_at = now
        r.accepted_by = accepting_user
        session.add(r)
    return len(rows)


def reject_and_mark(
    session: Session,
    machine_id: str,
    baseline_id: int,
) -> AgentBaseline:
    row = session.exec(
        select(AgentBaseline).where(
            AgentBaseline.id == baseline_id,
            AgentBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(
            f"AgentBaseline id={baseline_id} for machine={machine_id} not found"
        )
    row.status = "removed"
    session.add(row)
    return row
