"""TOFU baseline + drift detection for Claude Code skills.

Sibling of hook_baseline_service and mcp_baseline_service. Slot identity is
(machine_id, name, origin, parent_plugin); fingerprint composes those plus
dir_hash. Severity matrix:

  * new (after bootstrap)        → warn  (skill.new)
  * bootstrap (no active rows)   → silent (status="pending", no finding)
  * removed                      → silent (status="missing")
  * content drift, has scripts   → block (skill.rug_pull.content)
  * content drift, text-only     → warn  (skill.drift.text)

Design: docs/superpowers/specs/2026-06-02-skills-agents-baseline-design.md
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlmodel import Session, select

from ccguard.schemas.inventory import SkillEntry
from ccguard.server.db.models import FindingRecord, SkillBaseline


def compute_fingerprint(
    name: str,
    origin: str,
    parent_plugin: str | None,
    dir_hash: str,
) -> str:
    """sha256 of name|origin|parent_plugin|dir_hash. Parent_plugin sentinel
    is empty string so local skills (parent_plugin=None) don't collide with
    plugin-bundled ones whose plugin name happens to be empty."""
    pp = parent_plugin or ""
    raw = f"{name}|{origin}|{pp}|{dir_hash}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
    current_skills: list[SkillEntry],
    *,
    inventory_id: int | None = None,
) -> list[FindingRecord]:
    """Reconcile current skills against SkillBaseline. Mutates session."""
    now = _now()
    findings: list[FindingRecord] = []
    seen_slots: set[tuple[str, str, str]] = set()

    for sk in current_skills:
        origin = sk.origin
        parent = sk.parent_plugin or ""
        slot = (sk.name, origin, parent)
        seen_slots.add(slot)
        new_fp = compute_fingerprint(sk.name, origin, sk.parent_plugin, sk.dir_hash)

        existing = session.exec(
            select(SkillBaseline).where(
                SkillBaseline.machine_id == machine_id,
                SkillBaseline.name == sk.name,
                SkillBaseline.origin == origin,
                # parent_plugin может быть NULL — сравниваем безопасно через
                # IS-эквивалент в SQLAlchemy через `==` + явный None.
                SkillBaseline.parent_plugin == (sk.parent_plugin or None),
            )
        ).one_or_none()

        if existing is not None and existing.fingerprint == new_fp:
            existing.last_seen_at = now
            if existing.status == "missing":
                existing.status = "active"  # silent recovery
            session.add(existing)
            continue

        if existing is None:
            # New slot. Bootstrap-aware emission — silent on first sync.
            has_active = session.exec(
                select(SkillBaseline)
                .where(
                    SkillBaseline.machine_id == machine_id,
                    SkillBaseline.status == "active",
                )
                .limit(1)
            ).first()

            row = SkillBaseline(
                machine_id=machine_id,
                name=sk.name,
                origin=origin,
                parent_plugin=sk.parent_plugin,
                source_marketplace=sk.source_marketplace,
                dir_hash=sk.dir_hash,
                has_referenced_scripts=sk.has_referenced_scripts,
                path=sk.path,
                fingerprint=new_fp,
                status="pending",
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(row)

            if has_active is not None:
                source_label = (
                    f"{sk.parent_plugin}@{sk.source_marketplace}"
                    if sk.parent_plugin else "local"
                )
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="skill.new",
                    severity="warn",
                    title=f"Новый скилл «{sk.name}»",
                    description=(
                        f"Источник: {source_label}. Если ты сам его поставил — "
                        "нажми «Принять baseline». Если нет — удали из "
                        "~/.claude/skills/ или отключи плагин."
                    ),
                    payload={
                        "name": sk.name,
                        "origin": origin,
                        "parent_plugin": sk.parent_plugin,
                        "source_marketplace": sk.source_marketplace,
                        "path": sk.path,
                        "has_referenced_scripts": sk.has_referenced_scripts,
                    },
                ))
            continue

        # Same slot, fingerprint changed → content drift.
        if existing.dir_hash != sk.dir_hash:
            if sk.has_referenced_scripts:
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="skill.rug_pull.content",
                    severity="block",
                    title=f"Скилл «{sk.name}» изменился (содержит скрипты)",
                    description=(
                        "В директории скилла есть исполняемые файлы — "
                        "drift может означать supply chain rug pull. "
                        "Проверь источник плагина. Если ты сам обновлял — "
                        "нажми «Принять новый baseline»."
                    ),
                    payload={
                        "name": sk.name,
                        "origin": origin,
                        "parent_plugin": sk.parent_plugin,
                        "source_marketplace": sk.source_marketplace,
                        "old_dir_hash": existing.dir_hash,
                        "new_dir_hash": sk.dir_hash,
                        "path": sk.path,
                    },
                ))
            else:
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="skill.drift.text",
                    severity="warn",
                    title=f"Изменился текст скилла «{sk.name}»",
                    description=(
                        "SKILL.md или связанные .md-файлы изменились "
                        "(скриптов внутри нет, риск ниже). Просмотри diff."
                    ),
                    payload={
                        "name": sk.name,
                        "origin": origin,
                        "parent_plugin": sk.parent_plugin,
                        "source_marketplace": sk.source_marketplace,
                        "old_dir_hash": existing.dir_hash,
                        "new_dir_hash": sk.dir_hash,
                        "path": sk.path,
                    },
                ))

        existing.dir_hash = sk.dir_hash
        existing.has_referenced_scripts = sk.has_referenced_scripts
        existing.path = sk.path
        existing.source_marketplace = sk.source_marketplace
        existing.fingerprint = new_fp
        existing.last_seen_at = now
        session.add(existing)

    # Mark unseen rows as missing. P7: a CONFIRMED skill disappearing is a
    # supply-chain removal worth surfacing; a pending row stays silent.
    all_rows = session.exec(
        select(SkillBaseline).where(SkillBaseline.machine_id == machine_id)
    ).all()
    removed: list[SkillBaseline] = []
    for r in all_rows:
        slot = (r.name, r.origin, r.parent_plugin or "")
        if slot not in seen_slots and r.status not in ("missing", "removed"):
            if r.status in ("active", "accepted_drift"):
                removed.append(r)
            r.status = "missing"
            session.add(r)

    # Bulk removal (e.g. `npm uninstall <plugin>`) → one grouped finding instead
    # of one-per-skill (anti alert-fatigue; review should-fix).
    if len(removed) > _REMOVAL_GROUP_THRESHOLD:
        names = ", ".join(r.name for r in removed[:8])
        findings.append(
            _make_finding(
                machine_id=machine_id,
                inventory_id=inventory_id,
                rule_id="skill.removed",
                severity="warn",
                title=f"Удалено {len(removed)} принятых skill'ов",
                description=(
                    f"{len(removed)} принятых skill'ов исчезли за один sync "
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
                    rule_id="skill.removed",
                    severity="warn",
                    title="Принятый skill удалён",
                    description=(
                        f"Skill `{r.name}` был принят в baseline, но исчез из "
                        "конфигурации. Removal зафиксирован (supply-chain артефакт удалён)."
                    ),
                    payload={"name": r.name, "origin": r.origin},
                )
            )

    for f in findings:
        session.add(f)
    return findings


# --- Accept / reject ------------------------------------------------------


def accept_baseline(
    session: Session,
    machine_id: str,
    baseline_id: int,
    accepting_user: str,
) -> SkillBaseline:
    row = session.exec(
        select(SkillBaseline).where(
            SkillBaseline.id == baseline_id,
            SkillBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(
            f"SkillBaseline id={baseline_id} for machine={machine_id} not found"
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
        select(SkillBaseline).where(
            SkillBaseline.machine_id == machine_id,
            SkillBaseline.status == "pending",
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
) -> SkillBaseline:
    row = session.exec(
        select(SkillBaseline).where(
            SkillBaseline.id == baseline_id,
            SkillBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(
            f"SkillBaseline id={baseline_id} for machine={machine_id} not found"
        )
    row.status = "removed"
    session.add(row)
    return row
