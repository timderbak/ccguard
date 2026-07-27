"""TOFU-эталон и детект дрейфа для файлов памяти Claude Code (ASI06).

Брат hook_/skill_/agent_baseline_service. Слот — (machine_id, path), отпечаток —
content_hash файла. Матрица серьёзности намеренно мягкая по дрейфу и строже по
появлению нового вне проекта:

  * первый sync машины (нет active-строк)  → silent (status="pending")
  * новый файл памяти после bootstrap      → warn  (memory.new)
  * новый ВНЕШНИЙ импорт / ancestor-файл   → warn  (memory.external) — отдельно,
        потому что это инструкция вне того, что ревьюят в репозитории
  * дрейф содержимого                       → warn  (memory.drift)
  * исчез                                    → silent (status="missing")

Почему дрейф — warn, а не block: CLAUDE.md законно правят постоянно. Блокирующая
находка на каждое редактирование памяти приучила бы оператора её игнорировать —
и настоящую закладку он пропустил бы вместе с шумом. Задача baseline не в том,
чтобы кричать на каждое изменение, а в том, чтобы ни одно не прошло незаметно.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.schemas.inventory import MemoryEntry
from ccguard.server.db.models import FindingRecord, MemoryBaseline

# Появление нового файла на этих уровнях примечательнее рядовой правки: он вне
# того, что команда ревьюит в репозитории (родительские каталоги на машине,
# внешний @import из home / по абсолютному пути).
_OFF_REPO_SCOPES = frozenset({"import", "ancestor", "enterprise", "managed_memory"})

# Массовое исчезновение группируем в одну находку (анти-шум) — как у скиллов.
_REMOVAL_GROUP_THRESHOLD = 3


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _human_scope(scope: str) -> str:
    return {
        "enterprise": "управляемая политика организации",
        "user": "пользовательский ~/.claude/CLAUDE.md",
        "project": "проектный CLAUDE.md",
        "project_local": "локальный CLAUDE.local.md",
        "subdir": "CLAUDE.md во вложенном каталоге",
        "ancestor": "CLAUDE.md выше корня проекта (вне репозитория)",
        "import": "файл, притянутый через @import",
        "rules": "правило в .claude/rules/",
        "output_style": "стиль вывода (расширяет системный промпт)",
        "managed_memory": "инструкция в managed-settings.json (политика организации)",
        # Носители инструкций Cursor (agent_kind=cursor).
        "cursor_rules": "правило Cursor (.cursor/rules)",
        "cursor_legacy": "legacy .cursorrules (Cursor)",
        "agents_md": "AGENTS.md (кросс-инструментальные инструкции агенту)",
    }.get(scope, scope)


def _make_finding(
    *, machine_id: str, inventory_id: int | None, rule_id: str,
    severity: str, title: str, description: str, payload: dict,
) -> FindingRecord:
    payload_full = {
        "rule_id": rule_id, "severity": severity,
        "title": title, "description": description, **payload,
    }
    return FindingRecord(
        machine_id=machine_id, inventory_id=inventory_id, rule_id=rule_id,
        severity=severity, discovered_at=_now(),
        payload_json=json.dumps(payload_full, ensure_ascii=False),
    )


def update_and_detect(
    session: Session,
    machine_id: str,
    current_memory: list[MemoryEntry],
    *,
    inventory_id: int | None = None,
) -> list[FindingRecord]:
    """Свести пришедшие файлы памяти с эталоном. Мутирует сессию."""
    now = _now()
    findings: list[FindingRecord] = []
    seen_paths: set[str] = set()

    # Bootstrap: если у машины ещё нет ни одной принятой строки — это первый
    # контакт, всё заводим тихо (pending). Иначе первое подключение машины,
    # где память уже есть, породило бы десяток находок на пустом месте.
    has_active = session.exec(
        select(MemoryBaseline)
        .where(MemoryBaseline.machine_id == machine_id, MemoryBaseline.status == "active")
        .limit(1)
    ).first() is not None

    for mem in current_memory:
        seen_paths.add(mem.path)
        existing = session.exec(
            select(MemoryBaseline).where(
                MemoryBaseline.machine_id == machine_id,
                MemoryBaseline.path == mem.path,
            )
        ).one_or_none()

        if existing is not None and existing.content_hash == mem.content_hash:
            existing.last_seen_at = now
            existing.scope = mem.scope
            existing.imported_by = mem.imported_by
            if existing.status == "missing":
                existing.status = "active"  # тихое возвращение
            session.add(existing)
            continue

        if existing is None:
            session.add(MemoryBaseline(
                machine_id=machine_id, path=mem.path, scope=mem.scope,
                content_hash=mem.content_hash, size_bytes=mem.size_bytes,
                imported_by=mem.imported_by, status="pending",
                first_seen_at=now, last_seen_at=now,
            ))
            if has_active:
                off_repo = mem.scope in _OFF_REPO_SCOPES
                findings.append(_make_finding(
                    machine_id=machine_id, inventory_id=inventory_id,
                    rule_id="memory.external" if off_repo else "memory.new",
                    severity="warn",
                    title=(
                        f"Новый файл инструкций вне репозитория ({_human_scope(mem.scope)})"
                        if off_repo else
                        f"Новый файл инструкций агента ({_human_scope(mem.scope)})"
                    ),
                    description=(
                        f"Появился {_human_scope(mem.scope)}: {mem.path}. "
                        + (
                            "Он вне того, что ревьюят в репозитории — "
                            "инструкцию отсюда никто не увидит в code review. "
                            if off_repo else
                            "Это прямые инструкции агенту. "
                        )
                        + "Если ты добавил его сам — прими baseline; если нет — "
                        "проверь содержимое: там может быть закладка."
                        + (f" Притянут из: {mem.imported_by}." if mem.imported_by else "")
                    ),
                    payload={
                        "path": mem.path, "scope": mem.scope,
                        "imported_by": mem.imported_by, "size_bytes": mem.size_bytes,
                    },
                ))
            continue

        # Слот есть, отпечаток изменился → дрейф содержимого.
        findings.append(_make_finding(
            machine_id=machine_id, inventory_id=inventory_id,
            rule_id="memory.drift", severity="warn",
            title=f"Изменился файл инструкций агента ({_human_scope(existing.scope)})",
            description=(
                f"Содержимое {mem.path} изменилось. Память — это прямые "
                "инструкции агенту; посмотри diff. Если правил сам — прими "
                "новый baseline, иначе проверь, не добавлена ли закладка."
            ),
            payload={
                "path": mem.path, "scope": mem.scope,
                "old_hash": existing.content_hash, "new_hash": mem.content_hash,
                "imported_by": mem.imported_by,
            },
        ))
        existing.content_hash = mem.content_hash
        existing.size_bytes = mem.size_bytes
        existing.scope = mem.scope
        existing.imported_by = mem.imported_by
        existing.last_seen_at = now
        session.add(existing)

    # Обратная совместимость важнее полноты детекта удаления: агент v0.1/v0.2
    # памяти не шлёт вовсе, и для сервера это неотличимо от «всё удалили».
    # Если список пуст — НЕ реконсилим исчезновения, иначе каждый sync старого
    # агента ронял бы всю принятую память в missing и спамил memory.removed.
    # Цена: удаление сразу ВСЕХ файлов памяти на новом агенте мы не поймаем в
    # тот же тик — но это редкость, а как только вернётся хоть один файл,
    # разница вскроется. Мягкая деградация тут дороже редкого сигнала.
    if not current_memory:
        for f in findings:
            session.add(f)
        return findings

    # Исчезнувшие: принятый файл памяти пропал. Тихо помечаем missing, но
    # массовое исчезновение сворачиваем в одну находку.
    all_rows = session.exec(
        select(MemoryBaseline).where(MemoryBaseline.machine_id == machine_id)
    ).all()
    removed: list[MemoryBaseline] = []
    for r in all_rows:
        if r.path not in seen_paths and r.status not in ("missing", "removed"):
            if r.status == "active":
                removed.append(r)
            r.status = "missing"
            session.add(r)

    if len(removed) > _REMOVAL_GROUP_THRESHOLD:
        findings.append(_make_finding(
            machine_id=machine_id, inventory_id=inventory_id,
            rule_id="memory.removed", severity="warn",
            title=f"Исчезло {len(removed)} принятых файлов памяти",
            description=(
                f"{len(removed)} принятых файлов инструкций пропали за один sync. "
                "Возможно законная чистка, но проверить стоит."
            ),
            payload={"removed_count": len(removed)},
        ))
    else:
        for r in removed:
            findings.append(_make_finding(
                machine_id=machine_id, inventory_id=inventory_id,
                rule_id="memory.removed", severity="warn",
                title="Принятый файл памяти исчез",
                description=(
                    f"Файл инструкций {r.path} был принят в baseline, но пропал "
                    "из конфигурации."
                ),
                payload={"path": r.path, "scope": r.scope},
            ))

    for f in findings:
        session.add(f)
    return findings


# --- Принять / отклонить ----------------------------------------------------


def accept_baseline(
    session: Session, machine_id: str, baseline_id: int, accepting_user: str
) -> MemoryBaseline:
    row = session.exec(
        select(MemoryBaseline).where(
            MemoryBaseline.id == baseline_id,
            MemoryBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(f"MemoryBaseline id={baseline_id} machine={machine_id} not found")
    row.status = "active"
    row.accepted_at = _now()
    row.accepted_by = accepting_user
    session.add(row)
    return row


def accept_all_pending(session: Session, machine_id: str, accepting_user: str) -> int:
    rows = session.exec(
        select(MemoryBaseline).where(
            MemoryBaseline.machine_id == machine_id,
            MemoryBaseline.status == "pending",
        )
    ).all()
    now = _now()
    for r in rows:
        r.status = "active"
        r.accepted_at = now
        r.accepted_by = accepting_user
        session.add(r)
    return len(rows)


def reject_and_mark(session: Session, machine_id: str, baseline_id: int) -> MemoryBaseline:
    row = session.exec(
        select(MemoryBaseline).where(
            MemoryBaseline.id == baseline_id,
            MemoryBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(f"MemoryBaseline id={baseline_id} machine={machine_id} not found")
    row.status = "removed"
    session.add(row)
    return row
