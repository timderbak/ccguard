"""Личность агента: работа без подтверждений человеком.

Claude Code сообщает в каждом вызове хука режим прав (``permission_mode``).
Два его значения означают, что человек НЕ подтверждает действия:

* ``bypassPermissions`` — проверки прав отключены полностью;
* ``dontAsk`` — агент не спрашивает подтверждений.

Ключевое решение против ложных срабатываний: **сам по себе такой режим не
является находкой**. Это законный рабочий режим — в CI, в пакетных прогонах, в
автоматизации. Алерт на каждое его включение — гарантированный шум, а шум
приводит к тому, что алерты начинают игнорировать.

Находка возникает только на СОВПАДЕНИИ двух условий: агент работал без
подтверждений И в этом режиме выполнил что-то заведомо опасное. Разница
принципиальная: «разработчик гоняет сборку в автоматическом режиме» — это норма,
а «в автоматическом режиме прочитаны ключи и следом ушёл сетевой запрос» — это
то, что человек не одобрял и, скорее всего, даже не видел.

Опасность действия не задаётся отдельным списком: берутся веса из
``risk_constants.DEFAULT_WEIGHTS`` — той же шкалы, по которой считается риск
машины. Так порог остаётся в одном месте, и добавление нового сигнала в каталог
автоматически учитывается здесь.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.services.risk_constants import DEFAULT_WEIGHTS
from ccguard.server.services.settings_service import get_setting

log = logging.getLogger(__name__)

RULE_ID = "identity.unattended_risk"
SEVERITY = "warn"

# Режимы, в которых человек не подтверждает действия агента.
UNATTENDED_MODES: frozenset[str] = frozenset({"bypassPermissions", "dontAsk"})

# Порог «опасности» по общей шкале весов риска. 4.0 и выше — это доступ к
# учётным данным, эксфильтрация, разрушающие операции; сборка, чтение файлов и
# разведка остаются ниже и в одиночку находку не порождают.
DANGEROUS_WEIGHT_THRESHOLD = 4.0

SETTING_WINDOW_HOURS = "identity.unattended.window_hours"
DEFAULT_WINDOW_HOURS = 24.0


def dangerous_signal_ids() -> frozenset[str]:
    """Сигналы, которые считаются опасными в режиме без подтверждений.

    Считается от общей шкалы весов, а не отдельным списком — новый сигнал в
    каталоге с высоким весом попадает сюда сам, без правки этого модуля.
    """
    return frozenset(
        sid for sid, weight in DEFAULT_WEIGHTS.items() if weight >= DANGEROUS_WEIGHT_THRESHOLD
    )


def is_unattended(permission_mode: str | None) -> bool:
    """True, если в этом режиме человек не подтверждает действия.

    ``None`` (агент версии, которая не сообщает режим) осознанно считается
    «не подтверждено обратное» → False. Иначе весь парк старых агентов разом
    подсветился бы как работающий без надзора, что неправда.
    """
    return permission_mode in UNATTENDED_MODES


def _window_hours(session: Session) -> float:
    raw = get_setting(session, SETTING_WINDOW_HOURS)
    if raw is None:
        return DEFAULT_WINDOW_HOURS
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_WINDOW_HOURS
    return val if val > 0 else DEFAULT_WINDOW_HOURS


def _same_day_finding_exists(session: Session, machine_id: str, now: datetime) -> bool:
    """Одна находка на машину в сутки — как у остальных корреляторов."""
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == RULE_ID)
        .where(func.date(FindingRecord.discovered_at) == now.date().isoformat())
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _signals_of(event: ToolUseEvent) -> list[str]:
    try:
        data = json.loads(event.signals_json or "[]")
    except (ValueError, TypeError):
        return []
    return [s for s in data if isinstance(s, str)] if isinstance(data, list) else []


def evaluate_one(session: Session, machine_id: str) -> FindingRecord | None:
    """Находка, если на машине в режиме без подтверждений выполнялись опасные
    действия. Возвращает её либо None."""
    window = _window_hours(session)
    now = datetime.now(UTC)
    since = now - timedelta(hours=window)

    stmt = (
        select(ToolUseEvent)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .where(ToolUseEvent.permission_mode.in_(tuple(UNATTENDED_MODES)))  # type: ignore[attr-defined]
    )
    events = list(session.exec(stmt))
    if not events:
        return None

    dangerous = dangerous_signal_ids()
    hits: list[tuple[ToolUseEvent, list[str]]] = []
    for e in events:
        matched = [s for s in _signals_of(e) if s in dangerous]
        if matched:
            hits.append((e, matched))
    if not hits:
        # Режим без подтверждений сам по себе — не находка (см. модуль-докстринг).
        return None
    if _same_day_finding_exists(session, machine_id, now):
        return None

    signal_counts = Counter(s for _, matched in hits for s in matched)
    modes = sorted({e.permission_mode for e, _ in hits if e.permission_mode})
    actors = sorted({e.actor_user for e, _ in hits if e.actor_user})
    first_at = min(e.ts for e, _ in hits)
    last_at = max(e.ts for e, _ in hits)

    payload = {
        "modes": modes,
        "actors": actors,
        "events": len(hits),
        "signals": dict(signal_counts.most_common()),
        "window_hours": window,
        "first_at": first_at.isoformat(),
        "last_at": last_at.isoformat(),
        "narrative": (
            f"Агент выполнял опасные действия ({', '.join(sorted(signal_counts))}) "
            f"в режиме без подтверждений человеком ({', '.join(modes)}). "
            "Такие действия человек не одобрял поштучно и, скорее всего, не видел."
        ),
        "recommendation": (
            "Проверь, кто и зачем запустил агента в этом режиме. Для CI это "
            "нормально; на рабочей машине — повод убедиться, что это осознанно."
        ),
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=RULE_ID,
        severity=SEVERITY,
        discovered_at=now,
        payload_json=json.dumps(payload, ensure_ascii=False, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, object]:
    """Обход всех машин. Одна упавшая машина не ломает остальные."""
    machines = list(session.exec(select(Machine)))
    emitted = 0
    errors: list[str] = []
    for m in machines:
        try:
            if evaluate_one(session, m.machine_id) is not None:
                emitted += 1
        except Exception as exc:  # noqa: BLE001 — изоляция границы намеренная
            try:
                session.rollback()
            except Exception:  # noqa: BLE001
                pass
            errors.append(f"{m.machine_id}: {exc}")
            log.warning("identity tick error: %s", errors[-1])
    return {"machines_evaluated": len(machines), "findings_emitted": emitted, "errors": errors}


def fleet_permission_summary(session: Session, *, days: int = 7) -> dict[str, object]:
    """Сводка по флоту: в каких режимах работают агенты.

    Отвечает на вопрос, который задаёт руководитель ИБ первым: «сколько наших
    машин работают с отключёнными подтверждениями». Машина попадает в
    ``unattended_machines``, если хотя бы одно её событие за период пришло в
    таком режиме.
    """
    since = datetime.now(UTC) - timedelta(days=days)
    rows = list(
        session.exec(
            select(
                ToolUseEvent.machine_id,
                ToolUseEvent.permission_mode,
                func.count().label("n"),  # type: ignore[arg-type]
            )
            .where(ToolUseEvent.ts >= since)
            .group_by(ToolUseEvent.machine_id, ToolUseEvent.permission_mode)
        )
    )
    by_mode: Counter[str] = Counter()
    unattended: set[str] = set()
    known: set[str] = set()
    all_machines: set[str] = set()
    for machine_id, mode, n in rows:
        all_machines.add(machine_id)
        if not mode:
            continue  # агент не сообщает режим — не «без подтверждений», а «неизвестно»
        known.add(machine_id)
        by_mode[mode] += int(n)
        if is_unattended(mode):
            unattended.add(machine_id)
    return {
        "machines_total": len(all_machines),
        "machines_reporting_mode": len(known),
        "unattended_machines": sorted(unattended),
        "unattended_count": len(unattended),
        "events_by_mode": dict(by_mode.most_common()),
        "days": days,
    }


def agent_type_summary(session: Session, *, days: int = 7) -> list[dict[str, object]]:
    """Какие субагенты действовали по флоту и на скольких машинах.

    ``agent_type`` приходит только внутри субагента, поэтому события основного
    агента сюда не попадают — это список именно делегированных исполнителей.
    """
    since = datetime.now(UTC) - timedelta(days=days)
    rows = list(
        session.exec(
            select(
                ToolUseEvent.agent_type,
                func.count(func.distinct(ToolUseEvent.machine_id)).label("machines"),
                func.count().label("events"),  # type: ignore[arg-type]
            )
            .where(ToolUseEvent.ts >= since)
            .where(ToolUseEvent.agent_type.is_not(None))  # type: ignore[attr-defined]
            .group_by(ToolUseEvent.agent_type)
        )
    )
    out = [
        {"agent_type": r[0], "machines": int(r[1]), "events": int(r[2])}
        for r in rows
        if r[0]
    ]
    out.sort(key=lambda d: (-int(d["events"]), str(d["agent_type"])))
    return out
