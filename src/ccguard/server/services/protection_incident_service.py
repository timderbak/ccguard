"""Процесс разбора: машина без защиты → объяснение → вердикт.

Диагноз показывает состояние на сейчас, и этого не хватает. Состояние живёт
минуты: человек снял хуки, поработал, вернул — и на экране снова всё зелёное.
А вопрос «почему сняли» живёт неделями и адресован человеку, а не машине.

Поэтому наблюдение фиксируется в эпизод и дальше идёт по шагам:

    открыт  →  объяснён  →  принят / отклонён
    (ждём     (владелец    (ИБ вынесла
     ответа)   ответил)     вердикт)

Два решения, на которых всё держится:

1. **Возврат защиты не закрывает эпизод.** Иначе самая интересная
   последовательность — снял, сделал, вернул — стиралась бы сама собой, и
   спрашивать пришлось бы только тех, кто забыл вернуть. Возврат отмечается
   (``recovered_at``) и понижает срочность, но ответить всё равно нужно.

2. **Один открытый эпизод на машину.** Пока эпизод не разобран, новые
   наблюдения обновляют его, а не создают ещё один. Иначе выключенный на
   неделю ноутбук дал бы сотню одинаковых «инцидентов», и список перестали бы
   читать.

Эпизоды открываются только на то, что диагноз пометил как требующее разбора
(``needs_review``). Простой машины и неизвестное состояние старого агента сюда
не попадают: они не являются событием, за которое кто-то отвечает.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.server.db.models import ProtectionIncident
from ccguard.server.services import sensor_diagnosis

log = logging.getLogger(__name__)

# Статусы эпизода. Первые два — работа не закончена, последние два — закрыт.
OPEN = "open"
EXPLAINED = "explained"
ACCEPTED = "accepted"
REJECTED = "rejected"

_UNRESOLVED = (OPEN, EXPLAINED)


class NotFound(Exception):
    """Эпизода с таким номером нет."""


class AlreadyClosed(Exception):
    """Вердикт уже вынесен — переписывать его нельзя."""


def _now() -> datetime:
    return datetime.now(UTC)


def open_for_machine(session: Session, machine_id: str) -> ProtectionIncident | None:
    """Незакрытый эпизод машины, если он есть."""
    return session.exec(
        select(ProtectionIncident)
        .where(ProtectionIncident.machine_id == machine_id)
        .where(ProtectionIncident.status.in_(_UNRESOLVED))  # type: ignore[attr-defined]
        .order_by(ProtectionIncident.opened_at.desc())  # type: ignore[attr-defined]
        .limit(1)
    ).first()


def sync(session: Session, *, now: datetime | None = None) -> dict[str, object]:
    """Свести диагнозы флота с эпизодами: открыть новые, обновить текущие.

    Вызывается фоновым тиком. Ничего не закрывает: закрытие — это решение
    человека, а не следствие того, что машина снова вышла на связь.
    """
    now = now or _now()
    opened = 0
    updated = 0
    recovered = 0
    errors: list[str] = []

    for d in sensor_diagnosis.diagnose_fleet(session, now=now):
        try:
            existing = open_for_machine(session, d.machine_id)
            if d.needs_review:
                if existing is None:
                    session.add(
                        ProtectionIncident(
                            machine_id=d.machine_id, state=d.state, opened_at=now,
                            opened_title=d.title, opened_detail=d.detail,
                            last_state=d.state, last_checked_at=now,
                        )
                    )
                    opened += 1
                    continue
                # Эпизод мог «переехать»: сняли хуки → машина вовсе исчезла.
                # Это тот же разбор, но оператору важно видеть свежую картину.
                existing.last_state = d.state
                existing.last_checked_at = now
                # Защита была потеряна и снова потеряна — отметку о возврате
                # снимаем, иначе эпизод выглядел бы благополучнее, чем есть.
                existing.recovered_at = None
                session.add(existing)
                updated += 1
            elif existing is not None and d.protected and existing.recovered_at is None:
                # Защита вернулась. Эпизод НЕ закрываем — ответить всё равно
                # нужно, — но фиксируем момент и снижаем срочность.
                existing.recovered_at = now
                existing.last_state = d.state
                existing.last_checked_at = now
                session.add(existing)
                recovered += 1
        except Exception as exc:  # noqa: BLE001 — тик не должен падать целиком
            try:
                session.rollback()
            except Exception:  # noqa: BLE001
                pass
            errors.append(f"{d.machine_id}: {exc}")
            log.warning("protection sync error: %s", errors[-1])

    if opened or updated or recovered:
        session.commit()
    return {
        "opened": opened, "updated": updated,
        "recovered": recovered, "errors": errors,
    }


def tick(session: Session) -> dict[str, object]:
    """Точка входа для планировщика."""
    return sync(session)


def explain(
    session: Session, incident_id: int, *, text: str, who: str | None
) -> ProtectionIncident:
    """Записать объяснение причины. Переводит эпизод в «ждёт вердикта»."""
    inc = session.get(ProtectionIncident, incident_id)
    if inc is None:
        raise NotFound(str(incident_id))
    if inc.status in (ACCEPTED, REJECTED):
        raise AlreadyClosed(str(incident_id))
    text = (text or "").strip()
    if not text:
        raise ValueError("пустое объяснение")
    # Объяснение можно уточнить, пока вердикта нет: первая формулировка часто
    # неполная, и заставлять заводить новый эпизод ради правки бессмысленно.
    inc.explanation = text[:4000]
    inc.explained_by = who
    inc.explained_at = _now()
    inc.status = EXPLAINED
    session.add(inc)
    session.commit()
    session.refresh(inc)
    return inc


def review(
    session: Session, incident_id: int, *, accept: bool, who: str | None,
    note: str | None = None,
) -> ProtectionIncident:
    """Вынести вердикт по объяснению — это и закрывает эпизод.

    Отклонение тоже закрывает: смысл не в том, чтобы эпизод висел вечно, а в
    том, чтобы решение было записано и подписано. Отклонённые остаются в
    отчёте отдельной строкой — именно они интересны при разборе постфактум.
    """
    inc = session.get(ProtectionIncident, incident_id)
    if inc is None:
        raise NotFound(str(incident_id))
    if inc.status in (ACCEPTED, REJECTED):
        raise AlreadyClosed(str(incident_id))
    inc.status = ACCEPTED if accept else REJECTED
    inc.reviewed_by = who
    inc.reviewed_at = _now()
    inc.review_note = (note or "").strip()[:1000] or None
    session.add(inc)
    session.commit()
    session.refresh(inc)
    return inc


def list_incidents(
    session: Session, *, unresolved_only: bool = True, limit: int = 200
) -> list[ProtectionIncident]:
    """Эпизоды для страницы разбора. Неразобранные — первыми."""
    stmt = select(ProtectionIncident)
    if unresolved_only:
        stmt = stmt.where(ProtectionIncident.status.in_(_UNRESOLVED))  # type: ignore[attr-defined]
    rows = list(session.exec(stmt.order_by(ProtectionIncident.opened_at.desc()).limit(limit)))  # type: ignore[attr-defined]
    # Порядок: ждут ответа → ждут вердикта → закрытые. Внутри — свежие сверху.
    order = {OPEN: 0, EXPLAINED: 1, REJECTED: 2, ACCEPTED: 3}
    rows.sort(key=lambda r: (order.get(r.status, 9), r.recovered_at is not None))
    return rows


def summary(session: Session) -> dict[str, int]:
    """Сводка для шапки страницы и для отчёта."""
    rows = list(session.exec(select(ProtectionIncident)))
    return {
        "total": len(rows),
        "awaiting_explanation": sum(1 for r in rows if r.status == OPEN),
        "awaiting_review": sum(1 for r in rows if r.status == EXPLAINED),
        "accepted": sum(1 for r in rows if r.status == ACCEPTED),
        "rejected": sum(1 for r in rows if r.status == REJECTED),
        # Незакрытые эпизоды, где защита так и не вернулась, — самое срочное.
        "still_unprotected": sum(
            1 for r in rows if r.status in _UNRESOLVED and r.recovered_at is None
        ),
    }
