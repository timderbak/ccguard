"""Почему сенсор замолчал: снятие защиты или обычная пауза.

Обнаружение тишины (``sensor_health_service``) отвечает на вопрос «замолчал ли»,
но не на вопрос «почему». А для работы это разные вещи: выключенный на выходные
ноутбук и машина, с которой сняли хуки, выглядят одинаково — просто нет сигнала.
Разбирать вручную каждую тишину невозможно, а игнорировать нельзя, потому что
именно так выглядит попытка уйти из-под наблюдения.

Различение строится на том, что у нас **два независимых источника жизни**:

* сигнал демона — фоновая служба раз в N минут говорит «я жив» и заодно
  докладывает, на месте ли хуки и совпадает ли их отпечаток с эталоном;
* события хука аудита — приходят, только когда человек реально работает
  с агентом.

Они отказывают по-разному, и это даёт диагноз:

    сигнал  события   вывод
    -----------------------------------------------------------------
    есть    есть      всё работает
    есть    нет       агент просто не использовали (это НОРМА, не инцидент)
    нет     есть      демон мёртв, но хуки живы — защита работает частично
    нет     нет       машина не работает ИЛИ снесли всё

Отдельно и важнее всего: если сигнал ЕСТЬ и в нём сказано, что хуки не на месте
или их отпечаток разошёлся с эталоном — это прямая улика, а не догадка. Такой
случай не надо выводить косвенно, машина сама о нём доложила.

Диагноз не заменяет находку о тишине, а объясняет её: он нужен, чтобы у
оператора на карточке машины было «демон упал, хуки целы», а не «нет сигнала».
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import Machine, ToolUseEvent
from ccguard.server.services.sensor_health_service import lifecycle_state

log = logging.getLogger(__name__)

# Диагнозы. Строки, а не перечисление, — они уезжают в интерфейс и в отчёты.
OK = "ok"                          # всё на месте
IDLE = "idle"                      # сигнал идёт, агентом просто не пользуются
HOOKS_REMOVED = "hooks_removed"    # машина сама доложила: хуков нет
HOOKS_CHANGED = "hooks_changed"    # отпечаток хуков разошёлся с эталоном
DAEMON_DOWN = "daemon_down"        # сигнала нет, но события идут — служба упала
OFFLINE = "offline"                # ни сигнала, ни событий — выключена или снесена
UNKNOWN = "unknown"                # никогда не отчитывалась (старый агент)

# Насколько назад смотрим на события хука аудита, решая «работал ли агент».
# Берём с запасом относительно окна тишины: короткое окно дало бы «демон упал»
# на машине, где человек просто ушёл на обед.
_ACTIVITY_WINDOW_HOURS = 6.0


@dataclass(frozen=True)
class Diagnosis:
    """Диагноз состояния защиты на одной машине."""

    machine_id: str
    state: str          # см. константы выше
    title: str          # короткая формулировка для интерфейса
    detail: str         # что именно произошло и что это значит
    protected: bool     # действует ли защита прямо сейчас
    needs_review: bool  # требует ли разбирательства человеком
    last_heartbeat_at: datetime | None = None
    last_event_at: datetime | None = None


def _last_event_at(session: Session, machine_id: str, since: datetime) -> datetime | None:
    """Когда последний раз приходило событие от хука аудита."""
    row = session.exec(
        select(ToolUseEvent.ts)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .order_by(ToolUseEvent.ts.desc())  # type: ignore[attr-defined]
        .limit(1)
    ).first()
    return row


def diagnose(session: Session, machine: Machine, *, now: datetime | None = None) -> Diagnosis:
    """Определить, почему машина в текущем состоянии."""
    now = now or datetime.now(UTC)
    state = lifecycle_state(session, machine, now)
    since = now - timedelta(hours=_ACTIVITY_WINDOW_HOURS)
    last_event = _last_event_at(session, machine.machine_id, since)
    hb = machine.last_heartbeat_at

    def _mk(st: str, title: str, detail: str, *, protected: bool, review: bool) -> Diagnosis:
        return Diagnosis(
            machine_id=machine.machine_id, state=st, title=title, detail=detail,
            protected=protected, needs_review=review,
            last_heartbeat_at=hb, last_event_at=last_event,
        )

    # 1. Прямая улика важнее любых косвенных выводов: машина сама доложила, что
    # хуков нет или они изменились. Догадываться не нужно.
    if machine.hooks_intact is False:
        return _mk(
            HOOKS_REMOVED, "Хуки сняты",
            "Машина на связи и сама сообщила, что хуки ccguard не установлены. "
            "Снять их можно только осознанно — случайно так не происходит.",
            protected=False, review=True,
        )
    if (
        machine.hooks_hash_baseline
        and machine.hooks_hash
        and machine.hooks_hash != machine.hooks_hash_baseline
    ):
        return _mk(
            HOOKS_CHANGED, "Хуки изменены",
            "Отпечаток набора хуков разошёлся с эталоном: конфигурацию правили. "
            "Возможно легитимно (обновление), но проверить нужно.",
            protected=False, review=True,
        )

    # 2. Никогда не отчитывалась — старый агент либо ещё не дошла первая связь.
    if state == "unknown":
        return _mk(
            UNKNOWN, "Нет данных",
            "Машина ни разу не присылала сигнал о работе. Либо агент старой "
            "версии, либо установка не завершена.",
            protected=False, review=False,
        )

    # 3. Сигнал идёт — защита на месте. Отсутствие событий здесь НЕ проблема:
    # человек мог просто не пользоваться агентом, и поднимать из-за этого
    # тревогу означало бы приучить оператора её игнорировать.
    if state in ("active", "stale"):
        if last_event is None:
            return _mk(
                IDLE, "Защита работает, агент не используется",
                "Сигнал приходит, хуки на месте. Событий нет — значит агентом "
                "в этот период просто не работали.",
                protected=True, review=False,
            )
        return _mk(
            OK, "Защита работает", "Сигнал приходит, события поступают.",
            protected=True, review=False,
        )

    # 4. Сигнала нет. Различаем по второму источнику: если события от хука
    # аудита продолжают идти — значит хуки живы, а упала фоновая служба.
    # Это существенно мягче, чем «машина ушла из-под наблюдения».
    if last_event is not None:
        return _mk(
            DAEMON_DOWN, "Фоновая служба не отвечает",
            "Сигнал о работе не приходит, но события от хуков поступают: "
            "хуки живы и блокировка действует, перестала работать служба "
            "синхронизации. Инвентаризация машины устаревает.",
            protected=True, review=True,
        )
    return _mk(
        OFFLINE, "Машина не на связи",
        "Нет ни сигнала, ни событий. Машина выключена, вне сети — либо агент "
        "удалён целиком. Различить снаружи нельзя: нужен ответ владельца.",
        protected=False, review=True,
    )


def diagnose_fleet(session: Session, *, now: datetime | None = None) -> list[Diagnosis]:
    """Диагноз по всем машинам. Требующие разбирательства — первыми."""
    out = [diagnose(session, m, now=now) for m in session.exec(select(Machine))]
    # Порядок: сначала то, где защита не действует, потом то, что требует
    # внимания, затем остальное — оператор читает сверху вниз.
    out.sort(key=lambda d: (d.protected, not d.needs_review, d.machine_id))
    return out


def fleet_summary(session: Session, *, now: datetime | None = None) -> dict[str, object]:
    """Сводка для верхнего уровня: сколько машин под защитой и сколько нет."""
    rows = diagnose_fleet(session, now=now)
    return {
        "total": len(rows),
        "protected": sum(1 for d in rows if d.protected),
        "unprotected": sum(1 for d in rows if not d.protected),
        "needs_review": sum(1 for d in rows if d.needs_review),
        "by_state": {
            st: sum(1 for d in rows if d.state == st)
            for st in (OK, IDLE, HOOKS_REMOVED, HOOKS_CHANGED, DAEMON_DOWN, OFFLINE, UNKNOWN)
            if any(d.state == st for d in rows)
        },
    }
