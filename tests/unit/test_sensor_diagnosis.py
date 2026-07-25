"""Диагностика: почему сенсор замолчал.

Главная ценность — отличать «сняли защиту» от «ноутбук выключен». Раньше это
выглядело одинаково, и оператору приходилось разбираться вручную с каждым
случаем тишины; так тревоги и начинают игнорировать.

Отдельно проверяется обратное: обычные ситуации НЕ должны требовать
разбирательства, иначе список «требует внимания» станет бесполезным.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import Machine, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import sensor_diagnosis as sd


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _machine(s, mid="m1", *, hb_minutes_ago=1, hooks_intact=True,
             hooks_hash="h1", baseline="h1", interval=900):
    now = datetime.now(UTC).replace(tzinfo=None)
    hb = None if hb_minutes_ago is None else now - timedelta(minutes=hb_minutes_ago)
    s.add(Machine(machine_id=mid, machine_label=mid, first_seen=now, last_seen=now,
                  agent_version="0.3", last_heartbeat_at=hb,
                  expected_interval_sec=interval, hooks_intact=hooks_intact,
                  hooks_hash=hooks_hash, hooks_hash_baseline=baseline))
    s.commit()
    return s.get(Machine, mid)


def _event(s, mid="m1", minutes_ago=5):
    s.add(ToolUseEvent(machine_id=mid, ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
          tool_name="Bash", fingerprint="a"*16, decision="allow", result_status="success",
          signals_json=json.dumps([])))
    s.commit()


# --- прямые улики: машина сама доложила ------------------------------------


def test_hooks_removed_is_direct_evidence():
    # Машина на связи и говорит «хуков нет» — выводить это косвенно не нужно.
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hooks_intact=False)
        d = sd.diagnose(s, m)
    assert d.state == sd.HOOKS_REMOVED
    assert d.protected is False
    assert d.needs_review is True


def test_hooks_hash_drift_detected():
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hooks_hash="новый", baseline="старый")
        d = sd.diagnose(s, m)
    assert d.state == sd.HOOKS_CHANGED
    assert d.needs_review is True


def test_removed_beats_drift_when_both():
    # Если хуков нет вообще — это важнее расхождения отпечатка.
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hooks_intact=False, hooks_hash="x", baseline="y")
        assert sd.diagnose(s, m).state == sd.HOOKS_REMOVED


# --- различение по двум источникам жизни ------------------------------------


def test_daemon_down_but_hooks_alive():
    # Сигнала нет, но события идут: служба упала, защита действует.
    # Это принципиально мягче, чем «машина ушла из-под наблюдения».
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hb_minutes_ago=600)   # молчит давно
        _event(s, minutes_ago=5)              # но агентом пользуются
        d = sd.diagnose(s, m)
    assert d.state == sd.DAEMON_DOWN
    assert d.protected is True     # хуки живы — блокировка работает
    assert d.needs_review is True  # но чинить надо


def test_offline_when_no_signal_at_all():
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hb_minutes_ago=600)
        d = sd.diagnose(s, m)
    assert d.state == sd.OFFLINE
    assert d.protected is False


def test_offline_detail_admits_ambiguity():
    # Честность: снаружи нельзя отличить выключенный ноутбук от снесённого
    # агента, и диагноз обязан это признавать, а не выдумывать уверенность.
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hb_minutes_ago=600)
        d = sd.diagnose(s, m)
    assert "нельзя" in d.detail.lower() or "различить" in d.detail.lower()


# --- норма не должна шуметь --------------------------------------------------


def test_healthy_machine_is_ok():
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s)
        _event(s)
        d = sd.diagnose(s, m)
    assert d.state == sd.OK
    assert d.protected is True
    assert d.needs_review is False


def test_idle_machine_is_not_an_incident():
    # Сигнал идёт, событий нет — человек просто не работал с агентом.
    # Поднимать тревогу здесь означало бы приучить её игнорировать.
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s)
        d = sd.diagnose(s, m)
    assert d.state == sd.IDLE
    assert d.protected is True
    assert d.needs_review is False


def test_never_reported_is_not_alertable():
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hb_minutes_ago=None)
        d = sd.diagnose(s, m)
    assert d.state == sd.UNKNOWN
    assert d.needs_review is False


def test_stale_but_within_grace_still_ok():
    # Перезагрузка или короткая пауза не должны считаться потерей защиты.
    eng = _engine()
    with Session(eng) as s:
        m = _machine(s, hb_minutes_ago=20, interval=900)  # чуть просрочено
        _event(s)
        d = sd.diagnose(s, m)
    assert d.protected is True
    assert d.needs_review is False


# --- сводка по флоту ---------------------------------------------------------


def test_fleet_sorted_unprotected_first():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "здоровая")
        _event(s, "здоровая")
        _machine(s, "снятая", hooks_intact=False)
        rows = sd.diagnose_fleet(s)
    assert rows[0].machine_id == "снятая"   # без защиты — первой


def test_fleet_summary_counts():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "a")
        _event(s, "a")
        _machine(s, "b", hooks_intact=False)
        _machine(s, "c", hb_minutes_ago=600)
        summary = sd.fleet_summary(s)
    assert summary["total"] == 3
    assert summary["protected"] == 1
    assert summary["unprotected"] == 2
    assert summary["needs_review"] == 2
