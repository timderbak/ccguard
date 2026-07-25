"""Детект работы агента без подтверждений человеком.

Главное свойство, которое здесь проверяется, — анти-ложные-срабатывания: сам по
себе режим ``bypassPermissions``/``dontAsk`` находкой НЕ является. Это законный
режим для CI и пакетных прогонов, и алерт на каждое его включение превратился бы
в шум. Находка возникает только когда в таком режиме выполнено что-то заведомо
опасное.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import identity_service as svc


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _machine(s: Session, mid: str = "m1") -> str:
    now = datetime.now(UTC).replace(tzinfo=None)
    s.add(Machine(machine_id=mid, machine_label=mid, first_seen=now, last_seen=now,
                  agent_version="0.3.0"))
    s.commit()
    return mid


def _event(s: Session, mid: str, *, signals=None, mode=None, actor="alice",
           minutes_ago: int = 5, agent_type=None) -> None:
    s.add(ToolUseEvent(
        machine_id=mid,
        ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        tool_name="Bash", fingerprint="a" * 16, decision="allow", result_status="success",
        signals_json=json.dumps(signals or []),
        actor_user=actor, permission_mode=mode, agent_type=agent_type,
    ))
    s.commit()


# --- что считается «без подтверждений» --------------------------------------


def test_unattended_modes_recognized():
    assert svc.is_unattended("bypassPermissions") is True
    assert svc.is_unattended("dontAsk") is True


def test_normal_modes_not_unattended():
    for mode in ("default", "plan", "acceptEdits", "auto"):
        assert svc.is_unattended(mode) is False


def test_missing_mode_is_not_unattended():
    # Старый агент не сообщает режим. Считать его «работающим без надзора»
    # нельзя — иначе весь парк старых агентов разом подсветится неверно.
    assert svc.is_unattended(None) is False


def test_dangerous_set_comes_from_risk_weights():
    dangerous = svc.dangerous_signal_ids()
    assert "cred.read.aws" in dangerous          # доступ к учётным данным
    assert "c2.reverse_shell" in dangerous       # обратная оболочка
    assert "discovery.recon" not in dangerous    # разведка — вес ниже порога
    assert "fs.write.normal" not in dangerous    # обычная запись — не опасность


# --- анти-ложные-срабатывания (главное) -------------------------------------


def test_unattended_mode_alone_is_not_a_finding():
    # Ровно тот случай, ради которого сделан порог: CI гоняет сборку в
    # bypassPermissions — это норма, алертить нельзя.
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        _event(s, mid, signals=["fs.write.normal"], mode="bypassPermissions")
        _event(s, mid, signals=["discovery.recon"], mode="bypassPermissions")
        assert svc.evaluate_one(s, mid) is None


def test_dangerous_action_in_normal_mode_is_not_this_finding():
    # Опасное действие в обычном режиме ловят другие детекторы; здесь — нет,
    # иначе находка дублировала бы риск-движок.
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        _event(s, mid, signals=["cred.read.aws"], mode="default")
        assert svc.evaluate_one(s, mid) is None


def test_no_events_no_finding():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        assert svc.evaluate_one(s, mid) is None


# --- срабатывание на совпадении ---------------------------------------------


def test_dangerous_action_in_unattended_mode_fires():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        _event(s, mid, signals=["cred.read.aws"], mode="bypassPermissions")
        f = svc.evaluate_one(s, mid)
        assert f is not None
        assert f.rule_id == "identity.unattended_risk"
        payload = json.loads(f.payload_json)
        assert payload["modes"] == ["bypassPermissions"]
        assert "cred.read.aws" in payload["signals"]
        assert payload["actors"] == ["alice"]


def test_dont_ask_mode_also_fires():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        _event(s, mid, signals=["egress.network_tool"], mode="dontAsk")
        assert svc.evaluate_one(s, mid) is not None


def test_only_dangerous_signals_counted_in_payload():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        _event(s, mid, signals=["cred.read.aws", "discovery.recon"], mode="dontAsk")
        f = svc.evaluate_one(s, mid)
        payload = json.loads(f.payload_json)
        assert "cred.read.aws" in payload["signals"]
        assert "discovery.recon" not in payload["signals"]  # шум не тащим в отчёт


def test_same_day_dedup():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        _event(s, mid, signals=["cred.read.aws"], mode="bypassPermissions")
        assert svc.evaluate_one(s, mid) is not None
        assert svc.evaluate_one(s, mid) is None  # второй раз за сутки — молчим
        assert len(list(s.exec(select(FindingRecord)))) == 1


def test_events_outside_window_ignored():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        _event(s, mid, signals=["cred.read.aws"], mode="bypassPermissions",
               minutes_ago=60 * 24 * 3)  # трое суток назад, окно 24 ч
        assert svc.evaluate_one(s, mid) is None


# --- обход флота -------------------------------------------------------------


def test_tick_covers_all_machines_and_isolates_errors():
    eng = _engine()
    with Session(eng) as s:
        a = _machine(s, "m-a")
        b = _machine(s, "m-b")
        _event(s, a, signals=["cred.read.aws"], mode="bypassPermissions")
        _event(s, b, signals=["fs.write.normal"], mode="bypassPermissions")
        res = svc.tick(s)
    assert res["machines_evaluated"] == 2
    assert res["findings_emitted"] == 1  # только машина с опасным действием
    assert res["errors"] == []


# --- сводки для интерфейса ---------------------------------------------------


def test_fleet_summary_counts_unattended_machines():
    eng = _engine()
    with Session(eng) as s:
        a = _machine(s, "m-a")
        b = _machine(s, "m-b")
        c = _machine(s, "m-c")
        _event(s, a, mode="bypassPermissions")
        _event(s, b, mode="default")
        _event(s, c, mode="dontAsk")
        summary = svc.fleet_permission_summary(s)
    assert summary["unattended_count"] == 2
    assert summary["unattended_machines"] == ["m-a", "m-c"]
    assert summary["machines_total"] == 3


def test_fleet_summary_separates_unknown_from_unattended():
    # Агент без поддержки поля — это «неизвестно», а не «без подтверждений».
    eng = _engine()
    with Session(eng) as s:
        a = _machine(s, "m-a")
        _event(s, a, mode=None)
        summary = svc.fleet_permission_summary(s)
    assert summary["unattended_count"] == 0
    assert summary["machines_total"] == 1
    assert summary["machines_reporting_mode"] == 0


def test_agent_type_summary_lists_subagents():
    eng = _engine()
    with Session(eng) as s:
        a = _machine(s, "m-a")
        b = _machine(s, "m-b")
        _event(s, a, agent_type="security-reviewer", mode="default")
        _event(s, b, agent_type="security-reviewer", mode="default")
        _event(s, a, agent_type="Explore", mode="default")
        _event(s, a, mode="default")  # основной агент — в сводку не попадает
        rows = svc.agent_type_summary(s)
    assert [r["agent_type"] for r in rows] == ["security-reviewer", "Explore"]
    assert rows[0]["machines"] == 2
    assert rows[1]["machines"] == 1
