"""Эпизод «машина без защиты»: от наблюдения до подписанного вердикта.

Проверяется в первую очередь не то, что запись создаётся, а два свойства, ради
которых процесс вообще заводился:

* эпизод НЕ закрывается сам, когда защита вернулась — иначе «снял, сделал,
  вернул» стиралось бы бесследно и спрашивали бы только забывчивых;
* на машину открыт один эпизод, а не по одному на каждую проверку — иначе
  выключенный ноутбук завалил бы список и его перестали бы читать.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session, select

from ccguard.server.db.models import Machine, ProtectionIncident, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import protection_incident_service as pis


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _machine(s, mid="m1", *, hb_minutes_ago=1, hooks_intact=True,
             hooks_hash="h1", baseline="h1"):
    now = datetime.now(UTC).replace(tzinfo=None)
    hb = None if hb_minutes_ago is None else now - timedelta(minutes=hb_minutes_ago)
    m = s.get(Machine, mid)
    if m is None:
        m = Machine(machine_id=mid, machine_label=mid, first_seen=now, last_seen=now,
                    agent_version="0.3", expected_interval_sec=900)
        s.add(m)
    m.last_heartbeat_at = hb
    m.hooks_intact = hooks_intact
    m.hooks_hash = hooks_hash
    m.hooks_hash_baseline = baseline
    s.add(m)
    s.commit()
    return m


def _event(s, mid="m1", minutes_ago=5):
    s.add(ToolUseEvent(
        machine_id=mid, ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        tool_name="Bash", fingerprint="a" * 16, decision="allow",
        result_status="success", signals_json=json.dumps([]),
    ))
    s.commit()


def _all(s) -> list[ProtectionIncident]:
    return list(s.exec(select(ProtectionIncident)))


# --- открытие эпизода -------------------------------------------------------


def test_stripped_hooks_open_an_episode():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        res = pis.sync(s)
        assert res["opened"] == 1
        inc = _all(s)[0]
    assert inc.state == "hooks_removed"
    assert inc.status == pis.OPEN
    # Формулировка сохраняется вместе с эпизодом: через месяц объяснение будут
    # читать без доступа к тому, что показывал экран тогда.
    assert "хук" in inc.opened_title.lower()
    assert inc.opened_detail


def test_healthy_machine_opens_nothing():
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        _event(s)
        res = pis.sync(s)
    assert res["opened"] == 0


def test_idle_machine_opens_nothing():
    # Сигнал идёт, агентом просто не пользовались. Это не событие, за которое
    # кто-то отвечает, и требовать объяснения тут не за что.
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        res = pis.sync(s)
    assert res["opened"] == 0


def test_unknown_agent_opens_nothing():
    # Старый агент, который никогда не присылал сигнал. Мы не знаем, что там —
    # а спрашивать «объясните» за собственную неосведомлённость нельзя.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hb_minutes_ago=None, hooks_intact=None)
        res = pis.sync(s)
    assert res["opened"] == 0


# --- дедупликация -----------------------------------------------------------


def test_repeated_sync_updates_one_episode_not_many():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        for _ in range(5):
            pis.sync(s)
        rows = _all(s)
    assert len(rows) == 1, "повторные проверки не должны плодить эпизоды"


def test_episode_follows_a_worsening_state():
    # Сначала сняли хуки, потом машина исчезла совсем. Это тот же разбор, но
    # оператор должен видеть свежую картину, а не ту, что была при открытии.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        _machine(s, hb_minutes_ago=600, hooks_intact=True)
        pis.sync(s)
        inc = _all(s)[0]
    assert inc.state == "hooks_removed", "исходное наблюдение не переписывается"
    assert inc.last_state == "offline"


# --- главное свойство: возврат защиты не закрывает эпизод --------------------


def test_recovery_does_not_close_the_episode():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        # Хуки вернули на место.
        _machine(s, hooks_intact=True)
        _event(s)
        res = pis.sync(s)
        inc = _all(s)[0]
    assert res["recovered"] == 1
    assert inc.recovered_at is not None, "возврат защиты фиксируется"
    assert inc.status == pis.OPEN, (
        "но эпизод остаётся открытым: иначе «снял, сделал, вернул» "
        "стиралось бы само собой"
    )


def test_recovery_is_recorded_once():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        _machine(s, hooks_intact=True)
        _event(s)
        pis.sync(s)
        res = pis.sync(s)
    assert res["recovered"] == 0


def test_losing_protection_again_clears_the_recovery_mark():
    # Хуки сняли, вернули, снова сняли. Пока отметка о возврате висит, эпизод
    # выглядит благополучнее, чем есть на самом деле.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        _machine(s, hooks_intact=True)
        _event(s)
        pis.sync(s)
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc = _all(s)[0]
    assert inc.recovered_at is None


# --- процесс разбора --------------------------------------------------------


def test_explanation_moves_to_awaiting_review():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc_id = _all(s)[0].id
        inc = pis.explain(s, inc_id, text="переустанавливал Claude Code", who="ivan")
    assert inc.status == pis.EXPLAINED
    assert inc.explanation == "переустанавливал Claude Code"
    assert inc.explained_by == "ivan"
    assert inc.explained_at is not None


def test_empty_explanation_is_rejected():
    # Пустой ответ закрывал бы вопрос, ничего не объяснив.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc_id = _all(s)[0].id
        with pytest.raises(ValueError):
            pis.explain(s, inc_id, text="   ", who="ivan")


def test_verdict_closes_the_episode():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc_id = _all(s)[0].id
        pis.explain(s, inc_id, text="переустановка", who="ivan")
        inc = pis.review(s, inc_id, accept=True, who="secops", note="ок")
    assert inc.status == pis.ACCEPTED
    assert inc.reviewed_by == "secops"
    assert inc.review_note == "ок"


def test_rejection_also_closes_but_keeps_the_record():
    # Отклонение тоже закрывает: смысл не в том, чтобы эпизод висел вечно, а в
    # том, чтобы решение было записано и подписано.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc_id = _all(s)[0].id
        pis.explain(s, inc_id, text="не помню", who="ivan")
        inc = pis.review(s, inc_id, accept=False, who="secops")
    assert inc.status == pis.REJECTED
    assert inc.explanation == "не помню", "объяснение не стирается вердиктом"


def test_verdict_cannot_be_overwritten():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc_id = _all(s)[0].id
        pis.explain(s, inc_id, text="переустановка", who="ivan")
        pis.review(s, inc_id, accept=False, who="secops")
        with pytest.raises(pis.AlreadyClosed):
            pis.review(s, inc_id, accept=True, who="someone-else")


def test_closed_episode_lets_a_new_one_open():
    # После вердикта машина снова «чистая»: если хуки снимут второй раз, это
    # отдельный случай с отдельным объяснением.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc_id = _all(s)[0].id
        pis.explain(s, inc_id, text="переустановка", who="ivan")
        pis.review(s, inc_id, accept=True, who="secops")
        res = pis.sync(s)
        rows = _all(s)
    assert res["opened"] == 1
    assert len(rows) == 2


def test_explanation_can_be_refined_before_verdict():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, hooks_intact=False)
        pis.sync(s)
        inc_id = _all(s)[0].id
        pis.explain(s, inc_id, text="не помню", who="ivan")
        inc = pis.explain(s, inc_id, text="вспомнил: чинил прокси", who="ivan")
    assert inc.explanation == "вспомнил: чинил прокси"


def test_missing_episode_raises():
    eng = _engine()
    with Session(eng) as s, pytest.raises(pis.NotFound):
        pis.explain(s, 999, text="x", who="ivan")


# --- сводка -----------------------------------------------------------------


def test_summary_counts_the_urgent_case_separately():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "m-gone", hooks_intact=False)
        _machine(s, "m-back", hooks_intact=False)
        pis.sync(s)
        # На одной машине защиту вернули, на другой нет.
        _machine(s, "m-back", hooks_intact=True)
        _event(s, "m-back")
        pis.sync(s)
        out = pis.summary(s)
    assert out["total"] == 2
    assert out["awaiting_explanation"] == 2
    assert out["still_unprotected"] == 1, (
        "машина, где защита так и не вернулась, — самое срочное"
    )


def test_list_puts_unanswered_first():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "m-a", hooks_intact=False)
        _machine(s, "m-b", hooks_intact=False)
        pis.sync(s)
        first = _all(s)[0]
        pis.explain(s, first.id, text="ответил", who="ivan")
        rows = pis.list_incidents(s)
    assert rows[0].status == pis.OPEN
    assert rows[-1].status == pis.EXPLAINED


# --- отчёт ------------------------------------------------------------------


def test_report_records_both_accepted_and_rejected():
    # Отчёт, где видны только принятые решения, ничего не говорит о том,
    # работает ли процесс на самом деле.
    from ccguard.server.services import compliance_report_service as crs

    eng = _engine()
    with Session(eng) as s:
        _machine(s, "m-a", hooks_intact=False)
        _machine(s, "m-b", hooks_intact=False)
        pis.sync(s)
        for inc, ok in zip(_all(s), (True, False), strict=True):
            pis.explain(s, inc.id, text="причина", who="ivan")
            pis.review(s, inc.id, accept=ok, who="secops")
        rep = crs.build_report(s, days=30)

    assert rep["protection"]["accepted"] == 1
    assert rep["protection"]["rejected"] == 1
    decisions = [d for d in rep["decisions"] if d["what"] == "машина без защиты"]
    assert {d["decision"] for d in decisions} == {"принято", "отклонено"}
