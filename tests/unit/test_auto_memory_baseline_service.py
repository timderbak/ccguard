"""Детект отравления авто-памяти по аномальной дельте признаков.

Проверяются свойства, ради которых фича существует:

* первый контакт тихий (иначе подключение машины с уже накопленной памятью
  завалило бы находками);
* ПОСТЕПЕННЫЙ рост тихий — сравнение с соседним снимком, а не с древним эталоном;
* ВНЕЗАПНЫЙ вброс (скачок объёма), новый внешний @import, всплеск атака-маркеров
  → находка automemory.anomaly;
* внешний @import + всплеск маркеров вместе → critical (почти наверняка закладка);
* повтор того же снимка не даёт второй находки;
* пустой список — no-op (обратная совместимость со старым агентом).

Значения находок снимаем внутри сессии (ORM-объекты отвязываются на выходе).
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from ccguard.schemas import AutoMemoryStats
from ccguard.server.db.models import AutoMemoryBaseline
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import auto_memory_baseline_service as svc


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _am(**kw) -> AutoMemoryStats:
    d = dict(
        path="/m/MEMORY.md", size_bytes=200, line_count=10, import_count=0,
        external_import_count=0, url_count=1, suspicious_marker_count=0,
        content_hash="h",
    )
    d.update(kw)
    return AutoMemoryStats(**d)


def _rows(s, mid="m1"):
    return list(s.exec(select(AutoMemoryBaseline).where(AutoMemoryBaseline.machine_id == mid)))


def _transition(old: AutoMemoryStats, new: AutoMemoryStats) -> tuple[int, str | None, list[str]]:
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [old])
        s.commit()
        f = svc.update_and_detect(s, "m1", [new])
        n = len(f)
        sev = f[0].severity if f else None
        reasons = json.loads(f[0].payload_json)["reasons"] if f else []
        s.commit()
    return n, sev, reasons


# --- bootstrap / backward-compat -------------------------------------------


def test_first_contact_is_silent():
    eng = _engine()
    with Session(eng) as s:
        f = svc.update_and_detect(s, "m1", [_am(), _am(path="/m/topic.md")])
        s.commit()
        assert f == []
        assert len(_rows(s)) == 2


def test_empty_list_is_noop():
    eng = _engine()
    with Session(eng) as s:
        assert svc.update_and_detect(s, "m1", []) == []
        s.commit()
        assert _rows(s) == []


# --- тихие случаи ----------------------------------------------------------


def test_gradual_growth_is_quiet():
    # Небольшая дельта (агент дописал пару заметок) — не находка.
    n, _, _ = _transition(
        _am(line_count=10, size_bytes=200),
        _am(line_count=25, size_bytes=900, content_hash="h2"),
    )
    assert n == 0


def test_no_change_is_quiet():
    n, _, _ = _transition(_am(), _am())
    assert n == 0


def test_single_marker_does_not_fire():
    # Одиночное легитимное упоминание («тестируй через curl») — не скачок.
    n, _, _ = _transition(
        _am(suspicious_marker_count=0),
        _am(suspicious_marker_count=1, content_hash="h2"),
    )
    assert n == 0


# --- аномалии → находка ----------------------------------------------------


def test_sudden_volume_spike_warns():
    n, sev, reasons = _transition(
        _am(line_count=10, size_bytes=200),
        _am(line_count=90, size_bytes=200, content_hash="h2"),  # +80 строк
    )
    assert n == 1
    assert sev == "warn"
    assert any("рост объёма" in r for r in reasons)


def test_new_external_import_warns():
    n, sev, reasons = _transition(
        _am(external_import_count=0),
        _am(external_import_count=1, content_hash="h2"),
    )
    assert n == 1
    assert sev == "warn"
    assert any("внешний @import" in r for r in reasons)


def test_marker_jump_warns():
    n, sev, reasons = _transition(
        _am(suspicious_marker_count=0),
        _am(suspicious_marker_count=4, content_hash="h2"),
    )
    assert n == 1
    assert any("атака-маркеров" in r for r in reasons)


def test_url_jump_warns():
    n, sev, reasons = _transition(
        _am(url_count=0),
        _am(url_count=5, content_hash="h2"),
    )
    assert n == 1
    assert any("URL" in r for r in reasons)


def test_external_import_plus_markers_is_critical():
    # Сочетание вброшенного внешнего импорта и всплеска маркеров — почти
    # наверняка закладка, а не рядовая правка.
    n, sev, reasons = _transition(
        _am(external_import_count=0, suspicious_marker_count=0),
        _am(external_import_count=1, suspicious_marker_count=5, content_hash="h2"),
    )
    assert n == 1
    assert sev == "critical"
    assert len(reasons) >= 2


# --- анти-повтор -----------------------------------------------------------


def test_repeat_after_anomaly_no_second_finding():
    eng = _engine()
    poisoned = _am(line_count=90, external_import_count=1, suspicious_marker_count=5, content_hash="h2")
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_am()])
        s.commit()
        f1 = svc.update_and_detect(s, "m1", [poisoned])
        n1 = len(f1)
        s.commit()
        f2 = svc.update_and_detect(s, "m1", [poisoned])
        n2 = len(f2)
        s.commit()
        assert n1 == 1
        assert n2 == 0  # эталон сдвинут — повтора нет


def test_detect_anomalies_pure_no_change():
    # Чистая функция сравнения на «нет изменений».
    base = AutoMemoryBaseline(
        machine_id="m", path="/m/MEMORY.md", size_bytes=200, line_count=10,
        import_count=0, external_import_count=0, url_count=1,
        suspicious_marker_count=0, content_hash="h",
        first_seen_at=svc._now(), last_seen_at=svc._now(), updated_at=svc._now(),
    )
    reasons, sev = svc.detect_anomalies(base, _am())
    assert reasons == []
    assert sev == "warn"
