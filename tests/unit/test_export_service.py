"""Выгрузка находок в CSV и JSON.

Выгрузка уходит наружу — в чужие таблицы, скрипты и SIEM. Поэтому проверяется в
первую очередь то, что ломает принимающую сторону: порядок и состав колонок,
наличие шапки на пустой выборке, корректное экранирование, и что вложенные
подробности не теряются в JSON и не рвут строку в CSV.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import export_service as ex


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _finding(s: Session, *, rule_id="cred.read.aws", severity="warn", machine="m1",
             payload=None, days_ago=0) -> None:
    s.add(FindingRecord(
        machine_id=machine, inventory_id=None, rule_id=rule_id, severity=severity,
        discovered_at=datetime.now(UTC) - timedelta(days=days_ago),
        payload_json=json.dumps(payload or {"title": "Чтение ключей AWS"}, ensure_ascii=False),
    ))
    s.commit()


# --- CSV ---------------------------------------------------------------------


def test_csv_has_header_even_when_empty():
    # Пустая выгрузка без шапки неотличима от битого файла на приёмной стороне.
    out = ex.to_csv([])
    rows = list(csv.reader(io.StringIO(out)))
    assert rows == [list(ex.CSV_COLUMNS)]


def test_csv_column_order_is_stable():
    # Файл попадает в чужие скрипты — перестановка колонок ломает их так же,
    # как смена формата.
    assert ex.CSV_COLUMNS[0] == "discovered_at"
    assert ex.CSV_COLUMNS[1] == "machine_id"
    assert ex.CSV_COLUMNS[2] == "rule_id"
    assert ex.CSV_COLUMNS[3] == "severity"


def test_csv_writes_finding_fields():
    eng = _engine()
    with Session(eng) as s:
        _finding(s, payload={"title": "Чтение ключей", "description": "нашли",
                             "recommendation": "ротировать", "source": "regex"})
        rows = ex.select_findings(s)
        out = ex.to_csv(rows)
    parsed = list(csv.DictReader(io.StringIO(out)))
    assert len(parsed) == 1
    assert parsed[0]["machine_id"] == "m1"
    assert parsed[0]["severity"] == "warn"
    assert parsed[0]["title"] == "Чтение ключей"
    assert parsed[0]["recommendation"] == "ротировать"


def test_csv_escapes_commas_and_quotes():
    # Иначе одна находка с запятой в тексте разъедет всю таблицу.
    eng = _engine()
    with Session(eng) as s:
        _finding(s, payload={"title": 'ключи, токены и "секреты"'})
        out = ex.to_csv(ex.select_findings(s))
    parsed = list(csv.DictReader(io.StringIO(out)))
    assert parsed[0]["title"] == 'ключи, токены и "секреты"'


def test_csv_flattens_nested_details():
    # В таблице нет вложенности: список сигналов должен стать одной ячейкой,
    # а не порвать строку.
    eng = _engine()
    with Session(eng) as s:
        _finding(s, payload={"title": "цепочка", "matched_value": ["a", "b"]})
        out = ex.to_csv(ex.select_findings(s))
    parsed = list(csv.DictReader(io.StringIO(out)))
    assert parsed[0]["matched_value"] == '["a","b"]'
    assert len(list(csv.reader(io.StringIO(out)))) == 2  # шапка + одна строка


def test_csv_uses_narrative_when_no_description():
    # Корреляторы пишут narrative вместо description — выгрузка не должна
    # оставлять пустую колонку там, где текст есть.
    eng = _engine()
    with Session(eng) as s:
        _finding(s, payload={"title": "IOA", "narrative": "цепочка действий"})
        out = ex.to_csv(ex.select_findings(s))
    parsed = list(csv.DictReader(io.StringIO(out)))
    assert parsed[0]["description"] == "цепочка действий"


def test_csv_survives_broken_payload():
    eng = _engine()
    with Session(eng) as s:
        s.add(FindingRecord(machine_id="m1", inventory_id=None, rule_id="x", severity="warn",
                            discovered_at=datetime.now(UTC), payload_json="{битый"))
        s.commit()
        out = ex.to_csv(ex.select_findings(s))
    parsed = list(csv.DictReader(io.StringIO(out)))
    assert len(parsed) == 1  # строка есть, просто без подробностей
    assert parsed[0]["machine_id"] == "m1"


# --- JSON --------------------------------------------------------------------


def test_json_keeps_nested_details():
    # Ради этого JSON и нужен: структура не должна схлопываться в текст.
    eng = _engine()
    with Session(eng) as s:
        _finding(s, payload={"title": "цепочка", "signals": {"cred.read.aws": 2}})
        out = json.loads(ex.to_json(ex.select_findings(s)))
    assert out["count"] == 1
    assert out["findings"][0]["details"]["signals"] == {"cred.read.aws": 2}


def test_json_wrapper_has_count_and_timestamp():
    # Принимающей стороне нужно отличать пустую выгрузку от неудавшейся.
    out = json.loads(ex.to_json([]))
    assert out["count"] == 0
    assert out["findings"] == []
    assert "exported_at" in out


# --- фильтры (те же, что на странице) ----------------------------------------


def test_filter_by_severity():
    eng = _engine()
    with Session(eng) as s:
        _finding(s, severity="warn")
        _finding(s, severity="critical")
        assert len(ex.select_findings(s, severity="critical")) == 1


def test_filter_by_machine_and_rule():
    eng = _engine()
    with Session(eng) as s:
        _finding(s, machine="m1", rule_id="a")
        _finding(s, machine="m2", rule_id="b")
        assert len(ex.select_findings(s, machine_id="m1")) == 1
        assert len(ex.select_findings(s, rule_id="b")) == 1


def test_filter_by_days():
    eng = _engine()
    with Session(eng) as s:
        _finding(s, days_ago=0)
        _finding(s, days_ago=40)
        assert len(ex.select_findings(s, since_days=7)) == 1
        assert len(ex.select_findings(s)) == 2


def test_limit_bounds_export():
    # Выгрузка собирается в памяти: без предела одна кнопка могла бы положить
    # сервер на большой базе.
    eng = _engine()
    with Session(eng) as s:
        for _ in range(5):
            _finding(s)
        assert len(ex.select_findings(s, limit=3)) == 3


def test_newest_first():
    eng = _engine()
    with Session(eng) as s:
        _finding(s, rule_id="старая", days_ago=10)
        _finding(s, rule_id="новая", days_ago=0)
        rows = ex.select_findings(s)
    assert rows[0].rule_id == "новая"


# --- имя файла ---------------------------------------------------------------


def test_filename_has_date_and_extension():
    # Чтобы выгрузки не перезаписывали друг друга в папке «Загрузки».
    name = ex.filename("csv", now=datetime(2026, 7, 25, 14, 30, tzinfo=UTC))
    assert name == "ccguard-findings-20260725-1430.csv"
    assert ex.filename("json").endswith(".json")
