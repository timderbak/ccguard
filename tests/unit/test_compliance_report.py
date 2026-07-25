"""Отчёт за период — документ для аудита.

Проверяется прежде всего достоверность: отчёт не должен показывать только
успехи (иначе аудитор справедливо сочтёт его недостоверным), должен честно
отделять наблюдаемые машины от молчащих и явно показывать незакрытые техники.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import AuditRecord, FindingRecord, Machine
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import canary_service as cs
from ccguard.server.services import compliance_report_service as rs


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _machine(s, mid="m1", days_silent=0):
    now = datetime.now(UTC).replace(tzinfo=None)
    s.add(Machine(machine_id=mid, machine_label=mid, first_seen=now,
                  last_seen=now - timedelta(days=days_silent), agent_version="0.3"))
    s.commit()


def _finding(s, sev="warn", rid="cred.read.aws", days_ago=0, machine="m1"):
    s.add(FindingRecord(machine_id=machine, inventory_id=None, rule_id=rid, severity=sev,
          discovered_at=datetime.now(UTC) - timedelta(days=days_ago),
          payload_json=json.dumps({"title": "t"})))
    s.commit()


def _audit(s, *, decision="deny", fail_open=False, rule="hard.reverse_shell"):
    now = datetime.now(UTC)
    s.add(AuditRecord(machine_id="m1", timestamp=now, tool_name="Bash", decision=decision,
          rule_id=rule, reason="r", fail_open=fail_open, tool_input_fingerprint="a"*16))
    s.commit()


def test_empty_report_builds():
    # Отчёт на пустой системе обязан строиться: иначе им нельзя пользоваться
    # с первого дня внедрения.
    eng = _engine()
    with Session(eng) as s:
        r = rs.build_report(s)
    assert r["fleet"]["total"] == 0
    assert r["findings"]["total"] == 0
    assert r["decisions"] == []


def test_fleet_separates_silent_machines():
    # «Ноль инцидентов» на молчащей машине — не то же самое, что на наблюдаемой.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "живая", days_silent=0)
        _machine(s, "молчит", days_silent=60)
        r = rs.build_report(s, days=30)
    assert r["fleet"]["total"] == 2
    assert r["fleet"]["active"] == 1
    assert r["fleet"]["silent"] == 1


def test_findings_grouped_by_severity():
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        _finding(s, sev="critical")
        _finding(s, sev="critical")
        _finding(s, sev="warn")
        r = rs.build_report(s)
    assert r["findings"]["by_severity"]["critical"] == 2
    assert r["findings"]["by_severity"]["warn"] == 1
    assert r["findings"]["total"] == 3


def test_correlations_counted_separately():
    # Связанные цепочки — главное, что отличает средство от простого лога.
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        _finding(s, rid="ioa.exfil_sequence")
        _finding(s, rid="cred.read.aws")
        r = rs.build_report(s)
    assert r["findings"]["correlations"] == 1


def test_period_bounds_respected():
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        _finding(s, days_ago=0)
        _finding(s, days_ago=60)
        assert rs.build_report(s, days=30)["findings"]["total"] == 1
        assert rs.build_report(s, days=90)["findings"]["total"] == 2


def test_fail_open_reported_next_to_blocks():
    # Ключевое для достоверности: показываем не только успехи, но и случаи,
    # когда защита не смогла принять решение и пропустила действие.
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        _audit(s, decision="deny")
        _audit(s, decision="allow", fail_open=True)
        r = rs.build_report(s)
    assert r["blocks"]["total"] == 1
    assert r["blocks"]["fail_open"] == 1


def test_decisions_log_includes_canary_creation():
    eng = _engine()
    with Session(eng) as s:
        cs.create_canary(s, token_type="aws_key", created_by="tim")
        r = rs.build_report(s)
    assert len(r["decisions"]) == 1
    assert r["decisions"][0]["who"] == "tim"
    assert r["decisions"][0]["what"] == "приманка"


def test_canary_counts_present():
    eng = _engine()
    with Session(eng) as s:
        cs.create_canary(s, token_type="aws_key")
        r = rs.build_report(s)
    assert r["canaries"]["total"] == 1
    assert r["canaries"]["armed"] == 1


def test_coverage_section_present_even_without_taxonomy():
    # Отчёт не должен падать целиком, если один раздел собрать не удалось.
    eng = _engine()
    with Session(eng) as s:
        r = rs.build_report(s)
    assert "covered" in r["coverage"]
    assert "gaps" in r["coverage"]


def test_top_rules_sorted_by_frequency():
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        for _ in range(3):
            _finding(s, rid="частое")
        _finding(s, rid="редкое")
        r = rs.build_report(s)
    assert r["findings"]["top_rules"][0] == ("частое", 3)
