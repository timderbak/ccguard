"""Приманки (канареечные токены).

Ценность приманки держится на одном свойстве: у неё НЕТ законных причин для
обращения, поэтому ложных срабатываний не бывает по построению. Всё, что может
это свойство сломать, проверяется здесь в первую очередь:

* приманка не должна лежать на пути настоящего файла — иначе её сорвёт обычная
  работа инструментов (AWS CLI читает ~/.aws/credentials, ssh читает id_rsa);
* чтение настоящего файла не должно засчитываться как сработка приманки;
* значение приманки нигде не хранится — иначе утечка базы даст атакующему
  список приманок и он начнёт их обходить.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlmodel import Session, select

from ccguard.agent.signals.extractor import extract_signals
from ccguard.server.db.models import (
    CanaryToken,
    FindingRecord,
    Machine,
    ThreatIndicator,
    ToolUseEvent,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import canary_service as cs
from ccguard.server.services.indicator_override_service import load_sensitive_path_overrides


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


def _read_event(s: Session, mid: str, signals: list[str], actor: str = "alice") -> None:
    s.add(ToolUseEvent(
        machine_id=mid, ts=datetime.now(UTC), tool_name="Read", fingerprint="a" * 16,
        decision="allow", result_status="success", signals_json=json.dumps(signals),
        actor_user=actor,
    ))
    s.commit()


# --- главное свойство: пути не пересекаются с настоящими файлами -------------


@pytest.mark.parametrize("token_type", sorted(cs.RECIPES))
def test_default_paths_are_not_real_credential_files(token_type: str):
    """Приманка не должна занимать путь настоящего файла.

    Если положить её в ~/.aws/credentials, её будет срывать AWS CLI при обычной
    работе — и всё преимущество «ложных срабатываний не бывает» исчезает.
    """
    path = cs.RECIPES[token_type].default_path
    real_paths = {
        "~/.aws/credentials", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
        "~/.config/gh/hosts.yml", "~/.npmrc", "~/.netrc", "~/.kube/config",
    }
    assert path not in real_paths


def test_reading_real_file_does_not_trigger_canary():
    """Ключевой случай: чтение НАСТОЯЩИХ ключей не считается сработкой приманки."""
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        created = cs.create_canary(s, token_type="aws_key")
        overrides = load_sensitive_path_overrides(s)
        canary_signal = f"cred.read.store_{created.token.indicator_id}"

        # агент прочитал настоящий ~/.aws/credentials — сигнал обычный, не канареечный
        real_signals = set(extract_signals("Read", {"file_path": "~/.aws/credentials"}))
        assert "cred.read.aws" in real_signals
        assert canary_signal not in real_signals

        _read_event(s, mid, sorted(real_signals))
        assert cs.tick(s)["findings_emitted"] == 0

        # и сама приманка при этом осталась взведённой
        assert s.get(CanaryToken, created.token.id).status == "armed"
        assert overrides  # индикатор действительно раздаётся


def test_canary_path_pattern_matches_only_the_bait():
    eng = _engine()
    with Session(eng) as s:
        created = cs.create_canary(s, token_type="aws_key")
        ind = s.get(ThreatIndicator, created.token.indicator_id)
        import re
        rx = re.compile(ind.value, re.IGNORECASE)
        assert rx.search("~/.aws/credentials.bak")       # приманка
        assert not rx.search("~/.aws/credentials")       # настоящий файл


# --- значение не хранится ----------------------------------------------------


def test_value_is_never_stored():
    eng = _engine()
    with Session(eng) as s:
        created = cs.create_canary(s, token_type="aws_key")
        row = s.get(CanaryToken, created.token.id)
        # в записи только отпечаток
        assert row.value_sha256 == cs.value_digest(created.value)
        assert created.value not in json.dumps(row.model_dump(), default=str)


def test_each_canary_value_is_unique():
    eng = _engine()
    with Session(eng) as s:
        a = cs.create_canary(s, token_type="aws_key")
        b = cs.create_canary(s, token_type="aws_key")
        assert a.value != b.value


# --- правдоподобность формата ------------------------------------------------


def test_generated_values_look_real():
    # Приманка обязана быть неотличима на вид, иначе её просто пропустят.
    assert cs.generate_value("aws_key").startswith("AKIA")
    assert len(cs.generate_value("aws_key")) == 20
    assert cs.generate_value("github_pat").startswith("ghp_")
    assert cs.generate_value("slack_token").startswith("xoxb-")
    assert "BEGIN OPENSSH PRIVATE KEY" in cs.generate_value("ssh_key")


def test_file_content_is_ready_to_save():
    v = cs.generate_value("aws_key")
    content = cs.render_file_content("aws_key", v)
    assert "[default]" in content
    assert v in content


def test_unknown_type_rejected():
    with pytest.raises(ValueError):
        cs.generate_value("нет-такого")


# --- раздача агентам ---------------------------------------------------------


def test_canary_is_served_to_agents():
    eng = _engine()
    with Session(eng) as s:
        created = cs.create_canary(s, token_type="dotenv")
        served = load_sensitive_path_overrides(s)
        ids = {o["id"] for o in served}
        assert f"cred.read.store_{created.token.indicator_id}" in ids


# --- сработка ----------------------------------------------------------------


def test_trigger_emits_critical_finding():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        created = cs.create_canary(s, token_type="aws_key", label="ноутбук alice")
        _read_event(s, mid, [f"cred.read.store_{created.token.indicator_id}"])
        res = cs.tick(s)
        assert res["findings_emitted"] == 1
        f = s.exec(select(FindingRecord)).first()
        assert f.rule_id == "canary.triggered"
        assert f.severity == "critical"  # без порогов и накоплений
        payload = json.loads(f.payload_json)
        assert payload["file_path"] == "~/.aws/credentials.bak"
        assert payload["actor_user"] == "alice"


def test_trigger_marks_token_and_does_not_repeat():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        created = cs.create_canary(s, token_type="aws_key")
        _read_event(s, mid, [f"cred.read.store_{created.token.indicator_id}"])
        assert cs.tick(s)["findings_emitted"] == 1
        row = s.get(CanaryToken, created.token.id)
        assert row.status == "triggered"
        assert row.triggered_actor == "alice"
        # повторный прогон не плодит находки
        assert cs.tick(s)["findings_emitted"] == 0
        assert len(list(s.exec(select(FindingRecord)))) == 1


def test_untouched_canary_stays_armed():
    eng = _engine()
    with Session(eng) as s:
        _machine(s)
        cs.create_canary(s, token_type="aws_key")
        assert cs.tick(s)["findings_emitted"] == 0


def test_machine_scoped_canary_ignores_other_machines():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "m1")
        _machine(s, "m2")
        created = cs.create_canary(s, token_type="aws_key", machine_id="m1")
        _read_event(s, "m2", [f"cred.read.store_{created.token.indicator_id}"])
        assert cs.tick(s)["findings_emitted"] == 0
        _read_event(s, "m1", [f"cred.read.store_{created.token.indicator_id}"])
        assert cs.tick(s)["findings_emitted"] == 1


# --- управление --------------------------------------------------------------


def test_list_puts_triggered_first():
    eng = _engine()
    with Session(eng) as s:
        mid = _machine(s)
        cs.create_canary(s, token_type="aws_key")
        second = cs.create_canary(s, token_type="dotenv")
        _read_event(s, mid, [f"cred.read.store_{second.token.indicator_id}"])
        cs.tick(s)
        rows = cs.list_canaries(s)
        assert rows[0].status == "triggered"


def test_delete_removes_indicator_too():
    eng = _engine()
    with Session(eng) as s:
        created = cs.create_canary(s, token_type="aws_key")
        ind_id = created.token.indicator_id
        assert cs.delete_canary(s, created.token.id) is True
        assert s.get(ThreatIndicator, ind_id) is None  # перестала раздаваться агентам
        assert load_sensitive_path_overrides(s) == []


def test_delete_missing_returns_false():
    eng = _engine()
    with Session(eng) as s:
        assert cs.delete_canary(s, 999) is False


def test_same_path_canaries_share_one_indicator():
    # Одна и та же приманка, разложенная на разные машины: путь один, значит и
    # правило для агентов одно — дублировать его незачем.
    eng = _engine()
    with Session(eng) as s:
        a = cs.create_canary(s, token_type="aws_key", machine_id="m1")
        b = cs.create_canary(s, token_type="aws_key", machine_id="m2")
        assert a.token.indicator_id == b.token.indicator_id
        assert a.value != b.value  # но значения у них разные
        assert len(load_sensitive_path_overrides(s)) == 1


def test_deleting_one_canary_keeps_indicator_for_others():
    # Удаление одной приманки не должно ослеплять остальные на том же пути.
    eng = _engine()
    with Session(eng) as s:
        a = cs.create_canary(s, token_type="aws_key", machine_id="m1")
        b = cs.create_canary(s, token_type="aws_key", machine_id="m2")
        cs.delete_canary(s, a.token.id)
        assert s.get(ThreatIndicator, b.token.indicator_id) is not None
        assert len(load_sensitive_path_overrides(s)) == 1
        # а когда ушла последняя — правило снимается с раздачи
        cs.delete_canary(s, b.token.id)
        assert load_sensitive_path_overrides(s) == []
