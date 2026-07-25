"""Карточка машины показывает ПРИЧИНУ тишины, а не только её факт.

До этого страница машины показывала «sync: 3 часа назад» — и всё. Такая
формулировка одинаково описывает выключенный на выходные ноутбук и машину, с
которой сняли хуки. Проверяем, что теперь эти случаи различаются на экране, и
что обычная работа не рисует тревожную карточку.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import Machine, ToolUseEvent
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-diagnosis")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed(engine, machine_id: str, **kw) -> None:
    now = datetime.now(UTC)
    defaults = dict(
        machine_label="ui", last_seen=now, agent_version="0.3.0",
        last_heartbeat_at=now - timedelta(minutes=1),
        expected_interval_sec=900, hooks_intact=True,
    )
    defaults.update(kw)
    with Session(engine) as s:
        s.add(Machine(machine_id=machine_id, **defaults))
        s.commit()


def _event(engine, machine_id: str, minutes_ago: int = 5) -> None:
    with Session(engine) as s:
        s.add(ToolUseEvent(
            machine_id=machine_id,
            ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            tool_name="Bash", fingerprint="e" * 16, decision="allow",
            result_status="success", signals_json=json.dumps([]),
        ))
        s.commit()


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_healthy_machine_shows_protection_working(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-ok")
        _event(eng, "m-ok")
        r = client.get("/machines/m-ok", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "Защита работает" in r.text
    assert "защита действует" in r.text


def test_removed_hooks_render_as_removed_not_as_silence(monkeypatch, tmp_path) -> None:
    # Прямая улика: машина на связи и сама доложила, что хуков нет. На экране
    # это должно читаться как снятие защиты, а не как «нет сигнала».
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-strip", hooks_intact=False)
        r = client.get("/machines/m-strip", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "Хуки сняты" in r.text
    assert "защита не действует" in r.text
    assert "нужен разбор" in r.text


def test_daemon_down_but_hooks_alive_is_distinguished(monkeypatch, tmp_path) -> None:
    # Сигнала нет, но события от хуков идут — блокировка работает, упала только
    # служба синхронизации. Это принципиально мягче полного ухода из-под
    # наблюдения, и на экране должно выглядеть иначе.
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-dd", last_heartbeat_at=datetime.now(UTC) - timedelta(hours=4))
        _event(eng, "m-dd", minutes_ago=10)
        r = client.get("/machines/m-dd", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "Фоновая служба не отвечает" in r.text
    # Защита при этом действует — карточка не должна кричать «незащищена».
    assert "защита действует" in r.text


def test_idle_machine_is_not_shown_as_incident(monkeypatch, tmp_path) -> None:
    # Сигнал идёт, событий нет — человек просто не работал с агентом. Если
    # рисовать это как проблему, оператор перестанет читать карточки вообще.
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-idle")
        r = client.get("/machines/m-idle", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "агент не используется" in r.text
    assert "нужен разбор" not in r.text


def test_unknown_state_is_not_painted_as_breach(monkeypatch, tmp_path) -> None:
    # Машина никогда не присылала сигнал (старый агент или установка не
    # завершена). Утверждать «защита не действует» здесь нельзя: мы просто не
    # знаем. Красить неизвестность как взлом — значит врать оператору.
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        _seed(eng, "m-unk", last_heartbeat_at=None, hooks_intact=None)
        r = client.get("/machines/m-unk", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "состояние неизвестно" in r.text
    assert "защита не действует" not in r.text
    assert "нужен разбор" not in r.text
