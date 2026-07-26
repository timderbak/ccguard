"""Тип агента: сохранение через inventory и показ в UI.

Фундамент мультиагентности виден на стыке: агент прислал свой тип, сервер его
сохранил, флот и карточка машины его показывают — и честно помечают, что
поведенческая блокировка есть только у Claude Code.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.schemas import InventoryReport, SyncPayload
from ccguard.server.db.models import Machine
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-agentkind")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _payload(machine_id: str, kind: str | None) -> dict:
    kw = dict(machine_id=machine_id, machine_label=machine_id,
              timestamp=datetime.now(UTC), agent_version="0.3.0", os="linux")
    if kind is not None:
        kw["agent_kind"] = kind
    return SyncPayload(inventory=InventoryReport(**kw)).model_dump(mode="json")


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_inventory_persists_agent_kind(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        r = client.post("/api/v1/inventory", json=_payload("m-cur", "cursor"),
                        headers={"X-CCGuard-Token": VALID_TOKEN})
        assert r.status_code == 200, r.text
        with Session(eng) as s:
            assert s.get(Machine, "m-cur").agent_kind == "cursor"


def test_fleet_table_shows_non_claude_agent_as_visibility_only(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        client.post("/api/v1/inventory", json=_payload("m-cur", "cursor"),
                    headers={"X-CCGuard-Token": VALID_TOKEN})
        r = client.get("/machines", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "Cursor" in r.text
    assert "только видимость" in r.text  # честная пометка про отсутствие блокировки


def test_claude_machine_not_labeled_visibility_only(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        client.post("/api/v1/inventory", json=_payload("m-cc", "claude_code"),
                    headers={"X-CCGuard-Token": VALID_TOKEN})
        r = client.get("/machines", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "Claude Code" in r.text
    # У Claude Code блокировка есть — «только видимость» на его строке быть не должно.
    # (Проверяем, что метка не появилась именно из-за него: другой машины нет.)
    assert "только видимость" not in r.text


def test_old_agent_without_kind_defaults_to_claude_code(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        r = client.post("/api/v1/inventory", json=_payload("m-old", None),
                        headers={"X-CCGuard-Token": VALID_TOKEN})
        assert r.status_code == 200
        with Session(eng) as s:
            assert s.get(Machine, "m-old").agent_kind == "claude_code"
