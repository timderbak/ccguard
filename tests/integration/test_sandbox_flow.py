"""Полный цикл песочницы: inventory → эталон → ослабление → показ на странице.

Проверяет стык всех частей: агент прислал состояние песочницы, сервер завёл
эталон тихо, при ОСЛАБЛЕНИИ периметра выдал находку sandbox.weakened, блок
состояния виден на странице машины, а покрытие техник считает ASI03/T1562
закрытыми привязанным детектором. Плюс — обратная совместимость со старым
агентом без поля sandbox.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import InventoryReport, SandboxState, SyncPayload
from ccguard.server.db.models import FindingRecord, SandboxBaseline
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-sandbox")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _payload(machine_id: str, sandbox: SandboxState | None) -> dict:
    inv = InventoryReport(
        machine_id=machine_id, machine_label="sb-test",
        timestamp=datetime.now(UTC), agent_version="0.3.0", os="linux",
        sandbox=sandbox,
    )
    return SyncPayload(inventory=inv, findings=[], audit_events=[]).model_dump(mode="json")


def _hdr() -> dict:
    return {"X-CCGuard-Token": VALID_TOKEN}


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_first_sync_silent_then_weakening_reported(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-sb-1"
        # Первый sync — тихо, эталон заведён.
        r1 = client.post("/api/v1/inventory", headers=_hdr(),
                         json=_payload(mid, SandboxState(
                             configured=True, enabled=True,
                             network_allowed_domains=["a.com"])))
        assert r1.status_code == 200, r1.text
        with Session(eng) as s:
            rows = s.exec(select(SandboxBaseline)).all()
            assert len(rows) == 1 and rows[0].enabled is True
            assert s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "sandbox.weakened")).all() == []
        # Второй sync: выключили песочницу и расширили allowlist → находка.
        r2 = client.post("/api/v1/inventory", headers=_hdr(),
                         json=_payload(mid, SandboxState(
                             configured=True, enabled=False,
                             network_allowed_domains=["a.com", "evil.com"])))
        assert r2.status_code == 200
        with Session(eng) as s:
            weak = s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "sandbox.weakened")).all()
            assert len(weak) == 1
            assert weak[0].severity == "critical"  # песочница снята целиком


def test_sandbox_block_shows_on_machine_page(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-sb-2"
        client.post("/api/v1/inventory", headers=_hdr(),
                    json=_payload(mid, SandboxState(
                        configured=True, enabled=True, fail_if_unavailable=True,
                        allow_unsandboxed_commands=True,
                        network_allowed_domains=["api.example.com"])))
        page = client.get(f"/machines/{mid}", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert "Песочница" in page.text
    assert "api.example.com" in page.text       # egress-allowlist виден
    assert "команды вне изоляции" in page.text  # ослабляющий флаг-чип


def test_not_configured_shows_no_isolation_note(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-sb-3"
        client.post("/api/v1/inventory", headers=_hdr(),
                    json=_payload(mid, SandboxState(configured=False, default_mode="default")))
        page = client.get(f"/machines/{mid}", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert "не настроена" in page.text


def test_old_agent_without_sandbox_is_accepted(monkeypatch, tmp_path):
    # Агент v0.1/v0.2 шлёт inventory без поля sandbox — сервер обязан принять,
    # эталон песочницы не заводить.
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        r = client.post("/api/v1/inventory", headers=_hdr(),
                        json=_payload("m-old", None))
        assert r.status_code == 200, r.text
        with Session(eng) as s:
            assert s.exec(select(SandboxBaseline)).all() == []


def test_asi03_and_t1562_covered_after_seeding(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        from ccguard.server.services import coverage_service
        with Session(eng) as s:
            covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
    assert "ASI03" in covered   # Identity/Privilege Abuse — избыточные привилегии
    assert "T1562" in covered   # Impair Defenses — ослабление механизма изоляции
