"""Полный цикл памяти (ASI06): inventory → baseline → дрейф → показ и приём.

Проверяет стык всех частей вместе: агент прислал файлы памяти в inventory,
сервер завёл baseline, при изменении содержимого выдал находку, карточка видна
на странице машины, кнопка «Принять baseline» действительно закрывает вопрос.
Плюс — что покрытие техник теперь считает ASI06 закрытым.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import InventoryReport, MemoryEntry, SyncPayload
from ccguard.server.db.models import FindingRecord, MemoryBaseline
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-memory")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _payload(machine_id: str, memory: list[MemoryEntry]) -> dict:
    inv = InventoryReport(
        machine_id=machine_id, machine_label="mem-test",
        timestamp=datetime.now(UTC), agent_version="0.3.0", os="linux",
        memory_files=memory,
    )
    return SyncPayload(inventory=inv, findings=[], audit_events=[]).model_dump(mode="json")


def _mem(path, h, scope="project", imported_by=None):
    return MemoryEntry(path=path, scope=scope, content_hash=h, size_bytes=50,
                       imported_by=imported_by)


def _hdr() -> dict:
    return {"X-CCGuard-Token": VALID_TOKEN}


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_first_sync_is_silent_then_drift_is_reported(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-mem-1"
        # Первый sync — тихо, baseline pending.
        r1 = client.post("/api/v1/inventory",
                         json=_payload(mid, [_mem("/p/CLAUDE.md", "h1")]),
                         headers=_hdr())
        assert r1.status_code == 200, r1.text
        with Session(eng) as s:
            rows = s.exec(select(MemoryBaseline)).all()
            assert len(rows) == 1 and rows[0].status == "pending"
            assert s.exec(select(FindingRecord).where(
                FindingRecord.rule_id.like("memory.%"))).all() == []
            # Примем baseline, чтобы дальше дрейф считался как дрейф.
            rows[0].status = "active"
            s.add(rows[0])
            s.commit()
        # Второй sync с изменённым содержимым → находка дрейфа.
        r2 = client.post("/api/v1/inventory",
                         json=_payload(mid, [_mem("/p/CLAUDE.md", "h2")]),
                         headers=_hdr())
        assert r2.status_code == 200
        with Session(eng) as s:
            drift = s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "memory.drift")).all()
            assert len(drift) == 1


def test_external_import_drift_card_shows_on_machine_page(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-mem-2"
        client.post("/api/v1/inventory",
                    json=_payload(mid, [_mem("/p/CLAUDE.md", "h1")]),
                    headers=_hdr())
        with Session(eng) as s:
            row = s.exec(select(MemoryBaseline)).one()
            row.status = "active"
            s.add(row)
            s.commit()
        # Появился внешний @import — отдельное по смыслу событие.
        client.post("/api/v1/inventory",
                    json=_payload(mid, [
                        _mem("/p/CLAUDE.md", "h1"),
                        _mem("/home/u/evil.md", "hx", scope="import",
                             imported_by="/p/CLAUDE.md"),
                    ]),
                    headers=_hdr())
        page = client.get(f"/machines/{mid}", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert "вне репозитория" in page.text or "вне того" in page.text
    assert "/home/u/evil.md" in page.text
    assert "Принять baseline" in page.text


def test_accept_memory_baseline_button_clears_pending(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-mem-3"
        client.post("/api/v1/inventory",
                    json=_payload(mid, [_mem("/p/CLAUDE.md", "h1")]),
                    headers=_hdr())
        sid = _sid(eng)
        client.cookies.set("ccg_session", sid)
        page = client.get(f"/machines/{mid}")
        token = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
        with Session(eng) as s:
            bid = s.exec(select(MemoryBaseline)).one().id
        r = client.post(
            f"/machines/{mid}/memory-baseline/accept-all-pending",
            data={"csrf_token": token}, follow_redirects=False,
        )
        assert r.status_code == 303
        with Session(eng) as s:
            assert s.get(MemoryBaseline, bid).status == "active"


def test_asi06_is_covered_after_seeding(monkeypatch, tmp_path):
    # Раньше отчёт показывал ASI06 честным пробелом. Теперь детектор привязан —
    # покрытие должно считать технику закрытой.
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        from ccguard.server.services import coverage_service
        with Session(eng) as s:
            covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
    assert "ASI06" in covered


def test_old_agent_without_memory_is_accepted(monkeypatch, tmp_path):
    # Агент v0.1/v0.2 шлёт inventory без memory_files — сервер обязан принять.
    with _client(monkeypatch, tmp_path) as client:
        inv = InventoryReport(
            machine_id="m-old", machine_label="old", timestamp=datetime.now(UTC),
            agent_version="0.1.0", os="linux",
        )
        payload = SyncPayload(inventory=inv).model_dump(mode="json")
        r = client.post("/api/v1/inventory", json=payload, headers=_hdr())
    assert r.status_code == 200, r.text
