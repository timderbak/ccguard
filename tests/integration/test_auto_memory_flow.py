"""Полный цикл авто-памяти: inventory → снимок → аномальная дельта → показ.

Проверяет стык всех частей: агент прислал признаки авто-памяти, сервер завёл
снимок тихо, при подозрительной дельте (вброс + внешний @import + маркеры) выдал
находку automemory.anomaly, блок авто-памяти виден на странице машины, а покрытие
техник считает ASI06 закрытым. Плюс — обратная совместимость со старым агентом.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import AutoMemoryStats, InventoryReport, SyncPayload
from ccguard.server.db.models import AutoMemoryBaseline, FindingRecord
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-automem")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _payload(machine_id: str, auto_memory: list[AutoMemoryStats]) -> dict:
    inv = InventoryReport(
        machine_id=machine_id, machine_label="am-test",
        timestamp=datetime.now(UTC), agent_version="0.3.0", os="linux",
        auto_memory=auto_memory,
    )
    return SyncPayload(inventory=inv, findings=[], audit_events=[]).model_dump(mode="json")


def _am(**kw) -> AutoMemoryStats:
    d = dict(
        path="/h/.claude/projects/-p/memory/MEMORY.md", size_bytes=200, line_count=10,
        import_count=0, external_import_count=0, url_count=1,
        suspicious_marker_count=0, content_hash="h",
    )
    d.update(kw)
    return AutoMemoryStats(**d)


def _hdr() -> dict:
    return {"X-CCGuard-Token": VALID_TOKEN}


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_first_sync_silent_then_poison_reported(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-am-1"
        r1 = client.post("/api/v1/inventory", headers=_hdr(), json=_payload(mid, [_am()]))
        assert r1.status_code == 200, r1.text
        with Session(eng) as s:
            assert len(s.exec(select(AutoMemoryBaseline)).all()) == 1
            assert s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "automemory.anomaly")).all() == []
        # Отравление: вброс + внешний @import + маркеры → critical.
        r2 = client.post("/api/v1/inventory", headers=_hdr(), json=_payload(mid, [
            _am(line_count=95, size_bytes=6000, external_import_count=1,
                suspicious_marker_count=6, url_count=5, content_hash="h2")]))
        assert r2.status_code == 200
        with Session(eng) as s:
            anomaly = s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "automemory.anomaly")).all()
            assert len(anomaly) == 1
            assert anomaly[0].severity == "critical"


def test_auto_memory_block_shows_on_machine_page(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-am-2"
        client.post("/api/v1/inventory", headers=_hdr(), json=_payload(mid, [
            _am(external_import_count=1, suspicious_marker_count=2)]))
        page = client.get(f"/machines/{mid}", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert "Авто-память агента" in page.text
    assert "внешних @import" in page.text     # красный контекст-чип
    assert "атака-маркеры" in page.text


def test_old_agent_without_auto_memory_is_accepted(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        r = client.post("/api/v1/inventory", headers=_hdr(), json=_payload("m-old", []))
        assert r.status_code == 200, r.text
        with Session(eng) as s:
            assert s.exec(select(AutoMemoryBaseline)).all() == []


def test_asi06_covered_by_automemory_detector(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        from ccguard.server.services import coverage_service
        with Session(eng) as s:
            detail = coverage_service.coverage_detail(s, "ASI06")
    assert detail["found"] is True
    assert detail["covered"] is True
    assert "automemory_baseline" in {d["detector_key"] for d in detail["detectors"]}
