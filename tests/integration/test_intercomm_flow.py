"""Полный цикл ASI07: удалённый MCP-канал через inventory → находка + бейдж.

Проверяет стык: агент прислал inventory с удалённым MCP (http/sse), сервер после
bootstrap выдал intercomm.remote_channel, бейдж «удалённый канал» виден на
странице машины, покрытие считает ASI07 закрытым.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import InventoryReport, McpServerEntry, SyncPayload
from ccguard.server.db.models import FindingRecord
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-intercomm")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _payload(mid: str, mcps: list[McpServerEntry]) -> dict:
    inv = InventoryReport(
        machine_id=mid, machine_label="ic-test", timestamp=datetime.now(UTC),
        agent_version="0.3.0", os="linux", mcp_servers=mcps,
    )
    return SyncPayload(inventory=inv, findings=[], audit_events=[]).model_dump(mode="json")


def _mcp(name, transport="stdio", url=None) -> McpServerEntry:
    return McpServerEntry(name=name, transport=transport, url=url, source=f"cfg:{name}")


def _hdr() -> dict:
    return {"X-CCGuard-Token": VALID_TOKEN}


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_new_remote_channel_reported_and_badge_shown(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-ic-1"
        # bootstrap: локальный MCP.
        client.post("/api/v1/inventory", headers=_hdr(), json=_payload(mid, [_mcp("localfs")]))
        with Session(eng) as s:
            assert s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "intercomm.remote_channel")).all() == []
        # позже — удалённый MCP-канал.
        client.post("/api/v1/inventory", headers=_hdr(), json=_payload(mid, [
            _mcp("localfs"), _mcp("vendor", "sse", "https://mcp.vendor.io/sse")]))
        with Session(eng) as s:
            ic = s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "intercomm.remote_channel")).all()
            assert len(ic) == 1
            assert ic[0].severity == "warn"
        page = client.get(f"/machines/{mid}", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert "удалённый канал" in page.text


def test_asi07_covered_after_seeding(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        from ccguard.server.services import coverage_service
        with Session(eng) as s:
            detail = coverage_service.coverage_detail(s, "ASI07")
    assert detail["found"] is True
    assert detail["covered"] is True
    assert "intercomm_channel" in {d["detector_key"] for d in detail["detectors"]}
