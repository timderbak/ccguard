"""Полный цикл видимости Cursor: inventory (agent_kind=cursor) → baseline/дрейф → UI.

Cursor едет через существующие схемы (McpServerEntry / MemoryEntry) и сервисы
(mcp_baseline / memory_baseline) — БЕЗ новых серверных моделей. Проверяем:
машина заводится с agent_kind=cursor, MCP/правила baseline'ятся и дают дрейф,
флот честно показывает «только видимость» (НЕ зелёное «соответствует»), карточка
показывает баннер видимости + инвентарь Cursor. Плюс — детекция Cursor на агенте.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.agent.sync import _cursor_present
from ccguard.schemas import InventoryReport, McpServerEntry, MemoryEntry, SyncPayload
from ccguard.server.db.models import FindingRecord, Machine, MemoryBaseline
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-cursor")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _payload(mid, mcps, mems) -> dict:
    inv = InventoryReport(
        machine_id=mid, machine_label="dev-cursor", timestamp=datetime.now(UTC),
        agent_version="0.3.0", agent_kind="cursor", os="linux",
        mcp_servers=mcps, memory_files=mems,
    )
    return SyncPayload(inventory=inv, findings=[], audit_events=[]).model_dump(mode="json")


def _mem(path, h, scope="cursor_rules") -> MemoryEntry:
    return MemoryEntry(path=path, scope=scope, content_hash=h, size_bytes=40)


def _hdr() -> dict:
    return {"X-CCGuard-Token": VALID_TOKEN}


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_cursor_machine_registers_with_agent_kind(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-cursor-1"
        r = client.post("/api/v1/inventory", headers=_hdr(), json=_payload(
            mid,
            [McpServerEntry(name="r", transport="http", url="https://mcp.x.io", source=".cursor/mcp.json")],
            [_mem("/p/.cursor/rules/style.mdc", "h1")],
        ))
        assert r.status_code == 200, r.text
        with Session(eng) as s:
            m = s.get(Machine, mid)
            assert m.agent_kind == "cursor"
            # правило Cursor заведено в общий memory baseline
            assert s.exec(select(MemoryBaseline).where(MemoryBaseline.machine_id == mid)).all()


def test_cursor_rule_drift_detected(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-cursor-2"
        client.post("/api/v1/inventory", headers=_hdr(),
                    json=_payload(mid, [], [_mem("/p/.cursor/rules/style.mdc", "h1")]))
        with Session(eng) as s:  # принять baseline, чтобы дрейф считался дрейфом
            row = s.exec(select(MemoryBaseline).where(MemoryBaseline.machine_id == mid)).one()
            row.status = "active"
            s.add(row)
            s.commit()
        client.post("/api/v1/inventory", headers=_hdr(),
                    json=_payload(mid, [], [_mem("/p/.cursor/rules/style.mdc", "h2")]))
        with Session(eng) as s:
            drift = s.exec(select(FindingRecord).where(FindingRecord.rule_id == "memory.drift")).all()
            assert len(drift) == 1


def test_fleet_shows_visibility_only_not_compliant(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-cursor-3"
        client.post("/api/v1/inventory", headers=_hdr(),
                    json=_payload(mid, [], [_mem("/p/.cursorrules", "h1", scope="cursor_legacy")]))
        page = client.get("/machines", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert "только видимость" in page.text
    # Cursor-строка НЕ должна читаться как зелёное «соответствует».
    # (claude-строк в этом тесте нет, так что «соответствует» вообще не появится)
    assert "◐ только видимость" in page.text


def test_machine_page_shows_visibility_banner_and_cursor_inventory(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-cursor-4"
        client.post("/api/v1/inventory", headers=_hdr(), json=_payload(
            mid,
            [McpServerEntry(name="vendor", transport="sse", url="https://mcp.vendor.io/sse", source=".cursor/mcp.json")],
            [_mem("/p/.cursor/rules/api.mdc", "h1")],
        ))
        page = client.get(f"/machines/{mid}", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert "Агент только для видимости" in page.text        # честный баннер
    assert "без поведенческой блокировки" in page.text      # header-бейдж
    assert "удалённый канал" in page.text                   # remote MCP как ASI07-канал
    # Разделы, питаемые хуками/аудитом Claude Code, для Cursor скрыты — их
    # ложно-успокаивающая пустота («защита активна») не должна появляться.
    assert 'data-testid="enforce-blocks"' not in page.text
    assert "защита активна" not in page.text


def test_overview_shows_visibility_only_posture(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        client.post("/api/v1/inventory", headers=_hdr(),
                    json=_payload("m-cursor-5", [], [_mem("/p/.cursorrules", "h1", scope="cursor_legacy")]))
        page = client.get("/", cookies={"ccg_session": _sid(eng)})
    assert page.status_code == 200
    assert 'data-testid="agent-posture"' in page.text
    assert "только под наблюдением" in page.text


# --- агентная детекция Cursor ---------------------------------------------


def test_cursor_present_detection(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    assert _cursor_present(home, proj) is False
    (proj / ".cursorrules").write_text("x")
    assert _cursor_present(home, proj) is True
