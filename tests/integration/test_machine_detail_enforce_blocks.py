"""machine_detail surfaces the enforce-block stream (Tier 3).

AuditRecord (deny + fail_open) was persisted but never rendered, so anti-tamper
hard.* blocks were invisible. This verifies the "Заблокированные действия"
section renders the block with a humanized label, its reason, and distinguishes
a real block from a fail-open.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import AuditRecord, Machine
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-enforce-blocks")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed_machine(engine, machine_id: str) -> None:
    with Session(engine) as s:
        s.add(Machine(machine_id=machine_id, machine_label="ui",
                      last_seen=datetime.now(UTC), agent_version="0.2.0"))
        s.commit()


def _session(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


def test_machine_detail_renders_hard_deny_block(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-blk-1"
        _seed_machine(eng, mid)
        with Session(eng) as s:
            s.add(AuditRecord(
                machine_id=mid, timestamp=datetime.now(UTC),
                received_at=datetime.now(UTC) - timedelta(minutes=3),
                tool_name="Bash", decision="deny", rule_id="hard.fs_wipe",
                reason="Рекурсивное удаление корня файловой системы — гибель хоста.",
                fail_open=False, tool_input_fingerprint="abc",
            ))
            s.commit()
        sid = _session(eng)
        r = client.get(f"/machines/{mid}", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        html = r.text
        assert 'data-testid="enforce-blocks"' in html
        assert "Заблокированные действия" in html
        assert "Заблокировано" in html
        # humanized hard.* label (Tier 1) — not the raw rule_id alone
        assert "Тотальное удаление корня" in html
        assert "hard.fs_wipe" in html  # raw id still shown mono
        assert "гибель хоста" in html  # the reason


def test_machine_detail_fail_open_shown_distinctly(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-blk-fo"
        _seed_machine(eng, mid)
        with Session(eng) as s:
            s.add(AuditRecord(
                machine_id=mid, timestamp=datetime.now(UTC),
                received_at=datetime.now(UTC), tool_name="Bash", decision="deny",
                rule_id=None, reason="policy unavailable", fail_open=True,
                tool_input_fingerprint="fo",
            ))
            s.commit()
        sid = _session(eng)
        r = client.get(f"/machines/{mid}", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Fail-open" in r.text


def test_machine_detail_enforce_blocks_empty_state(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        mid = "m-blk-empty"
        _seed_machine(eng, mid)
        sid = _session(eng)
        r = client.get(f"/machines/{mid}", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert 'data-testid="enforce-blocks-empty"' in r.text
        assert "Заблокированных действий не зафиксировано" in r.text
