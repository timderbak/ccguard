"""Tests for /admin/mcp-inventory fleet page, HTMX drill-down, and review actions.

Единая база MCP по флоту: список серверов + хеши + статус ревью (проверено/
не проверено). Mirrors test_admin_skills_inventory.py's harness pattern.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import McpServerEntry
from ccguard.server.db.models import Machine, MCPServerBaseline
from ccguard.server.main import create_app
from ccguard.server.services import mcp_baseline_service
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _login(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-mcp-fleet")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed_machine(s: Session, machine_id: str) -> None:
    if s.get(Machine, machine_id) is None:
        s.add(Machine(
            machine_id=machine_id, machine_label=machine_id,
            first_seen=_now(), last_seen=_now(), agent_version="0.3.0",
        ))


def _mcp(name="notion", command="npx", args=None, description="a tool", tools_hash=None):
    from ccguard.agent.scan.mcp import _definition_text, _hash_text

    args = args or ["-y", "@notion/mcp"]
    return McpServerEntry(
        name=name, transport="stdio", command=command, args=args, url=None,
        env_keys=[], source="/test/.claude.json", description=description,
        description_hash=_hash_text(description),
        definition_hash=_hash_text(_definition_text(command, args, None)),
        tools_hash=tools_hash,
    )


def _csrf(client: TestClient, sid: str) -> str:
    r = client.get("/admin/mcp-inventory", cookies={"ccg_session": sid})
    assert r.status_code == 200
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m is not None, "csrf token not on /admin/mcp-inventory"
    return m.group(1)


# --- page render --------------------------------------------------------


def test_page_renders_empty(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        r = client.get("/admin/mcp-inventory", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "MCP по флоту" in r.text
        assert "Пока ни одного MCP-сервера" in r.text


def test_page_lists_mcp_with_review_progress(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine(s, "m1")
            _seed_machine(s, "m2")
            mcp_baseline_service.update_and_detect(s, "m1", [_mcp("notion")])
            mcp_baseline_service.update_and_detect(s, "m2", [_mcp("notion")])
            s.commit()
            mcp_baseline_service.mark_reviewed(s, "m1", "notion", reviewed_by="alice")
            sid = create_session(s, user_id="admin")

        r = client.get("/admin/mcp-inventory", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "notion" in r.text
        assert "1/2 проверено" in r.text
        assert "не полностью проверено" in r.text  # summary chip present


def test_page_highlights_divergent_mcp(monkeypatch, tmp_path) -> None:
    """Same MCP name, different launch command on two machines → divergent."""
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine(s, "m1")
            _seed_machine(s, "m2")
            mcp_baseline_service.update_and_detect(s, "m1", [_mcp("notion", command="npx")])
            mcp_baseline_service.update_and_detect(
                s, "m2", [_mcp("notion", command="/tmp/evil-npx")]
            )
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get("/admin/mcp-inventory", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert 'class="divbadge"' in r.text


def test_page_no_divergence_when_hashes_match(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine(s, "m1")
            _seed_machine(s, "m2")
            mcp_baseline_service.update_and_detect(s, "m1", [_mcp("notion")])
            mcp_baseline_service.update_and_detect(s, "m2", [_mcp("notion")])
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get("/admin/mcp-inventory", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert 'class="divbadge"' not in r.text


# --- drill-down partial --------------------------------------------------


def test_drill_partial_lists_machines_and_status(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine(s, "m1")
            _seed_machine(s, "m2")
            mcp_baseline_service.update_and_detect(s, "m1", [_mcp("notion")])
            mcp_baseline_service.update_and_detect(s, "m2", [_mcp("notion")])
            s.commit()
            mcp_baseline_service.mark_reviewed(s, "m1", "notion", reviewed_by="alice")
            sid = create_session(s, user_id="admin")

        r = client.get(
            "/_partials/mcp-inventory/drill?name=notion",
            cookies={"ccg_session": sid},
        )
        assert r.status_code == 200
        assert "m1" in r.text
        assert "m2" in r.text
        assert "проверено" in r.text
        assert "alice" in r.text


def test_drill_partial_unknown_name_empty(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        r = client.get(
            "/_partials/mcp-inventory/drill?name=ghost",
            cookies={"ccg_session": sid},
        )
        assert r.status_code == 200
        assert "Ничего не найдено" in r.text


# --- review actions --------------------------------------------------------


def test_review_marks_one_machine_active(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine(s, "m1")
            mcp_baseline_service.update_and_detect(s, "m1", [_mcp("notion")])
            s.commit()
            sid = create_session(s, user_id="admin")

        token = _csrf(client, sid)
        r = client.post(
            "/admin/mcp-inventory/review",
            data={"csrf_token": token, "machine_id": "m1", "mcp_name": "notion"},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(engine) as s:
            row = s.exec(select(MCPServerBaseline)).one()
            assert row.status == "active"
            assert row.accepted_by == "admin"


def test_review_all_flips_only_pending(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed_machine(s, "m1")
            _seed_machine(s, "m2")
            _seed_machine(s, "m3")
            mcp_baseline_service.update_and_detect(s, "m1", [_mcp("notion")])
            mcp_baseline_service.update_and_detect(s, "m2", [_mcp("notion")])
            mcp_baseline_service.update_and_detect(s, "m3", [_mcp("notion")])
            s.commit()
            mcp_baseline_service.mark_reviewed(s, "m2", "notion", reviewed_by="alice")
            sid = create_session(s, user_id="admin")

        token = _csrf(client, sid)
        r = client.post(
            "/admin/mcp-inventory/review-all",
            data={"csrf_token": token, "mcp_name": "notion"},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(engine) as s:
            rows = {r.machine_id: r for r in s.exec(select(MCPServerBaseline)).all()}
            assert rows["m1"].status == "active"
            assert rows["m1"].accepted_by == "admin"
            assert rows["m3"].status == "active"
            assert rows["m2"].accepted_by == "alice"  # untouched, already reviewed


def test_review_requires_auth(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        r = client.post(
            "/admin/mcp-inventory/review",
            data={"machine_id": "m1", "mcp_name": "notion"},
            follow_redirects=False,
        )
        assert r.status_code in (307, 401, 403)


def test_page_requires_auth(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        r = client.get("/admin/mcp-inventory", follow_redirects=False)
        assert r.status_code in (307, 401, 403)
