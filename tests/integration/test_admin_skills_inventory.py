"""Tests for /admin/skills-inventory fleet page and HTMX drill-down."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import (
    AgentBaseline,
    Machine,
    SkillBaseline,
)
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.skill_baseline_service import (
    compute_fingerprint as skill_fp,
)
from ccguard.server.services.agent_baseline_service import (
    compute_fingerprint as agent_fp,
)

from tests.integration.conftest import VALID_TOKEN


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _login(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-fleet")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed(s: Session, machine_id: str) -> None:
    if s.get(Machine, machine_id) is None:
        s.add(Machine(
            machine_id=machine_id, machine_label=machine_id,
            first_seen=_now(), last_seen=_now(), agent_version="0.3.0",
        ))


def _skill_row(s, m, name, dir_hash, *, parent="claude-mem", market="anthropics/cc-plugins"):
    s.add(SkillBaseline(
        machine_id=m, name=name, origin="plugin",
        parent_plugin=parent, source_marketplace=market,
        dir_hash=dir_hash, has_referenced_scripts=False,
        fingerprint=skill_fp(name, "plugin", parent, dir_hash),
        status="active", first_seen_at=_now(), last_seen_at=_now(),
    ))


def _agent_row(s, m, name, file_hash):
    s.add(AgentBaseline(
        machine_id=m, name=name, origin="local",
        parent_plugin=None, source_marketplace=None,
        file_hash=file_hash, tools_csv="Read", model=None,
        fingerprint=agent_fp(name, "local", None, file_hash),
        status="active", first_seen_at=_now(), last_seen_at=_now(),
    ))


def test_page_renders_empty(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        r = client.get("/admin/skills-inventory", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Артефакты флита" in r.text
        assert "Пока ни одного skill baseline" in r.text


def test_page_shows_skill_and_agent_aggregation(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed(s, "m1"); _seed(s, "m2")
            _skill_row(s, "m1", "mem-skill", "AAAA")
            _skill_row(s, "m2", "mem-skill", "AAAA")  # same hash → not divergent
            _agent_row(s, "m1", "my-agent", "BB")
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get("/admin/skills-inventory", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "mem-skill" in r.text
        assert "my-agent" in r.text
        # source attribution displayed
        assert "claude-mem@anthropics/cc-plugins" in r.text
        # No divergence badge expected
        assert "divergent" not in r.text


def test_page_highlights_divergent_skill(monkeypatch, tmp_path) -> None:
    """Same name on two machines with different dir_hash → row highlighted divergent."""
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed(s, "m1"); _seed(s, "m2")
            _skill_row(s, "m1", "diverg", "AAAA")
            _skill_row(s, "m2", "diverg", "BBBB")  # different hash
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get("/admin/skills-inventory", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "divergent" in r.text
        assert "расхождения skills: 1" in r.text


def test_drill_partial_returns_machine_list(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _seed(s, "m1"); _seed(s, "m2")
            _skill_row(s, "m1", "drill-me", "X")
            _skill_row(s, "m2", "drill-me", "Y")
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get(
            "/_partials/skills-inventory/drill"
            "?kind=skill&name=drill-me&origin=plugin&parent_plugin=claude-mem",
            cookies={"ccg_session": sid},
        )
        assert r.status_code == 200
        assert "m1" in r.text
        assert "m2" in r.text
