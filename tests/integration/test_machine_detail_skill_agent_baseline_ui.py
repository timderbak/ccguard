"""Routes + UI smoke для skill/agent baselines (parallels test_machine_detail_hook_baseline_ui)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    AgentBaseline,
    FindingRecord,
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
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-skill-agent")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _ensure_machine(s: Session, machine_id: str) -> None:
    if s.get(Machine, machine_id) is None:
        s.add(Machine(
            machine_id=machine_id, machine_label="sa-test",
            first_seen=_now(), last_seen=_now(), agent_version="0.3.0",
        ))


def _csrf(client: TestClient, machine_id: str, sid: str) -> str:
    r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text
    marker = 'name="csrf_token" value="'
    return r.text.split(marker, 1)[1].split('"', 1)[0]


# --- Skill routes ---------------------------------------------------------


def test_skill_accept_single_route(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        m = "m-sa-skill-accept"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _ensure_machine(s, m)
            row = SkillBaseline(
                machine_id=m, name="demo", origin="local",
                parent_plugin=None, source_marketplace=None,
                dir_hash="AAA", has_referenced_scripts=False,
                fingerprint=skill_fp("demo", "local", None, "AAA"),
                status="pending", first_seen_at=_now(), last_seen_at=_now(),
            )
            s.add(row); s.commit(); s.refresh(row)
            row_id = row.id
            sid = create_session(s, user_id="admin")

        token = _csrf(client, m, sid)
        resp = client.post(
            f"/machines/{m}/skill-baseline/{row_id}/accept",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with Session(engine) as s:
            fresh = s.exec(select(SkillBaseline)).one()
            assert fresh.status == "active"
            assert fresh.accepted_by == "admin"


def test_skill_accept_all_pending_route(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        m = "m-sa-skill-bulk"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _ensure_machine(s, m)
            for n in ("a", "b"):
                s.add(SkillBaseline(
                    machine_id=m, name=n, origin="local",
                    parent_plugin=None, source_marketplace=None,
                    dir_hash="X", has_referenced_scripts=False,
                    fingerprint=skill_fp(n, "local", None, "X"),
                    status="pending", first_seen_at=_now(), last_seen_at=_now(),
                ))
            s.commit()
            sid = create_session(s, user_id="admin")

        token = _csrf(client, m, sid)
        resp = client.post(
            f"/machines/{m}/skill-baseline/accept-all-pending",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with Session(engine) as s:
            rows = s.exec(select(SkillBaseline)).all()
            assert all(r.status == "active" for r in rows)


def test_skill_reject_route(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        m = "m-sa-skill-reject"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _ensure_machine(s, m)
            row = SkillBaseline(
                machine_id=m, name="demo", origin="local",
                parent_plugin=None, source_marketplace=None,
                dir_hash="AAA", has_referenced_scripts=False,
                fingerprint=skill_fp("demo", "local", None, "AAA"),
                status="pending", first_seen_at=_now(), last_seen_at=_now(),
            )
            s.add(row); s.commit(); s.refresh(row)
            row_id = row.id
            sid = create_session(s, user_id="admin")

        token = _csrf(client, m, sid)
        resp = client.post(
            f"/machines/{m}/skill-baseline/{row_id}/reject",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with Session(engine) as s:
            assert s.exec(select(SkillBaseline)).one().status == "removed"


# --- Agent routes ---------------------------------------------------------


def test_agent_accept_route(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        m = "m-sa-agent-accept"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _ensure_machine(s, m)
            row = AgentBaseline(
                machine_id=m, name="demo", origin="local",
                parent_plugin=None, source_marketplace=None,
                file_hash="AAA", tools_csv="Read", model=None,
                fingerprint=agent_fp("demo", "local", None, "AAA"),
                status="pending", first_seen_at=_now(), last_seen_at=_now(),
            )
            s.add(row); s.commit(); s.refresh(row)
            row_id = row.id
            sid = create_session(s, user_id="admin")

        token = _csrf(client, m, sid)
        resp = client.post(
            f"/machines/{m}/agent-baseline/{row_id}/accept",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with Session(engine) as s:
            assert s.exec(select(AgentBaseline)).one().status == "active"


# --- UI: bootstrap banners + drift cards ----------------------------------


def test_skill_bootstrap_banner_renders_with_pending(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        m = "m-sa-skill-banner"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _ensure_machine(s, m)
            for n in ("a", "b", "c"):
                s.add(SkillBaseline(
                    machine_id=m, name=n, origin="local",
                    parent_plugin=None, source_marketplace=None,
                    dir_hash="X", has_referenced_scripts=False,
                    fingerprint=skill_fp(n, "local", None, "X"),
                    status="pending", first_seen_at=_now(), last_seen_at=_now(),
                ))
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get(f"/machines/{m}", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Найдено 3" in r.text
        assert "скилла" in r.text  # plural for 3
        assert f'action="/machines/{m}/skill-baseline/accept-all-pending"' in r.text


def test_agent_drift_card_renders_with_dangerous_tools(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        m = "m-sa-agent-drift"
        engine = client.app.state.engine  # type: ignore[attr-defined]
        with Session(engine) as s:
            _ensure_machine(s, m)
            row = AgentBaseline(
                machine_id=m, name="risky", origin="local",
                parent_plugin=None, source_marketplace=None,
                file_hash="NEWHASH", tools_csv="Bash,Read", model=None,
                fingerprint=agent_fp("risky", "local", None, "NEWHASH"),
                status="active", first_seen_at=_now(), last_seen_at=_now(),
            )
            s.add(row); s.commit(); s.refresh(row)
            row_id = row.id
            s.add(FindingRecord(
                machine_id=m,
                rule_id="agent.rug_pull.dangerous",
                severity="block",
                discovered_at=_now(),
                payload_json=json.dumps({
                    "rule_id": "agent.rug_pull.dangerous",
                    "severity": "block",
                    "title": "Изменился субагент «risky» с опасными tools",
                    "description": "Промпт изменился, есть Bash.",
                    "name": "risky", "origin": "local",
                    "parent_plugin": None, "source_marketplace": None,
                    "old_file_hash": "OLDHASH", "new_file_hash": "NEWHASH",
                    "path": "/tmp/agents/risky.md",
                    "tools": ["Bash", "Read"],
                }),
            ))
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get(f"/machines/{m}", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        assert "Изменился субагент" in r.text
        assert "OLDHASH" in r.text and "NEWHASH" in r.text
        # Dangerous tool badge in red.
        assert "Bash" in r.text
        # Accept/reject buttons present.
        assert f"/agent-baseline/{row_id}/accept" in r.text
        assert f"/agent-baseline/{row_id}/reject" in r.text
