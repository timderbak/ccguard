"""Smoke test: web routes exist and serve HTML."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ccguard.server.main import create_app


def test_login_page_renders() -> None:
    app = create_app()
    client = TestClient(app)
    r = client.get("/login")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "ccguard" in r.text.lower()


def test_overview_renders_fleet_table(monkeypatch, tmp_path):
    import json
    from datetime import UTC, datetime

    from sqlmodel import Session

    from ccguard.server.db.models import InventorySnapshot, Machine, PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(
                PolicyVersion(
                    revision=1,
                    status="published",
                    yaml_text="meta:\n  revision: 1",
                    created_by="admin",
                )
            )
            s.add(
                Machine(
                    machine_id="m1",
                    machine_label="laptop",
                    first_seen=now,
                    last_seen=now,
                    agent_version="0.1.0",
                )
            )
            s.add(
                InventorySnapshot(
                    machine_id="m1",
                    received_at=now,
                    payload_json=json.dumps({"meta": {"revision": 1}}),
                )
            )
            sid = create_session(s, user_id="admin")
        r = client.get("/", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "laptop" in r.text
        assert "соответствует" in r.text


def test_machines_list_renders(monkeypatch, tmp_path):
    from datetime import UTC, datetime

    from sqlmodel import Session

    from ccguard.server.db.models import Machine
    from ccguard.server.services.auth_service import create_session, hash_password

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(
                Machine(
                    machine_id="m1",
                    machine_label="laptop",
                    first_seen=now,
                    last_seen=now,
                    agent_version="0.1.0",
                )
            )
            sid = create_session(s, user_id="admin")
        r = client.get("/machines", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "laptop" in r.text
        assert "Машины (1)" in r.text


def test_machine_detail_renders_inventory(monkeypatch, tmp_path):
    import json
    from datetime import UTC, datetime

    from sqlmodel import Session

    from ccguard.server.db.models import InventorySnapshot, Machine
    from ccguard.server.services.auth_service import create_session, hash_password

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(
                Machine(
                    machine_id="m1",
                    machine_label="laptop",
                    first_seen=now,
                    last_seen=now,
                    agent_version="0.1.0",
                )
            )
            s.add(
                InventorySnapshot(
                    machine_id="m1",
                    received_at=now,
                    payload_json=json.dumps({"mcp_servers": [{"name": "fs"}]}),
                )
            )
            sid = create_session(s, user_id="admin")
        r = client.get("/machines/m1", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "laptop" in r.text
        assert "fs" in r.text

        r404 = client.get("/machines/missing", cookies={"ccg_session": sid})
        assert r404.status_code == 404


def test_findings_feed_renders_with_filter(monkeypatch, tmp_path):
    from datetime import UTC, datetime

    from sqlmodel import Session

    from ccguard.server.db.models import FindingRecord
    from ccguard.server.services.auth_service import create_session, hash_password

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(
                FindingRecord(
                    machine_id="m1",
                    inventory_id=1,
                    rule_id="agents.forbidden_tool",
                    severity="warn",
                    discovered_at=now,
                    payload_json="{}",
                )
            )
            sid = create_session(s, user_id="admin")
        r = client.get(
            "/findings?rule_id=agents.forbidden_tool",
            cookies={"ccg_session": sid},
        )
        assert r.status_code == 200
        assert "agents.forbidden_tool" in r.text


def test_revoke_machine_deletes_row(monkeypatch, tmp_path):
    from datetime import UTC, datetime

    from sqlmodel import Session

    from ccguard.server.db.models import Machine
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.web.csrf import generate_csrf_token

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(
                Machine(
                    machine_id="m1",
                    machine_label="laptop",
                    first_seen=now,
                    last_seen=now,
                    agent_version="0.1.0",
                )
            )
            sid = create_session(s, user_id="admin")
        token = generate_csrf_token(secret="test-secret", session_id=sid)
        r = client.post(
            "/machines/m1/revoke",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/machines"
        with Session(engine) as s:
            assert s.get(Machine, "m1") is None


def test_policy_editor_renders_current_policy(monkeypatch, tmp_path) -> None:
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            s.add(
                PolicyVersion(
                    revision=1, status="published",
                    yaml_text=(
                        "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
                        "mcp_servers:\n  severity: warn\n  allowlist_names: [filesystem]\n"
                    ),
                    created_by="admin",
                )
            )
            sid = create_session(s, user_id="admin")
        r = client.get("/policy", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "filesystem" in r.text  # current allowlist appears in form


def test_policy_editor_has_all_sections(monkeypatch, tmp_path) -> None:
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    yaml_text = (
        "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
    )
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            s.add(PolicyVersion(revision=1, status="published",
                                yaml_text=yaml_text, created_by="admin"))
            sid = create_session(s, user_id="admin")
        r = client.get("/policy", cookies={"ccg_session": sid})
        for needle in ["MCP-серверы", "Сеть", "Команды", "Навыки", "Хуки", "Агенты", "Переменные окружения"]:
            assert needle in r.text, f"missing section: {needle}"


def test_save_draft_then_publish_bumps_revision(monkeypatch, tmp_path) -> None:
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            s.add(PolicyVersion(
                revision=1, status="published",
                yaml_text=(
                    "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
                ),
                created_by="admin",
            ))
            sid = create_session(s, user_id="admin")
        csrf = generate_csrf_token(secret="s", session_id=sid)

        form_data = {
            "csrf_token": csrf,
            "mcp_servers.severity": "warn",
            "mcp_servers.allowlist_names": "filesystem",
            "mcp_servers.denylist_names": "",
            "mcp_servers.denylist_url_patterns": "",
            "network.severity": "warn",
            "network.allowlist_hosts": "",
            "network.denylist_hosts": "",
            "commands.severity": "warn",
            "commands.denylist_patterns": "",
            "commands.allowlist_patterns": "",
            "skills.severity": "warn",
            "skills.allowlist_names": "",
            "skills.trusted_dir_hashes": "",
            "hooks.severity": "warn",
            "hooks.allowlist_commands": "",
            "hooks.deny_unknown": "1",
            "agents.severity": "warn",
            "agents.allowlist_names": "",
            "agents.denylist_names": "",
            "agents.denylist_tools": "Bash",
            "agents.trusted_file_hashes": "",
            "env.severity": "warn",
            "env.denylist_patterns": "",
            "env.allowlist_names": "",
        }
        r = client.post("/policy/publish", data=form_data,
                        cookies={"ccg_session": sid}, follow_redirects=False)
        assert r.status_code == 303
        with Session(engine) as s:
            rows = list(s.exec(PolicyVersion.__table__.select()  # type: ignore[attr-defined]
                               .where(PolicyVersion.status == "published")))
            assert any(row.revision == 2 for row in rows)


def test_policy_history_rollback(monkeypatch, tmp_path):
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.services.policy_service import get_draft
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")

    yaml_text = "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            s.add(PolicyVersion(id=1, revision=1, status="archived",
                                yaml_text=yaml_text, created_by="admin"))
            s.add(PolicyVersion(revision=2, status="published",
                                yaml_text=yaml_text, created_by="admin"))
            sid = create_session(s, user_id="admin")
        csrf = generate_csrf_token(secret="s", session_id=sid)

        r = client.get("/policy/history", cookies={"ccg_session": sid})
        assert r.status_code == 200

        r = client.post(
            "/policy/rollback/1",
            data={"csrf_token": csrf},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 303
        with Session(engine) as s:
            assert get_draft(s) is not None


def test_settings_create_and_revoke_token(monkeypatch, tmp_path) -> None:
    from ccguard.server.db.models import AgentToken
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session, select

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        csrf = generate_csrf_token(secret="s", session_id=sid)

        r = client.get("/settings", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Токены агентов" in r.text

        r = client.post(
            "/settings/tokens",
            data={"csrf_token": csrf, "label": "laptop"},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "new_token=" in r.headers["location"]

        with Session(engine) as s:
            rows = list(s.exec(select(AgentToken)))
            assert len(rows) == 1
            assert rows[0].label == "laptop"
            token_id = rows[0].id

        r = client.post(
            f"/settings/tokens/{token_id}/revoke",
            data={"csrf_token": csrf},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 303
        with Session(engine) as s:
            row = s.get(AgentToken, token_id)
            assert row is not None
            assert row.revoked_at is not None


def test_change_admin_password(monkeypatch, tmp_path) -> None:
    from ccguard.server.services.auth_service import (
        create_session,
        hash_password,
        verify_password,
    )
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    hash_file = tmp_path / "admin_hash.txt"
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("old-pass"))
    monkeypatch.setenv("CCGUARD_ADMIN_HASH_FILE", str(hash_file))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            sid = create_session(s, user_id="admin")
        csrf = generate_csrf_token(secret="s", session_id=sid)

        # wrong current password rejected
        r = client.post(
            "/settings/password",
            data={
                "csrf_token": csrf,
                "current_password": "wrong",
                "new_password": "new-pass-123",
            },
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 401

        # correct current password accepted
        r = client.post(
            "/settings/password",
            data={
                "csrf_token": csrf,
                "current_password": "old-pass",
                "new_password": "new-pass-123",
            },
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "password_msg=" in r.headers["location"]

        assert hash_file.exists()
        new_hash = hash_file.read_text().strip()
        assert verify_password("new-pass-123", new_hash)
        assert not verify_password("old-pass", new_hash)


