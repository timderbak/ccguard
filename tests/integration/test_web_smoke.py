"""Smoke test: web routes exist and serve HTML."""

from __future__ import annotations

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
        assert "compliant" in r.text.lower()


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
        assert "Machines (1)" in r.text


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
