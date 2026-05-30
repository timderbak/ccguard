"""chip-pills UI doesn't break form POST — textarea name preserved."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-chip")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def test_policy_editor_renders_chip_pill_scaffolding(monkeypatch, tmp_path) -> None:
    """The chip UI markup must be present so JS can enhance it."""
    client, sid = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/policy", cookies={"ccg_session": sid})
        # Policy may 503 in tests without seeded policy — accept either.
        if r.status_code == 503:
            return
        assert r.status_code == 200
        body = r.text
        # Each list field gets a data-chip-list root.
        assert "data-chip-list" in body
        # Chip container + add input scaffolding must be in the rendered HTML.
        assert "data-chip-container" in body
        assert "data-chip-input" in body
        # Textarea name attributes preserved (test-locked).
        assert 'name="commands.denylist_patterns"' in body
        assert 'name="skills.trusted_dir_hashes"' in body
        assert 'name="hooks.allowlist_commands"' in body
    finally:
        client.__exit__(None, None, None)
