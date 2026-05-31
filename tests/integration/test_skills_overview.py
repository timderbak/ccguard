"""/admin/skills overview — LLM scan results for skill + agent files."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import ScanResult
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-skills-ov")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def _scan(s, *, fh, path, scope, score, cat):
    s.add(ScanResult(
        file_hash=fh, file_path=path, scope=scope,
        risk_score=score, category=cat, rationale="x",
        scanned_at=datetime.now(UTC), model="claude-sonnet-4-6",
        ttl_expires_at=datetime.now(UTC) + timedelta(hours=24),
    ))


def test_empty_page_renders_help_text(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/admin/skills", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "Скан скиллов" in body
        assert "Сканов пока нет" in body
    finally:
        client.__exit__(None, None, None)


def test_renders_scan_rows_with_verdict(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            _scan(s, fh="a" * 64, path="~/.claude/skills/code-rev/SKILL.md",
                  scope="skill", score=5, cat="benign")
            _scan(s, fh="b" * 64, path="~/.claude/skills/sus/SKILL.md",
                  scope="skill", score=85, cat="prompt_injection")
            _scan(s, fh="c" * 64, path="~/.claude/agents/helper.md",
                  scope="agent", score=20, cat="benign")
            s.commit()
        r = client.get("/admin/skills", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "code-rev/SKILL.md" in body
        assert "prompt_injection" in body
        assert "helper.md" in body
        # Stats: total 3, suspicious 1 (only the 85-score one ≥ 40).
        assert ">3</p>" in body  # total
        assert ">1</p>" in body  # suspicious
        # High score row gets red emphasis (font-semibold class).
        assert "text-red-600 font-semibold" in body
    finally:
        client.__exit__(None, None, None)


def test_anonymous_user_blocked(monkeypatch, tmp_path):
    client, _ = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/admin/skills", follow_redirects=False)
        assert r.status_code in (307, 401)
    finally:
        client.__exit__(None, None, None)
