"""Phase 4 / 04-02: integration tests for the «Обязательные» admin UI tab.

Covers:
- Task 1: tab strip + /policy/mandatory page + 4 sections + GET /policy/mandatory/_row
- Task 2: POST /policy/draft parses indexed required_*/managed_claude_md_blocks
  fields, validates with Pydantic, redirects per hidden ``tab`` field, injects
  ``_managed_by: "ccguard"`` on every required_mcp_servers entry server-side.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import PolicyVersion
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.web.csrf import generate_csrf_token


_BASE_YAML = (
    "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
)


@pytest.fixture
def client_session(monkeypatch, tmp_path):
    """A logged-in TestClient + sid + csrf token, with a baseline rev=1 published policy."""
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")
    monkeypatch.setenv("CCGUARD_TOKENS", "test-tok")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            s.add(
                PolicyVersion(
                    revision=1,
                    status="published",
                    yaml_text=_BASE_YAML,
                    created_by="admin",
                )
            )
            sid = create_session(s, user_id="admin")
        csrf = generate_csrf_token(secret="s", session_id=sid)
        yield client, sid, csrf, engine


# ---------------------------------------------------------------------------
# Task 1 — tab strip + new page + row partial endpoint
# ---------------------------------------------------------------------------


def test_renders_tabs(client_session):
    client, sid, _csrf, _engine = client_session

    # /policy tab strip active=rules
    r = client.get("/policy", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "Разделы политики" in r.text
    assert "Правила" in r.text
    assert "Обязательные" in r.text

    # /policy/mandatory renders all 4 cards + locked RU copy
    r = client.get("/policy/mandatory", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text[:500]
    assert "Разделы политики" in r.text
    assert "Обязательные" in r.text
    assert "MCP-серверы (обязательные)" in r.text
    assert "Скиллы (обязательные)" in r.text
    assert "Агенты (обязательные)" in r.text
    assert "Управляемые блоки CLAUDE.md" in r.text
    assert "+ добавить сервер" in r.text
    assert "+ добавить скилл" in r.text
    assert "+ добавить агента" in r.text
    assert "+ добавить блок" in r.text
    # empty-state copy for each section
    assert r.text.count("Записей нет.") >= 4
    # save / publish bar present
    assert "Сохранить черновик" in r.text
    assert "Опубликовать" in r.text


def test_row_partial_endpoint(client_session):
    client, sid, _csrf, _engine = client_session

    # MCP server row
    r = client.get(
        "/policy/mandatory/_row",
        params={"section": "required_mcp_servers", "i": 3},
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert 'name="required_mcp_servers[3].name"' in r.text
    assert 'name="required_mcp_servers[3].command"' in r.text
    assert 'name="required_mcp_servers[3].args"' in r.text
    assert 'name="required_mcp_servers[3].env"' in r.text
    assert "удалить" in r.text

    # Skill row
    r = client.get(
        "/policy/mandatory/_row",
        params={"section": "required_skills", "i": 0},
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert 'name="required_skills[0].name"' in r.text
    assert 'name="required_skills[0].frontmatter_type"' in r.text
    assert 'name="required_skills[0].content"' in r.text
    assert "min-h-[120px]" in r.text

    # Agent row
    r = client.get(
        "/policy/mandatory/_row",
        params={"section": "required_agents", "i": 5},
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert 'name="required_agents[5].name"' in r.text
    assert 'name="required_agents[5].content"' in r.text

    # Managed CLAUDE.md block row
    r = client.get(
        "/policy/mandatory/_row",
        params={"section": "managed_claude_md_blocks", "i": 2},
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert 'name="managed_claude_md_blocks[2].id"' in r.text
    assert 'pattern="[a-z0-9]+(-[a-z0-9]+)*"' in r.text
    assert 'name="managed_claude_md_blocks[2].description"' in r.text
    assert 'name="managed_claude_md_blocks[2].content"' in r.text

    # Unknown section -> 404
    r = client.get(
        "/policy/mandatory/_row",
        params={"section": "nope", "i": 0},
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Task 2 — form parser + draft + validation + publish round-trip
# ---------------------------------------------------------------------------


def test_draft_persists_all_four_sections_and_redirects_to_mandatory(client_session):
    client, sid, csrf, engine = client_session

    form_data = {
        "csrf_token": csrf,
        "tab": "mandatory",
        # MCP
        "required_mcp_servers[0].name": "stripe",
        "required_mcp_servers[0].command": "/usr/bin/x",
        "required_mcp_servers[0].args": "a, b, c",
        "required_mcp_servers[0].env": '{"K":"v"}',
        # Skill
        "required_skills[0].name": "sec",
        "required_skills[0].frontmatter_type": "skill",
        "required_skills[0].content": "---\nname: sec\n---\nbody",
        # Agent
        "required_agents[0].name": "rev",
        "required_agents[0].content": "agent body",
        # Block
        "managed_claude_md_blocks[0].id": "security-rules",
        "managed_claude_md_blocks[0].description": "d",
        "managed_claude_md_blocks[0].content": "X",
    }
    r = client.post(
        "/policy/draft",
        data=form_data,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text[:500]
    assert r.headers["location"] == "/policy/mandatory"

    # Inspect the draft row
    with Session(engine) as s:
        drafts = list(
            s.exec(
                PolicyVersion.__table__.select()  # type: ignore[attr-defined]
                .where(PolicyVersion.status == "draft")
            )
        )
        assert len(drafts) == 1
        data = yaml.safe_load(drafts[0].yaml_text)
        assert data["required_mcp_servers"] == [
            {
                "name": "stripe",
                "command": "/usr/bin/x",
                "args": ["a", "b", "c"],
                "env": {"K": "v"},
                "_managed_by": "ccguard",
            }
        ]
        assert data["required_skills"][0]["name"] == "sec"
        assert data["required_skills"][0]["frontmatter_type"] == "skill"
        assert data["required_skills"][0]["content"] == "---\nname: sec\n---\nbody"
        assert data["required_agents"][0] == {"name": "rev", "content": "agent body"}
        assert data["managed_claude_md_blocks"][0] == {
            "id": "security-rules",
            "description": "d",
            "content": "X",
        }


def test_draft_default_redirects_to_policy_when_tab_missing(client_session):
    client, sid, csrf, _engine = client_session
    # Minimal rules-tab form (mirrors existing /policy editor submission).
    rules_form = {
        "csrf_token": csrf,
        "mcp_servers.severity": "warn",
        "network.severity": "warn",
        "commands.severity": "warn",
        "skills.severity": "warn",
        "hooks.severity": "warn",
        "agents.severity": "warn",
        "env.severity": "warn",
    }
    r = client.post(
        "/policy/draft",
        data=rules_form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/policy"


def test_invalid_env_json_renders_locked_error_notice(client_session):
    client, sid, csrf, _engine = client_session
    r = client.post(
        "/policy/draft",
        data={
            "csrf_token": csrf,
            "tab": "mandatory",
            "required_mcp_servers[0].name": "stripe",
            "required_mcp_servers[0].command": "/usr/bin/x",
            "required_mcp_servers[0].args": "a",
            "required_mcp_servers[0].env": "{not json",
        },
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "Ошибка в MCP-серверах: проверьте name, command и env (валидный JSON)." in r.text
    # form value preserved
    assert "{not json" in r.text


def test_invalid_managed_block_id_renders_locked_error(client_session):
    client, sid, csrf, _engine = client_session
    r = client.post(
        "/policy/draft",
        data={
            "csrf_token": csrf,
            "tab": "mandatory",
            "managed_claude_md_blocks[0].id": "Bad ID",
            "managed_claude_md_blocks[0].description": "",
            "managed_claude_md_blocks[0].content": "x",
        },
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert (
        "Ошибка в блоках: id должен быть kebab-case (буквы/цифры/дефис); "
        "content не пустой." in r.text
    )


def test_publish_round_trip_exposes_sections_via_api(client_session):
    client, sid, csrf, _engine = client_session

    form_data = {
        "csrf_token": csrf,
        "tab": "mandatory",
        "required_mcp_servers[0].name": "stripe",
        "required_mcp_servers[0].command": "/usr/bin/x",
        "required_mcp_servers[0].args": "a, b",
        "required_mcp_servers[0].env": '{"K":"v"}',
        "required_skills[0].name": "sec",
        "required_skills[0].frontmatter_type": "skill",
        "required_skills[0].content": "body",
        "required_agents[0].name": "rev",
        "required_agents[0].content": "x",
        "managed_claude_md_blocks[0].id": "security-rules",
        "managed_claude_md_blocks[0].description": "",
        "managed_claude_md_blocks[0].content": "X",
    }
    r = client.post(
        "/policy/draft",
        data=form_data,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303

    r = client.post(
        "/policy/publish",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303

    # GET /api/v1/policy with valid agent token
    r = client.get("/api/v1/policy", headers={"X-CCGuard-Token": "test-tok"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["meta"]["revision"] == 2
    assert body["required_mcp_servers"][0]["name"] == "stripe"
    assert body["required_mcp_servers"][0]["args"] == ["a", "b"]
    assert body["required_mcp_servers"][0]["env"] == {"K": "v"}
    assert body["required_skills"][0]["name"] == "sec"
    assert body["required_agents"][0]["name"] == "rev"
    assert body["managed_claude_md_blocks"][0]["id"] == "security-rules"
