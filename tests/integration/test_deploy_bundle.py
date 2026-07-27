"""Выдача конфига для раскатки: API для сборщика и страница для админа.

Проверяется в первую очередь то, чего в ответе быть НЕ должно: реального
токена. Один токен, вшитый в образ, компрометирует весь флот при утечке и
останавливает весь флот при отзыве.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import Machine
from ccguard.server.main import create_app
from ccguard.server.services import deploy_config_service as dcs
from ccguard.server.services.auth_service import create_session, hash_password
from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-deploy")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _sid(engine) -> str:
    with Session(engine) as s:
        return create_session(s, user_id="admin")


# --- API для сборщика -------------------------------------------------------


def test_bundle_requires_a_token(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        r = client.get("/api/v1/deploy/bundle")
    assert r.status_code == 401


def test_bundle_returns_hooks_and_paths(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        r = client.get(
            "/api/v1/deploy/bundle?platform=linux",
            headers={"X-CCGuard-Token": VALID_TOKEN},
        )
    assert r.status_code == 200
    b = r.json()
    assert b["managed_settings_path"] == "/etc/claude-code/managed-settings.json"
    assert set(b["managed_settings"]["hooks"]) == {"PreToolUse", "PostToolUse"}
    assert b["expected_hooks_hash"]


def test_bundle_carries_no_real_token(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        r = client.get(
            "/api/v1/deploy/bundle?platform=linux",
            headers={"X-CCGuard-Token": VALID_TOKEN},
        )
    assert VALID_TOKEN not in r.text
    assert dcs.TOKEN_PLACEHOLDER in r.json()["agent_config"]


def test_unknown_platform_is_a_400(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        r = client.get(
            "/api/v1/deploy/bundle?platform=plan9",
            headers={"X-CCGuard-Token": VALID_TOKEN},
        )
    assert r.status_code == 400


# --- страница для админа ----------------------------------------------------


def test_page_shows_the_managed_config(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        r = client.get("/admin/deploy", cookies={"ccg_session": _sid(eng)})
    assert r.status_code == 200
    assert "/etc/claude-code/managed-settings.json" in r.text
    assert dcs.TOKEN_PLACEHOLDER in r.text
    # Почему токена нет — объяснено прямо на странице, а не только в коде.
    assert "хранилища секретов" in r.text


def test_page_warns_when_the_server_url_is_only_a_guess(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        r = client.get("/admin/deploy", cookies={"ccg_session": _sid(eng)})
    assert "Адрес не задан" in r.text


def test_saving_the_url_puts_it_into_the_config(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        sid = _sid(eng)
        client.cookies.set("ccg_session", sid)
        page = client.get("/admin/deploy")
        marker = 'name="csrf_token" value="'
        i = page.text.index(marker) + len(marker)
        token = page.text[i:page.text.index('"', i)]

        r = client.post(
            "/admin/deploy/server-url",
            data={"csrf_token": token, "server_url": "https://ccguard.corp",
                  "platform": "linux"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        after = client.get("/admin/deploy")
    assert "https://ccguard.corp" in after.text
    assert "Адрес не задан" not in after.text


def test_saving_egress_allowlist_puts_default_deny_into_the_config(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        client.cookies.set("ccg_session", _sid(client.app.state.engine))  # type: ignore[attr-defined]
        page = client.get("/admin/deploy")
        marker = 'name="csrf_token" value="'
        i = page.text.index(marker) + len(marker)
        token = page.text[i:page.text.index('"', i)]

        r = client.post(
            "/admin/deploy/egress-allowlist",
            data={"csrf_token": token, "allowlist": "pypi.org, github.com",
                  "platform": "linux"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        after = client.get("/admin/deploy")
    # Раскатанный конфиг теперь несёт default-deny egress с этими доменами.
    assert "pypi.org" in after.text and "github.com" in after.text
    assert "allowManagedDomainsOnly" in after.text
    assert "Egress ограничен" in after.text


def test_page_flags_a_machine_running_a_different_config(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        eng = client.app.state.engine  # type: ignore[attr-defined]
        now = datetime.now(UTC)
        with Session(eng) as s:
            s.add(Machine(machine_id="m-ok", machine_label="ok", last_seen=now,
                          last_heartbeat_at=now - timedelta(minutes=1),
                          hooks_hash=dcs.expected_hooks_hash("linux")))
            s.add(Machine(machine_id="m-other", machine_label="other", last_seen=now,
                          last_heartbeat_at=now - timedelta(minutes=1),
                          hooks_hash="c0ffee" * 10))
            s.commit()
        r = client.get("/admin/deploy", cookies={"ccg_session": _sid(eng)})
    assert "m-other" in r.text
    assert "Расхождений нет" not in r.text


def test_page_requires_auth(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        r = client.get("/admin/deploy")
    assert r.status_code in (401, 403, 303, 307)
