"""Integration tests for Plan 03-05 LLM admin routes.

Covers:
  (a) POST /admin/llm-settings — auth, CSRF, validation, persistence.
  (b) POST /admin/scan/{file_hash}/rescan — single <tr> partial, budget /
      disabled inline notices.
  (c) POST /admin/scan/rescan-all — APScheduler one-shot enqueue + ttl expiry.
  (d) GET /_partials/settings/llm-usage — enabled / disabled rendering.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    LLMCallLog,
    ScanResult,
    SettingsRecord,
)
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.settings_service import seed_llm_settings, set_setting
from ccguard.server.web.csrf import generate_csrf_token


@pytest.fixture
def admin_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[tuple[TestClient, str, str]]:
    """Return (client, session_id, csrf_token) with an admin logged in."""
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/admin.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.delenv("CCGUARD_SERVER_CONFIG", raising=False)
    with TestClient(create_app()) as c:
        engine = c.app.state.engine
        with Session(engine) as s:
            seed_llm_settings(s)
            sid = create_session(s, user_id="admin")
        csrf = generate_csrf_token(secret="test-secret", session_id=sid)
        yield c, sid, csrf


def _seed_scan_row(engine, file_hash: str, *, score: int = 85, category: str = "jailbreak") -> None:
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add(
            ScanResult(
                file_hash=file_hash,
                file_path="/agents/evil.md",
                scope="agent",
                risk_score=score,
                category=category,
                rationale="test",
                scanned_at=now,
                model="claude-haiku-4-5-20251001",
                ttl_expires_at=now + timedelta(days=30),
            )
        )
        s.add(
            FindingRecord(
                machine_id="_server",
                inventory_id=None,
                rule_id=f"llm.scan.{category}",
                severity="critical" if score > 70 else "warn",
                discovered_at=now,
                payload_json=json.dumps(
                    {
                        "file_hash": file_hash,
                        "risk_score": score,
                        "category": category,
                        "rationale": "test",
                        "scope": "agent",
                        "file_path": "/agents/evil.md",
                        "model": "claude-haiku-4-5-20251001",
                    }
                ),
            )
        )
        s.commit()


# -------- POST /admin/llm-settings ---------------------------------------


def test_llm_settings_post_without_admin_cookie_rejected(admin_client) -> None:
    client, _sid, _csrf = admin_client
    r = client.post("/admin/llm-settings", data={}, follow_redirects=False)
    assert r.status_code in (401, 403, 307)


def test_llm_settings_post_persists_toggle_and_budget(admin_client) -> None:
    client, sid, csrf = admin_client
    r = client.post(
        "/admin/llm-settings",
        data={"csrf_token": csrf, "enabled": "on", "daily_call_budget": "250"},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/settings"
    engine = client.app.state.engine
    with Session(engine) as s:
        enabled_row = s.get(SettingsRecord, "llm_scanner_enabled")
        budget_row = s.get(SettingsRecord, "daily_call_budget")
        assert enabled_row is not None and enabled_row.value == "true"
        assert budget_row is not None and budget_row.value == "250"


def test_llm_settings_post_invalid_budget_renders_validation_message(admin_client) -> None:
    client, sid, csrf = admin_client
    r = client.post(
        "/admin/llm-settings",
        data={"csrf_token": csrf, "daily_call_budget": "99999"},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "Бюджет должен быть целым числом от 0 до 10000." in r.text


# -------- POST /admin/scan/{file_hash}/rescan ----------------------------


def test_rescan_returns_single_tr_partial(admin_client) -> None:
    client, sid, csrf = admin_client
    fh = "a" * 64
    _seed_scan_row(client.app.state.engine, fh)
    # Make scanner enabled + budget remaining so no notice.
    with Session(client.app.state.engine) as s:
        set_setting(s, "llm_scanner_enabled", "true")
        set_setting(s, "daily_call_budget", "100")
    r = client.post(
        f"/admin/scan/{fh}/rescan",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    body = r.text.strip()
    assert body.startswith("<tr"), f"first tag not <tr>: {body[:80]!r}"
    assert "<table" not in body


def test_rescan_when_budget_exhausted_inline_notice(admin_client) -> None:
    client, sid, csrf = admin_client
    fh = "b" * 64
    _seed_scan_row(client.app.state.engine, fh)
    engine = client.app.state.engine
    with Session(engine) as s:
        set_setting(s, "llm_scanner_enabled", "true")
        set_setting(s, "daily_call_budget", "1")
        # one used = exhausted (budget=1, used=1)
        s.add(
            LLMCallLog(
                ts=datetime.now(UTC),
                file_hash="x" * 64,
                model="claude-haiku-4-5-20251001",
                input_tokens=10,
                output_tokens=5,
                cost_estimate_cents=1,
            )
        )
        s.commit()
    r = client.post(
        f"/admin/scan/{fh}/rescan",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "бюджет исчерпан" in r.text


def test_rescan_when_scanner_disabled_inline_notice(admin_client) -> None:
    client, sid, csrf = admin_client
    fh = "c" * 64
    _seed_scan_row(client.app.state.engine, fh)
    with Session(client.app.state.engine) as s:
        set_setting(s, "llm_scanner_enabled", "false")
    r = client.post(
        f"/admin/scan/{fh}/rescan",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "сканер выключен" in r.text


def test_rescan_unknown_file_hash_returns_404(admin_client) -> None:
    client, sid, csrf = admin_client
    r = client.post(
        "/admin/scan/" + ("d" * 64) + "/rescan",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 404


# -------- POST /admin/scan/rescan-all ------------------------------------


def test_rescan_all_expires_every_scan_result(admin_client) -> None:
    client, sid, csrf = admin_client
    engine = client.app.state.engine
    _seed_scan_row(engine, "e" * 64)
    _seed_scan_row(engine, "f" * 64, score=20, category="benign")
    r = client.post(
        "/admin/scan/rescan-all",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/settings"
    # Job runs in-process synchronously (one-shot scheduler job). Poll briefly.
    import time
    now = datetime.now(UTC)
    deadline = time.time() + 5
    while time.time() < deadline:
        with Session(engine) as s:
            rows = list(s.exec(select(ScanResult)))
            if all(
                (r.ttl_expires_at if r.ttl_expires_at.tzinfo else r.ttl_expires_at.replace(tzinfo=UTC)) < now
                for r in rows
            ):
                break
        time.sleep(0.1)
    with Session(engine) as s:
        rows = list(s.exec(select(ScanResult)))
        assert rows, "seeded rows missing"
        for r in rows:
            ttl = r.ttl_expires_at if r.ttl_expires_at.tzinfo else r.ttl_expires_at.replace(tzinfo=UTC)
            assert ttl < now, f"row not expired: {ttl}"


# -------- GET /_partials/settings/llm-usage ------------------------------


def test_llm_usage_partial_when_enabled_shows_usage_text(admin_client) -> None:
    client, sid, _csrf = admin_client
    with Session(client.app.state.engine) as s:
        set_setting(s, "llm_scanner_enabled", "true")
        set_setting(s, "daily_call_budget", "100")
    r = client.get(
        "/_partials/settings/llm-usage",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert "Использовано:" in r.text
    assert "$" in r.text


def test_llm_usage_partial_when_disabled_shows_off_text(admin_client) -> None:
    client, sid, _csrf = admin_client
    with Session(client.app.state.engine) as s:
        set_setting(s, "llm_scanner_enabled", "false")
    r = client.get(
        "/_partials/settings/llm-usage",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert "Сканер выключен." in r.text
