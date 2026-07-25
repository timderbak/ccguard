"""Alert emitter — webhook push of new findings (SIEM / Slack / Telegram)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.services import alert_emitter
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.settings_service import get_setting, set_setting

pytestmark = pytest.mark.integration


def _finding(s: Session, rule_id: str, severity: str, machine="m1") -> int:
    f = FindingRecord(machine_id=machine, inventory_id=None, rule_id=rule_id,
                      severity=severity, discovered_at=datetime.now(UTC), payload_json="{}")
    s.add(f)
    s.commit()
    s.refresh(f)
    return f.id


class _Recorder:
    def __init__(self, ok=True):
        self.calls: list[tuple[str, dict]] = []
        self.ok = ok

    def __call__(self, url: str, body: dict) -> bool:
        self.calls.append((url, body))
        return self.ok


def _enable(s: Session, *, min_severity="block", fmt="generic", chat_id="") -> None:
    set_setting(s, "alert.enabled", "true")
    set_setting(s, "alert.webhook_url", "https://siem.internal/ingest")
    set_setting(s, "alert.min_severity", min_severity)
    set_setting(s, "alert.format", fmt)
    set_setting(s, "alert.telegram_chat_id", chat_id)


def test_disabled_emits_nothing(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        _finding(s, "ioa.exfil_sequence", "critical")
        rec = _Recorder()
        summary = alert_emitter.emit_new_alerts(s, http_post=rec)
    assert summary["enabled"] is False
    assert rec.calls == []


def test_first_run_fast_forwards_past_backlog(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        _finding(s, "a", "critical")
        _finding(s, "b", "critical")
        _enable(s)
        rec = _Recorder()
        summary = alert_emitter.emit_new_alerts(s, http_post=rec)
    # the historical backlog is NOT replayed; watermark jumps to current max
    assert rec.calls == []
    assert "initialized_watermark" in summary
    assert summary["emitted"] == 0


def test_emits_only_new_and_above_severity(client: TestClient) -> None:
    eng = client.app.state.engine  # type: ignore[attr-defined]
    with Session(eng) as s:
        _finding(s, "old", "critical")          # backlog
        _enable(s, min_severity="block")
        alert_emitter.emit_new_alerts(s, http_post=_Recorder())  # fast-forward
        crit = _finding(s, "ioa.exfil_sequence", "critical")     # new, above
        _finding(s, "noise", "warn")                             # new, below min
        rec = _Recorder()
        summary = alert_emitter.emit_new_alerts(s, http_post=rec)
    assert summary["emitted"] == 1
    assert len(rec.calls) == 1
    body = rec.calls[0][1]
    assert body["finding"]["id"] == crit
    assert body["finding"]["severity"] == "critical"


def test_watermark_is_exactly_once(client: TestClient) -> None:
    eng = client.app.state.engine  # type: ignore[attr-defined]
    with Session(eng) as s:
        _enable(s)
        alert_emitter.emit_new_alerts(s, http_post=_Recorder())  # ff to 0/empty
        _finding(s, "ioa.chain.recon_to_exfil", "critical")
        first = alert_emitter.emit_new_alerts(s, http_post=_Recorder())
        second = alert_emitter.emit_new_alerts(s, http_post=_Recorder())
    assert first["emitted"] == 1
    assert second["emitted"] == 0   # already alerted, not re-sent


def test_slack_and_telegram_payload_shapes(client: TestClient) -> None:
    eng = client.app.state.engine  # type: ignore[attr-defined]
    with Session(eng) as s:
        fid = _finding(s, "ioa.fleet_campaign", "critical")
        f = s.get(FindingRecord, fid)
        slack = alert_emitter.format_payload(f, alert_emitter.AlertConfig(True, "u", "block", "slack", ""))
        tg = alert_emitter.format_payload(f, alert_emitter.AlertConfig(True, "u", "block", "telegram", "42"))
    assert "text" in slack and "ioa.fleet_campaign" in slack["text"]
    assert tg["chat_id"] == "42" and "ioa.fleet_campaign" in tg["text"]


def test_failed_webhook_still_advances_watermark(client: TestClient) -> None:
    eng = client.app.state.engine  # type: ignore[attr-defined]
    with Session(eng) as s:
        _enable(s)
        alert_emitter.emit_new_alerts(s, http_post=_Recorder())  # ff
        _finding(s, "ioa.exfil_sequence", "critical")
        rec = _Recorder(ok=False)  # sink down
        first = alert_emitter.emit_new_alerts(s, http_post=rec)
        second = alert_emitter.emit_new_alerts(s, http_post=_Recorder())
    assert first["failed"] == 1
    assert second["emitted"] == 0   # not retried forever — at-most-once


# --- admin UI --------------------------------------------------------------


@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/alert.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    from ccguard.server.main import create_app
    with TestClient(create_app()) as c:
        with Session(c.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        yield c, sid


def test_settings_page_shows_alert_section(admin_client) -> None:
    client, sid = admin_client
    body = client.get("/settings", cookies={"ccg_session": sid}).text
    assert "/admin/alert-settings" in body
    assert "Алерты" in body


def test_alert_settings_save_persists_and_resets_watermark(admin_client) -> None:
    client, sid = admin_client
    r = client.post("/admin/alert-settings", cookies={"ccg_session": sid},
                    data={"csrf_token": _csrf(client, sid), "enabled": "on",
                          "webhook_url": "https://siem.internal/x", "min_severity": "critical",
                          "alert_format": "slack"}, follow_redirects=False)
    assert r.status_code == 303
    with Session(client.app.state.engine) as s:
        assert get_setting(s, "alert.enabled") == "true"
        assert get_setting(s, "alert.webhook_url") == "https://siem.internal/x"
        assert get_setting(s, "alert.min_severity") == "critical"
        assert get_setting(s, "alert.last_finding_id") == "0"  # reset on enable


def test_alert_settings_rejects_bad_url(admin_client) -> None:
    client, sid = admin_client
    r = client.post("/admin/alert-settings", cookies={"ccg_session": sid},
                    data={"csrf_token": _csrf(client, sid), "enabled": "on",
                          "webhook_url": "ftp://nope", "min_severity": "block",
                          "alert_format": "generic"}, follow_redirects=False)
    assert r.status_code == 200
    assert "http" in r.text.lower()


def _csrf(client: TestClient, sid: str) -> str:
    """Scrape a CSRF token from the settings page."""
    import re
    html = client.get("/settings", cookies={"ccg_session": sid}).text
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "no csrf token on /settings"
    return m.group(1)
