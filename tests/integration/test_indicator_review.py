"""Admin review for pending Path-2 indicators: service + /indicators UI round-trip.

Headline: an auto-collected IOC lands pending and is invisible to agents until an
admin approves it here, at which point the host-rule serve path picks it up.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.main import create_app
from ccguard.server.services import indicator_review_service as svc
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.indicator_override_service import load_suspicious_host_rules


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/rev.db")
    init_db(eng)
    return eng


def _pending_host(value="185.220.101.5", source="abuse.ch-feodo") -> ThreatIndicator:
    return ThreatIndicator(
        indicator_type="suspicious_host",
        value=value,
        value_kind="exact",
        source=source,
        source_ref="feodotracker/ipblocklist",
        technique="T1071.001",
        tactic="command-and-control",
        weight=4.0,
        platform_relevant=True,
        status="pending",
        enabled=True,
        description="abuse.ch Feodo Tracker — Dridex botnet C2 IP",
    )


# --- service ----------------------------------------------------------------


def test_approve_flips_pending_to_active(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_pending_host())
        s.commit()
        row = s.exec(select(ThreatIndicator)).first()
        out = svc.approve(s, row.id, reviewed_by="admin")
    assert out.status == "active"
    assert out.enabled is True
    assert out.reviewed_by == "admin"
    assert out.reviewed_at is not None


def test_reject_flips_pending_to_rejected_and_disabled(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_pending_host())
        s.commit()
        row = s.exec(select(ThreatIndicator)).first()
        out = svc.reject(s, row.id, reviewed_by="admin")
    assert out.status == "rejected"
    assert out.enabled is False
    assert out.reviewed_by == "admin"


def test_approve_nonpending_raises(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        ind = _pending_host()
        ind.status = "active"
        s.add(ind)
        s.commit()
        row = s.exec(select(ThreatIndicator)).first()
        with pytest.raises(svc.NotPending):
            svc.approve(s, row.id, reviewed_by="admin")


def test_approve_missing_raises(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s, pytest.raises(svc.NotPending):
        svc.approve(s, 999, reviewed_by="admin")


def test_list_pending_oldest_first(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_pending_host(value="1.1.1.1"))
        s.add(_pending_host(value="2.2.2.2"))
        s.commit()
        pend = svc.list_pending(s)
    assert [p.value for p in pend] == ["1.1.1.1", "2.2.2.2"]


def test_approve_makes_indicator_served(tmp_path):
    # The whole point: pending → not served; approved → served as a warn host rule.
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_pending_host())
        s.commit()
        assert load_suspicious_host_rules(s) == []
        row = s.exec(select(ThreatIndicator)).first()
        svc.approve(s, row.id, reviewed_by="admin")
        served = load_suspicious_host_rules(s)
    assert len(served) == 1
    assert served[0]["severity"] == "warn"


# --- /indicators UI round-trip ----------------------------------------------


def _login(monkeypatch, tmp_path):
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-indreview")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
        s.add(_pending_host())
        s.commit()
    return client, sid


def _csrf(client, sid):
    r = client.get("/indicators", cookies={"ccg_session": sid})
    assert r.status_code == 200
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    assert m is not None, "csrf token not on /indicators (pending panel missing?)"
    return m.group(1)


def test_indicators_page_shows_pending_with_actions(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/indicators", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "185.220.101.5" in r.text
        assert "/admin/indicators/" in r.text  # approve/reject forms present
        assert "Одобрить" in r.text
    finally:
        client.__exit__(None, None, None)


def _pending_id(client) -> int:
    # create_app() seeds the store, so pick the pending row explicitly (not .first()).
    with Session(client.app.state.engine) as s:
        return s.exec(
            select(ThreatIndicator).where(ThreatIndicator.status == "pending")
        ).first().id


def test_web_approve_promotes_and_serves(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        row_id = _pending_id(client)
        r = client.post(
            f"/admin/indicators/{row_id}/approve",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            assert s.get(ThreatIndicator, row_id).status == "active"
            # now served among the host rules (seed rows already serve too, so
            # assert OUR IP appears rather than a total count)
            served = load_suspicious_host_rules(s)
            assert any("185.220.101.5" in r["pattern"] for r in served)
    finally:
        client.__exit__(None, None, None)


def test_web_reject_marks_rejected(monkeypatch, tmp_path):
    client, sid = _login(monkeypatch, tmp_path)
    try:
        token = _csrf(client, sid)
        row_id = _pending_id(client)
        r = client.post(
            f"/admin/indicators/{row_id}/reject",
            data={"csrf_token": token},
            cookies={"ccg_session": sid},
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        with Session(client.app.state.engine) as s:
            assert s.get(ThreatIndicator, row_id).status == "rejected"
    finally:
        client.__exit__(None, None, None)


def test_web_approve_requires_auth(monkeypatch, tmp_path):
    client, _ = _login(monkeypatch, tmp_path)
    try:
        with Session(client.app.state.engine) as s:
            row_id = s.exec(select(ThreatIndicator)).first().id
        r = client.post(f"/admin/indicators/{row_id}/approve", follow_redirects=False)
        assert r.status_code in (307, 401, 403)
    finally:
        client.__exit__(None, None, None)
