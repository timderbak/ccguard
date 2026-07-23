"""/api/v1/policy injects approved catalog overrides + ETag invalidates on change."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services import proposed_signal_service as svc
from ccguard.server.services.settings_service import set_setting


_VALID = {
    "id": "cred.read.session_cookie",
    "attack_technique": "T1539",
    "pattern": r"cookies\.binarycookies",
    "description": "browser session cookies",
}


def _approve_one(session: Session, draft: dict) -> int:
    row = svc.propose(session, draft=draft, source_kind="manual")
    svc.approve(session, row.id, reviewed_by="admin")  # type: ignore[arg-type]
    return row.id  # type: ignore[return-value]


def test_policy_endpoint_includes_signal_overrides(client: TestClient, auth_headers):
    with Session(client.app.state.engine) as s:
        _approve_one(s, _VALID)
    resp = client.get("/api/v1/policy", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    overrides = body.get("signal_overrides", [])
    assert len(overrides) == 1
    assert overrides[0]["id"] == "cred.read.session_cookie"
    assert overrides[0]["pattern"] == r"cookies\.binarycookies"


def test_policy_overrides_empty_by_default(client: TestClient, auth_headers):
    resp = client.get("/api/v1/policy", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json().get("signal_overrides", []) == []


def test_etag_changes_when_an_override_is_added(client: TestClient, auth_headers):
    r1 = client.get("/api/v1/policy", headers=auth_headers)
    etag_before = r1.headers["ETag"]

    with Session(client.app.state.engine) as s:
        _approve_one(s, _VALID)

    r2 = client.get("/api/v1/policy", headers=auth_headers)
    etag_after = r2.headers["ETag"]
    assert etag_before != etag_after


def test_corrupt_setting_override_value_is_skipped(client: TestClient, auth_headers):
    with Session(client.app.state.engine) as s:
        set_setting(s, "catalog.override.bogus.signal", "{not json")
    resp = client.get("/api/v1/policy", headers=auth_headers)
    assert resp.status_code == 200
    # Corrupt entries dropped silently, valid endpoint still returns 200.
    assert resp.json().get("signal_overrides", []) == []


# --- ThreatIndicator → served overrides (indicators become live detection) ---


def _add_dangerous_indicator(session: Session, pattern: str) -> None:
    from ccguard.server.db.models import ThreatIndicator

    session.add(
        ThreatIndicator(
            indicator_type="dangerous_command", value=pattern, value_kind="regex",
            source="manual", technique="T1059", tactic="execution",
            status="active", enabled=True, description="test danger",
        )
    )
    session.commit()


def test_active_dangerous_indicator_is_served_and_detects(client: TestClient, auth_headers):
    """An active dangerous_command indicator is served on the same wire and, fed
    to the agent extractor, actually fires — closing the 'indicators added but
    never used' gap."""
    with Session(client.app.state.engine) as s:
        _add_dangerous_indicator(s, r"wget\s+.*169\.254\.169\.254")  # cloud metadata SSRF
    body = client.get("/api/v1/policy", headers=auth_headers).json()
    overrides = body.get("signal_overrides", [])
    ind_ovs = [o for o in overrides if str(o["id"]).startswith("indicator.")]
    assert len(ind_ovs) == 1

    # End-to-end: the served override, handed to the agent extractor, detects.
    from ccguard.agent.signals.extractor import extract_signals

    sigs = extract_signals(
        "Bash", {"command": "wget http://169.254.169.254/latest/meta-data/"},
        overrides=ind_ovs,
    )
    assert ind_ovs[0]["id"] in sigs


def test_etag_changes_when_an_indicator_is_added(client: TestClient, auth_headers):
    etag_before = client.get("/api/v1/policy", headers=auth_headers).headers["ETag"]
    with Session(client.app.state.engine) as s:
        _add_dangerous_indicator(s, r"nc\s+-e\s+/bin/sh")
    etag_after = client.get("/api/v1/policy", headers=auth_headers).headers["ETag"]
    assert etag_before != etag_after
