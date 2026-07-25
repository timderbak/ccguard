"""UI connectivity / lineage-link regression guards.

Every object in ccguard is a node in a graph (event → signal → detector →
finding → technique → coverage). These tests pin the cross-object links that
make that graph navigable in the UI — so a future refactor cannot silently
turn a page back into a dead end or point a link at a 404.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import ChainMatch, FindingRecord, Machine
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password

pytestmark = pytest.mark.integration


@pytest.fixture
def admin_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[tuple[TestClient, str]]:
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/conn.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    monkeypatch.delenv("CCGUARD_SERVER_CONFIG", raising=False)
    with TestClient(create_app()) as c:
        with Session(c.app.state.engine) as s:
            sid = create_session(s, user_id="admin")
        yield c, sid


def _get(client: TestClient, sid: str, path: str):
    return client.get(path, cookies={"ccg_session": sid})


def _seed_finding(engine, *, machine: str, rule_id: str, payload: dict, severity="critical") -> int:
    with Session(engine) as s:
        f = FindingRecord(
            machine_id=machine, inventory_id=None, rule_id=rule_id, severity=severity,
            discovered_at=datetime.now(UTC), payload_json=json.dumps(payload, ensure_ascii=False),
        )
        s.add(f)
        s.commit()
        s.refresh(f)
        return f.id


def _seed_machine(engine, machine_id: str) -> None:
    with Session(engine) as s:
        if s.get(Machine, machine_id) is None:
            s.add(Machine(machine_id=machine_id))
            s.commit()


# --- static / seed-catalog pages (no extra seeding) ------------------------


def test_settings_policy_link_fixed(admin_client):
    """The dead /policy/edit link (404) is gone; the real /policy editor is linked."""
    client, sid = admin_client
    body = _get(client, sid, "/settings").text
    assert "/policy/edit" not in body
    assert 'href="/policy"' in body


def test_nav_exposes_proposed_signals(admin_client):
    """The proposed-signals review queue was an orphan (menu-less); now in nav."""
    client, sid = admin_client
    body = _get(client, sid, "/settings").text
    assert 'href="/admin/proposed-signals"' in body


def test_signals_catalog_has_anchor_and_internal_technique_link(admin_client):
    """Signal rows carry an id anchor (for detector deep-links) and link their
    technique to the internal /coverage page when the technique is in the catalog."""
    client, sid = admin_client
    body = _get(client, sid, "/signals").text
    assert 'id="cred.read.aws"' in body                 # row anchor for /signals#<id>
    assert "/coverage/T1552.001" in body                # covered technique → internal


def test_indicators_link_covered_technique_internally(admin_client):
    client, sid = admin_client
    body = _get(client, sid, "/indicators").text
    assert "/coverage/T1552" in body                    # a seeded cred indicator's technique


def test_detector_detail_links_rules_and_signals(admin_client):
    """A detector's emitted rule_ids link to their findings; watched signals link
    into the signals catalog."""
    client, sid = admin_client
    body = _get(client, sid, "/detectors/exfil_sequence").text
    assert "/findings?rule_id=" in body                 # emitted rule → its findings
    assert "/signals#" in body                           # watched signal → catalog anchor


def test_attacks_scenarios_have_stable_anchors(admin_client):
    client, sid = admin_client
    body = _get(client, sid, "/attacks").text
    assert 'id="scenario-recon_to_exfil"' in body        # deep-link target from techniques


def test_technique_detail_links_to_scenarios(admin_client):
    """AML.T0051 (IPI, initial-access) appears in kill-chain scenarios; the
    'Примеры атак' block links each scenario to its /attacks anchor."""
    client, sid = admin_client
    body = _get(client, sid, "/coverage/AML.T0051").text
    assert "/attacks#scenario-" in body


# --- finding-backed pages (seed one finding / match) -----------------------


def test_finding_detail_links_technique_internally(admin_client):
    """A finding's technique chip links INTERNALLY to /coverage (not only external
    MITRE) when the technique exists in the catalog."""
    client, sid = admin_client
    fid = _seed_finding(
        client.app.state.engine, machine="_fleet", rule_id="ioa.fleet_campaign",
        payload={"identity": "payments-mcp", "family": "mcp", "machine_count": 2,
                 "machines": ["a", "b"], "narrative": "campaign"},
    )
    body = _get(client, sid, f"/findings/{fid}").text
    # fleet detector binds supply-chain techniques (T1195 / ASI04) — both seeded.
    assert "/coverage/T1195" in body or "/coverage/ASI04" in body


def test_machine_detail_finding_links_to_finding_page(admin_client):
    """The machine page's own findings list now links each row to /findings/{id}
    (previously a dead end — the richest page was unreachable from the machine)."""
    client, sid = admin_client
    eng = client.app.state.engine
    _seed_machine(eng, "dev-9")
    fid = _seed_finding(eng, machine="dev-9", rule_id="ioa.exfil_sequence", severity="critical",
                        payload={"cred_signal": "cred.read.aws", "egress_signal": "egress.network_tool",
                                 "cred_ts": "2026-07-22T09:04:00Z", "egress_ts": "2026-07-22T09:08:00Z",
                                 "elapsed_seconds": 240.0, "window_minutes": 15.0})
    body = _get(client, sid, "/machines/dev-9").text
    assert f"/findings/{fid}" in body


def test_attacks_recent_match_links_machine_and_finding(admin_client):
    client, sid = admin_client
    eng = client.app.state.engine
    _seed_machine(eng, "dev-3")
    fid = _seed_finding(eng, machine="dev-3", rule_id="ioa.chain.recon_to_exfil", severity="critical",
                        payload={"scenario_key": "recon_to_exfil"})
    with Session(eng) as s:
        s.add(ChainMatch(scenario_key="recon_to_exfil", machine_id="dev-3", session_id=None,
                         matched_at=datetime.now(UTC), finding_id=fid, matched_steps_json="[]"))
        s.commit()
    body = _get(client, sid, "/attacks").text
    assert "/machines/dev-3" in body                     # match → its machine
    assert f"/findings/{fid}" in body                    # match → the finding it produced


def test_anomaly_detail_links_machine_and_finding(admin_client):
    client, sid = admin_client
    eng = client.app.state.engine
    _seed_machine(eng, "dev-5")
    fid = _seed_finding(eng, machine="dev-5", rule_id="anomaly.mcp_calls_per_day", severity="warn",
                        payload={"observed_value": 42, "sigma_distance": 4.1})
    body = _get(client, sid, "/anomalies/dev-5/mcp_calls_per_day").text
    assert "/machines/dev-5" in body                     # header → machine
    assert f"/findings/{fid}" in body                    # metric finding row → detail


# --- catalog consolidation: 5 loose catalogs → 2 connected axes -------------


def test_detect_vocabulary_axis_connects_signals_indicators_rules(admin_client):
    """The three 'vocabulary' catalogs each carry a tab strip linking the others,
    so they read as one grouped axis instead of three loose menu items."""
    client, sid = admin_client
    for path in ("/signals", "/indicators", "/finding-rules"):
        body = _get(client, sid, path).text
        assert 'href="/signals"' in body
        assert 'href="/indicators"' in body
        assert 'href="/finding-rules"' in body
        assert "Словарь детекта" in body


def test_coverage_axis_connects_coverage_and_correlations(admin_client):
    client, sid = admin_client
    for path in ("/coverage", "/correlations"):
        body = _get(client, sid, path).text
        assert 'href="/coverage"' in body
        assert 'href="/correlations"' in body


def test_skills_axis_connects_inventory_and_scan(admin_client):
    """The two skills screens (baseline inventory + LLM scan) now cross-link;
    /admin/skills is no longer an orphan reachable only by direct URL."""
    client, sid = admin_client
    for path in ("/admin/skills-inventory", "/admin/skills"):
        body = _get(client, sid, path).text
        assert 'href="/admin/skills-inventory"' in body
        assert 'href="/admin/skills"' in body


# --- on-prem: self-hosted assets, no runtime CDN ---------------------------


def test_ui_references_no_runtime_cdn(admin_client):
    """The console must render in an air-gapped install — no external CDN in the
    page <head>, only self-hosted /static/vendor assets."""
    client, sid = admin_client
    body = client.get("/login").text  # base.html renders on the unauthenticated login page
    for cdn in ("cdn.tailwindcss.com", "unpkg.com", "fonts.googleapis.com", "fonts.gstatic.com"):
        assert cdn not in body, f"runtime CDN still referenced: {cdn}"
    assert "/static/vendor/tailwind.css" in body
    assert "/static/vendor/htmx.min.js" in body


def test_static_vendor_assets_served(admin_client):
    client, sid = admin_client
    for asset, ctype in (
        ("/static/vendor/tailwind.css", "css"),
        ("/static/vendor/htmx.min.js", "javascript"),
        ("/static/vendor/fonts.css", "css"),
    ):
        r = client.get(asset)
        assert r.status_code == 200, asset
        assert ctype in r.headers.get("content-type", "")
