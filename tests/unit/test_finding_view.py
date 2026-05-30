"""Explainable finding view-model for the machine detail page."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

from ccguard.server.web.finding_view import (
    attack_url_for_signal,
    build_explainable_findings,
)


def _fr(rule_id: str, payload: dict | None = None, severity: str = "warn"):
    return SimpleNamespace(
        rule_id=rule_id,
        severity=severity,
        discovered_at=datetime(2026, 5, 30, 12, 0, tzinfo=UTC),
        payload_json=json.dumps(payload) if payload is not None else "",
    )


def test_attack_url_handles_sub_technique():
    assert attack_url_for_signal("cred.read.aws") == "https://attack.mitre.org/techniques/T1552/001/"


def test_attack_url_handles_plain_technique():
    assert attack_url_for_signal("discovery.recon") == "https://attack.mitre.org/techniques/T1033/"


def test_attack_url_unknown_signal_returns_none():
    assert attack_url_for_signal("not.a.real.signal") is None


def test_unrelated_finding_passes_through_without_explainer():
    rows = build_explainable_findings([_fr("anomaly.bash_calls_per_day")])
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "anomaly.bash_calls_per_day"
    assert rows[0]["explainer"] is None


def test_risk_finding_gets_score_and_contribution_explainer():
    payload = {
        "score": 13.0,
        "threshold": 10.0,
        "window_hours": 24.0,
        "half_life_hours": 6.0,
        "contributions": {"cred.read.aws": 5.0, "egress.network_tool": 4.0, "exec.pipe_to_shell": 4.0},
        "event_count": 1,
    }
    rows = build_explainable_findings([_fr("risk.elevated", payload)])
    exp = rows[0]["explainer"]
    assert exp is not None
    assert exp["kind"] == "risk"
    assert exp["score"] == 13.0
    assert exp["threshold"] == 10.0
    # Contributions sorted by weight desc.
    sigs = [c["signal_id"] for c in exp["contributions"]]
    assert sigs[0] == "cred.read.aws"
    assert all("attack_url" in c for c in exp["contributions"])


def test_sequence_finding_gets_cred_and_egress_explainer():
    payload = {
        "cred_ts": "2026-05-30T11:55:00+00:00",
        "cred_signal": "cred.read.aws",
        "egress_ts": "2026-05-30T12:00:00+00:00",
        "egress_signal": "egress.network_tool",
        "elapsed_seconds": 300.0,
        "window_minutes": 15.0,
        "lookback_hours": 24.0,
    }
    rows = build_explainable_findings([_fr("ioa.exfil_sequence", payload, severity="high")])
    exp = rows[0]["explainer"]
    assert exp is not None
    assert exp["kind"] == "sequence"
    assert exp["cred"]["signal_id"] == "cred.read.aws"
    assert exp["cred"]["attack_url"]
    assert exp["egress"]["signal_id"] == "egress.network_tool"
    assert exp["egress"]["attack_url"]
    assert exp["elapsed_seconds"] == 300.0


def test_malformed_payload_is_safe():
    bad = SimpleNamespace(
        rule_id="risk.elevated",
        severity="warn",
        discovered_at=datetime(2026, 5, 30, 12, 0, tzinfo=UTC),
        payload_json="{not json",
    )
    rows = build_explainable_findings([bad])
    assert rows[0]["explainer"] is None  # corrupt payload degrades to plain row
