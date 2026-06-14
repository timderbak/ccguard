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


def test_slow_chain_finding_gets_stage_explainer():
    payload = {
        "distinct_count": 3,
        "min_distinct": 3,
        "span_hours": 52.0,
        "lookback_days": 14.0,
        "stages": [
            {
                "stage": "credential-access",
                "first_seen": "2026-06-08T10:00:00+00:00",
                "last_seen": "2026-06-08T10:00:00+00:00",
                "count": 1,
                "example_signal": "cred.read.aws",
            },
            {
                "stage": "exfiltration",
                "first_seen": "2026-06-10T12:00:00+00:00",
                "last_seen": "2026-06-10T12:30:00+00:00",
                "count": 2,
                "example_signal": "egress.http_client",
            },
            {
                "stage": "defense-evasion",
                "first_seen": "2026-06-11T09:00:00+00:00",
                "last_seen": "2026-06-11T09:00:00+00:00",
                "count": 1,
                "example_signal": "defense.clear_logs",
            },
        ],
    }
    rows = build_explainable_findings([_fr("ioa.slow_chain", payload)])
    exp = rows[0]["explainer"]
    assert exp is not None
    assert exp["kind"] == "slow_chain"
    assert exp["distinct_count"] == 3
    assert exp["min_distinct"] == 3
    assert len(exp["stages"]) == 3
    assert exp["stages"][0]["stage"] == "credential-access"
    assert exp["stages"][0]["example_signal"] == "cred.read.aws"
    assert exp["stages"][1]["count"] == 2


def test_slow_chain_without_stages_degrades_to_passthrough():
    rows = build_explainable_findings([_fr("ioa.slow_chain", {"distinct_count": 3})])
    assert rows[0]["explainer"] is None  # no stages → no breakdown


def test_ai_trigger_escalation_gets_explainer():
    payload = {
        "trigger_rule": "mcp.rug_pull.description_changed",
        "trigger_at": "2026-06-14T00:00:00+00:00",
        "escalation_stage": "exfiltration",
        "escalation_signal": "egress.http_client",
        "escalation_at": "2026-06-14T10:00:00+00:00",
        "gap_hours": 10.0,
        "window_hours": 72.0,
        "narrative": "AI-origin trigger then exfil 10h later.",
    }
    rows = build_explainable_findings([_fr("ioa.ai_trigger_escalation", payload, severity="critical")])
    exp = rows[0]["explainer"]
    assert exp is not None
    assert exp["kind"] == "ai_trigger_escalation"
    assert exp["trigger_rule"] == "mcp.rug_pull.description_changed"
    assert exp["gap_hours"] == 10.0
    assert exp["escalation"]["signal_id"] == "egress.http_client"
    assert exp["escalation"]["attack_url"]  # catalog signal → resolves
    assert exp["escalation"]["stage"] == "exfiltration"


def test_ai_trigger_escalation_via_ioa_finding_has_no_attack_url():
    # escalation can be an ioa.* rule (not a catalog signal) — shown as-is
    payload = {
        "trigger_rule": "skill.drift.text",
        "trigger_at": "2026-06-14T00:00:00+00:00",
        "escalation_stage": "correlated_chain",
        "escalation_signal": "ioa.exfil_sequence",
        "escalation_at": "2026-06-14T05:00:00+00:00",
        "gap_hours": 5.0,
        "window_hours": 72.0,
        "narrative": "x",
    }
    exp = build_explainable_findings([_fr("ioa.ai_trigger_escalation", payload)])[0]["explainer"]
    assert exp["escalation"]["signal_id"] == "ioa.exfil_sequence"
    assert exp["escalation"]["attack_url"] is None


def test_ai_trigger_malformed_payload_degrades_to_passthrough():
    rows = build_explainable_findings([_fr("ioa.ai_trigger_escalation", {"narrative": "x"})])
    assert rows[0]["explainer"] is None  # no trigger_rule/escalation_signal → no breakdown


# --- humanize_rule: plain-language labels for the findings list + overview ----
def test_humanize_rule_exact_and_prefix():
    from ccguard.server.web.finding_view import humanize_rule
    # exact
    assert humanize_rule("ioa.ai_trigger_escalation") == "AI-триггер → эскалация (supply-chain атака)"
    assert humanize_rule("ioa.slow_chain") == "Медленная kill-chain (растянута на дни)"
    # prefix
    assert humanize_rule("mcp.rug_pull.tools_changed") == "Подмена MCP-сервера (rug-pull)"
    assert humanize_rule("sensor.hooks_removed") == "Security-хук удалён (агент ослеплён)"
    assert humanize_rule("prompt_injection.base64_encoded_prompt") == "Prompt injection"
    assert humanize_rule("dangerous.exfil/curl-pipe-bash") == "Опасная команда"
    # ioa.chain.* beats the generic ioa. prefix (more specific first)
    assert humanize_rule("ioa.chain.recon_to_exfil") == "Kill-chain цепочка"


def test_humanize_rule_unknown_falls_back_to_raw():
    from ccguard.server.web.finding_view import humanize_rule
    assert humanize_rule("some.brand.new.rule") == "some.brand.new.rule"
