"""The moat correlator: connect an AI-origin trigger (MCP rug-pull / drift / PI)
to the subsequent endpoint escalation on the same machine — one connected story."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import supply_chain_escalation_service as svc
from ccguard.server.services.supply_chain_escalation_service import (
    Escalation,
    Trigger,
    evaluate_link,
)

_NOW = datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC)


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _ev(s, mid, ts, sigs, sess="s1"):
    s.add(ToolUseEvent(machine_id=mid, ts=ts, tool_name="Bash", fingerprint="0" * 16,
                       decision="allow", result_status="success",
                       signals_json=json.dumps(sigs), session_id=sess))


def _finding(s, mid, ts, rule_id, sev="warn"):
    s.add(FindingRecord(machine_id=mid, inventory_id=None, rule_id=rule_id,
                        severity=sev, discovered_at=ts, payload_json="{}"))


# --- pure kernel ---------------------------------------------------------


def test_trigger_then_escalation_within_window_links():
    trig = [Trigger("mcp.rug_pull.description_changed", _NOW - timedelta(hours=10))]
    esc = [Escalation("exfiltration", "egress.http_client", _NOW - timedelta(hours=2))]
    r = evaluate_link(trig, esc, window_hours=72)
    assert r is not None
    assert r.trigger.rule_id == "mcp.rug_pull.description_changed"
    assert r.escalation.stage == "exfiltration"


def test_escalation_before_trigger_does_not_link():
    # cause must precede effect
    trig = [Trigger("mcp.rug_pull.tools_changed", _NOW - timedelta(hours=2))]
    esc = [Escalation("exfiltration", "egress.http_client", _NOW - timedelta(hours=10))]
    assert evaluate_link(trig, esc, window_hours=72) is None


def test_escalation_outside_window_does_not_link():
    trig = [Trigger("skill.rug_pull.content", _NOW - timedelta(hours=100))]
    esc = [Escalation("exfiltration", "egress.http_client", _NOW - timedelta(hours=2))]
    assert evaluate_link(trig, esc, window_hours=72) is None


def test_no_trigger_no_link():
    esc = [Escalation("impact", "impact.delete", _NOW)]
    assert evaluate_link([], esc, window_hours=72) is None


# --- orchestrator --------------------------------------------------------


def test_rug_pull_then_exfil_fires_critical():
    with Session(_engine()) as s:
        _finding(s, "m1", datetime.now(UTC) - timedelta(hours=12),
                 "mcp.rug_pull.description_changed", "critical")
        _ev(s, "m1", datetime.now(UTC) - timedelta(hours=3), ["cred.read.aws"])
        _ev(s, "m1", datetime.now(UTC) - timedelta(hours=2), ["egress.http_client"])
        s.commit()
        f = svc.evaluate_one(s, "m1")
    assert f is not None
    assert f.rule_id == "ioa.ai_trigger_escalation"
    assert f.severity == "critical"
    payload = json.loads(f.payload_json)
    assert payload["trigger_rule"] == "mcp.rug_pull.description_changed"
    assert payload["escalation_stage"] == "exfiltration"


def test_trigger_but_only_cred_read_does_not_fire():
    # reading a secret alone is too common to call a supply-chain attack
    with Session(_engine()) as s:
        _finding(s, "m1", datetime.now(UTC) - timedelta(hours=12),
                 "mcp.rug_pull.tools_changed", "critical")
        _ev(s, "m1", datetime.now(UTC) - timedelta(hours=2), ["cred.read.aws"])
        s.commit()
        assert svc.evaluate_one(s, "m1") is None


def test_prompt_injection_then_reverse_shell_fires():
    with Session(_engine()) as s:
        _finding(s, "m1", datetime.now(UTC) - timedelta(hours=1),
                 "prompt_injection.read_file.ignore_previous_instructions", "warn")
        _ev(s, "m1", datetime.now(UTC) - timedelta(minutes=20), ["c2.reverse_shell"])
        s.commit()
        f = svc.evaluate_one(s, "m1")
    assert f is not None
    assert json.loads(f.payload_json)["escalation_stage"] == "command-and-control"


def test_existing_ioa_finding_counts_as_escalation():
    with Session(_engine()) as s:
        _finding(s, "m1", datetime.now(UTC) - timedelta(hours=5),
                 "mcp.rug_pull.tools_changed", "critical")
        _finding(s, "m1", datetime.now(UTC) - timedelta(hours=1),
                 "ioa.exfil_sequence", "critical")
        s.commit()
        f = svc.evaluate_one(s, "m1")
    assert f is not None
    assert json.loads(f.payload_json)["escalation_signal"] == "ioa.exfil_sequence"


def test_no_trigger_no_finding():
    with Session(_engine()) as s:
        _ev(s, "m1", datetime.now(UTC) - timedelta(hours=2), ["egress.http_client"])
        s.commit()
        assert svc.evaluate_one(s, "m1") is None


def test_same_day_dedup():
    with Session(_engine()) as s:
        _finding(s, "m1", datetime.now(UTC) - timedelta(hours=12),
                 "agent.rug_pull.dangerous", "block")
        _ev(s, "m1", datetime.now(UTC) - timedelta(hours=2), ["impact.delete"])
        s.commit()
        first = svc.evaluate_one(s, "m1")
        second = svc.evaluate_one(s, "m1")
    assert first is not None and second is None


def test_tick_summary():
    with Session(_engine()) as s:
        s.add(Machine(machine_id="m1"))
        s.add(Machine(machine_id="m2"))
        _finding(s, "m1", datetime.now(UTC) - timedelta(hours=6),
                 "mcp.rug_pull.description_changed", "critical")
        _ev(s, "m1", datetime.now(UTC) - timedelta(hours=1), ["egress.paste_site"])
        # m2: escalation but NO trigger → no link
        _ev(s, "m2", datetime.now(UTC) - timedelta(hours=1), ["egress.http_client"])
        s.commit()
        summary = svc.tick(s)
        findings = list(s.exec(select(FindingRecord).where(
            FindingRecord.rule_id == "ioa.ai_trigger_escalation")))
    assert summary["findings_emitted"] == 1
    assert [f.machine_id for f in findings] == ["m1"]
