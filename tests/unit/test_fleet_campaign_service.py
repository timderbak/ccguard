"""Fleet-scope campaign correlator — one compromised component across N machines."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import FindingRecord
from ccguard.server.services import fleet_campaign_service as fc


@pytest.fixture
def session():
    eng = create_engine("sqlite://")
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


def _trigger(machine: str, *, identity: str, family: str = "mcp", ago_h: float = 1.0) -> fc.Trigger:
    return fc.Trigger(
        machine_id=machine, family=family, identity=identity,
        rule_id=f"{family}.rug_pull.tools_changed",
        ts=datetime.now(UTC) - timedelta(hours=ago_h),
    )


# --- pure kernel ---------------------------------------------------------


def test_campaign_fires_when_same_component_on_n_machines():
    triggers = [
        _trigger("m1", identity="payments-mcp"),
        _trigger("m2", identity="payments-mcp"),
        _trigger("m3", identity="payments-mcp"),
    ]
    out = fc.detect_campaigns(triggers, min_machines=2)
    assert len(out) == 1
    assert out[0].identity == "payments-mcp"
    assert out[0].machines == ("m1", "m2", "m3")


def test_no_campaign_below_min_machines():
    triggers = [_trigger("m1", identity="x"), _trigger("m1", identity="x")]  # same machine twice
    assert fc.detect_campaigns(triggers, min_machines=2) == []


def test_distinct_components_do_not_merge():
    triggers = [
        _trigger("m1", identity="mcp-A"), _trigger("m2", identity="mcp-A"),
        _trigger("m1", identity="mcp-B"),
    ]
    out = fc.detect_campaigns(triggers, min_machines=2)
    assert {c.identity for c in out} == {"mcp-A"}  # only A spans 2 machines


def test_same_name_different_family_not_merged():
    triggers = [
        _trigger("m1", identity="deploy", family="skill"),
        _trigger("m2", identity="deploy", family="agent"),
    ]
    assert fc.detect_campaigns(triggers, min_machines=2) == []  # different families


def test_identical_poison_everywhere_is_a_campaign():
    # the is_divergent blind spot: identical poison on all machines still fires here
    triggers = [_trigger(f"m{i}", identity="logger-mcp") for i in range(4)]
    out = fc.detect_campaigns(triggers, min_machines=2)
    assert out and out[0].machines == ("m0", "m1", "m2", "m3")


def test_most_spread_sorts_first():
    triggers = [
        _trigger("m1", identity="small"), _trigger("m2", identity="small"),
        _trigger("a", identity="big"), _trigger("b", identity="big"), _trigger("c", identity="big"),
    ]
    out = fc.detect_campaigns(triggers, min_machines=2)
    assert out[0].identity == "big"  # 3 machines beats 2


# --- orchestrator (DB) ---------------------------------------------------


def _finding(s, machine, rule_id, identity, ago_h=1.0):
    s.add(FindingRecord(
        machine_id=machine, inventory_id=None, rule_id=rule_id, severity="critical",
        discovered_at=datetime.now(UTC) - timedelta(hours=ago_h),
        payload_json=json.dumps({"mcp_name": identity, "matched_value": identity}),
    ))
    s.commit()


def test_evaluate_emits_fleet_finding(session):
    for m in ("dev-1", "dev-2", "dev-3"):
        _finding(session, m, "mcp.rug_pull.tools_changed", "payments-mcp")
    out = fc.evaluate(session)
    assert len(out) == 1
    p = json.loads(out[0].payload_json)
    assert out[0].rule_id == "ioa.fleet_campaign"
    assert out[0].machine_id == "_fleet"
    assert p["identity"] == "payments-mcp" and p["machine_count"] == 3


def test_evaluate_dedups_same_day(session):
    for m in ("dev-1", "dev-2"):
        _finding(session, m, "mcp.rug_pull.tools_changed", "x-mcp")
    assert len(fc.evaluate(session)) == 1
    assert fc.evaluate(session) == []  # second run same day → no dup


def test_evaluate_ignores_single_machine(session):
    _finding(session, "dev-1", "skill.drift", "solo-skill")
    assert fc.evaluate(session) == []


def test_evaluate_skips_non_trigger_findings(session):
    for m in ("dev-1", "dev-2"):
        s = session
        s.add(FindingRecord(
            machine_id=m, inventory_id=None, rule_id="risk.elevated", severity="warn",
            discovered_at=datetime.now(UTC), payload_json=json.dumps({"matched_value": "noise"}),
        ))
        s.commit()
    assert fc.evaluate(session) == []
