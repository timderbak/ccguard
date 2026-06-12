"""P7-depth: low-and-slow kill-chain accumulator (slow_chain_service)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import slow_chain_service as svc
from ccguard.server.services.slow_chain_service import SlowEvent, evaluate_progression

_NOW = datetime(2026, 6, 12, 12, 0, 0, tzinfo=UTC)


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _ev(session: Session, machine_id: str, ts: datetime, signals: list[str]) -> None:
    session.add(
        ToolUseEvent(
            machine_id=machine_id,
            ts=ts,
            tool_name="Bash",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps(signals),
        )
    )


# --- pure kernel ---------------------------------------------------------


def test_counts_distinct_advanced_stages_in_killchain_order():
    events = [
        SlowEvent(_NOW - timedelta(days=5), ("cred.read.aws",)),       # credential-access
        SlowEvent(_NOW - timedelta(days=3), ("defense.clear_logs",)),  # defense-evasion
        SlowEvent(_NOW - timedelta(days=1), ("egress.http_client",)),  # exfiltration
    ]
    r = evaluate_progression(events, _NOW, lookback_days=14)
    assert r.distinct_count == 3
    # kill-chain order: defense-evasion < credential-access < exfiltration
    assert [h.stage for h in r.stages] == [
        "defense-evasion",
        "credential-access",
        "exfiltration",
    ]
    assert r.span_seconds == (4 * 24 * 3600)  # day5 → day1


def test_non_advanced_stages_ignored():
    events = [
        SlowEvent(_NOW - timedelta(days=2), ("discovery.cloud_enum",)),  # discovery
        SlowEvent(_NOW - timedelta(days=1), ("exec.eval",)),            # execution
        SlowEvent(_NOW, ("fs.write.hidden",)),                          # collection
    ]
    assert evaluate_progression(events, _NOW, lookback_days=14).distinct_count == 0


def test_events_outside_lookback_dropped():
    events = [
        SlowEvent(_NOW - timedelta(days=20), ("cred.read.aws",)),   # too old
        SlowEvent(_NOW - timedelta(days=2), ("egress.http_client",)),
        SlowEvent(_NOW - timedelta(days=1), ("c2.reverse_shell",)),
    ]
    r = evaluate_progression(events, _NOW, lookback_days=14)
    assert r.distinct_count == 2
    assert "credential-access" not in {h.stage for h in r.stages}


def test_same_stage_repeats_collapse_to_one_with_count():
    events = [
        SlowEvent(_NOW - timedelta(days=4), ("cred.read.aws",)),
        SlowEvent(_NOW - timedelta(days=1), ("cred.read.saas_token",)),
    ]
    r = evaluate_progression(events, _NOW, lookback_days=14)
    assert r.distinct_count == 1
    hit = r.stages[0]
    assert hit.stage == "credential-access"
    assert hit.count == 2
    assert hit.first_seen == _NOW - timedelta(days=4)
    assert hit.last_seen == _NOW - timedelta(days=1)


def test_multiple_advanced_signals_in_one_event_count_each_stage():
    events = [
        SlowEvent(_NOW - timedelta(days=2), ("cred.read.aws", "egress.http_client")),
        SlowEvent(_NOW - timedelta(days=1), ("c2.reverse_shell",)),
    ]
    assert evaluate_progression(events, _NOW, lookback_days=14).distinct_count == 3


# --- orchestrator --------------------------------------------------------


def test_emits_slow_chain_when_spread_over_days():
    now = datetime.now(UTC)
    with Session(_engine()) as s:
        _ev(s, "m1", now - timedelta(days=5), ["cred.read.aws"])
        _ev(s, "m1", now - timedelta(days=3), ["defense.disable_security"])
        _ev(s, "m1", now - timedelta(days=1), ["egress.http_client"])
        s.commit()
        f = svc.evaluate_one(s, "m1")
    assert f is not None
    assert f.rule_id == "ioa.slow_chain"
    assert f.severity == "warn"
    payload = json.loads(f.payload_json)
    assert payload["distinct_count"] == 3
    assert {st["stage"] for st in payload["stages"]} == {
        "credential-access",
        "defense-evasion",
        "exfiltration",
    }


def test_burst_within_an_hour_does_not_fire():
    now = datetime.now(UTC)
    with Session(_engine()) as s:
        base = now - timedelta(days=1)
        _ev(s, "m1", base, ["cred.read.aws"])
        _ev(s, "m1", base + timedelta(minutes=2), ["egress.http_client"])
        _ev(s, "m1", base + timedelta(minutes=4), ["c2.reverse_shell"])
        s.commit()
        f = svc.evaluate_one(s, "m1")
    assert f is None  # span < 1h → tight-window engines own it


def test_two_distinct_advanced_stages_no_finding():
    now = datetime.now(UTC)
    with Session(_engine()) as s:
        _ev(s, "m1", now - timedelta(days=4), ["cred.read.aws"])
        _ev(s, "m1", now - timedelta(days=1), ["egress.http_client"])
        s.commit()
        f = svc.evaluate_one(s, "m1")
    assert f is None


def test_same_day_dedup():
    now = datetime.now(UTC)
    with Session(_engine()) as s:
        _ev(s, "m1", now - timedelta(days=5), ["cred.read.aws"])
        _ev(s, "m1", now - timedelta(days=3), ["c2.reverse_shell"])
        _ev(s, "m1", now - timedelta(days=1), ["egress.http_client"])
        s.commit()
        first = svc.evaluate_one(s, "m1")
        second = svc.evaluate_one(s, "m1")
    assert first is not None
    assert second is None


def test_cold_machine_no_events_no_finding():
    with Session(_engine()) as s:
        assert svc.evaluate_one(s, "ghost") is None


def test_tick_summary():
    now = datetime.now(UTC)
    with Session(_engine()) as s:
        s.add(Machine(machine_id="m1"))
        s.add(Machine(machine_id="m2"))
        # m1 trips; m2 only does benign discovery
        _ev(s, "m1", now - timedelta(days=5), ["cred.read.aws"])
        _ev(s, "m1", now - timedelta(days=3), ["lateral.remote_exec"])
        _ev(s, "m1", now - timedelta(days=1), ["egress.http_client"])
        _ev(s, "m2", now - timedelta(days=2), ["discovery.cloud_enum"])
        s.commit()
        summary = svc.tick(s)
        findings = list(s.exec(select(FindingRecord)))
    assert summary["machines_evaluated"] == 2
    assert summary["findings_emitted"] == 1
    assert summary["errors"] == []
    assert [f.machine_id for f in findings] == ["m1"]
