"""ТЗ-02: staging-chain orchestrator — session-scope, severity matrix, tick wiring.

Covers acceptance criteria 3-8: early match without egress (warn), full chain
with egress (critical), weak normal-write (info), cross-session isolation (no
match), NULL-session fallback (match), and the severity-bug fix on the existing
cred→egress finding.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.schemas.finding import Severity
from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.services import sequence_service
from ccguard.server.services.sequence_constants import STAGING_RULE_ID

_VALID_SEVERITIES = set(Severity.__args__)  # type: ignore[attr-defined]


def _warm(session: Session, machine_id: str) -> None:
    session.add(Machine(machine_id=machine_id, hostname="h"))
    session.add(
        MachineBaseline(
            machine_id=machine_id,
            metric="bash_calls_per_day",
            mean=1.0,
            stdev=0.5,
            sample_count=14,
            baseline_ready=True,
        )
    )
    session.commit()


def _add(
    session: Session,
    machine_id: str,
    *,
    signal: str,
    minutes_ago: float,
    session_id: str | None,
) -> None:
    session.add(
        sequence_service.ToolUseEvent(  # type: ignore[attr-defined]
            machine_id=machine_id,
            ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            tool_name="Write",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps([signal]),
            session_id=session_id,
        )
    )
    session.commit()


def test_staging_without_egress_warn(client) -> None:
    """AC3: trigger → hidden write, no egress → warn, egress_present=false."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-stage-warn")
        _add(s, "m-stage-warn", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add(s, "m-stage-warn", signal="fs.write.hidden", minutes_ago=2, session_id="A")
        finding = sequence_service.evaluate_one_staging(s, "m-stage-warn")
    assert finding is not None
    assert finding.rule_id == STAGING_RULE_ID
    assert finding.severity == "warn"
    payload = json.loads(finding.payload_json)
    assert payload["egress_present"] is False
    assert payload["session_id"] == "A"


def test_full_chain_with_egress_critical(client) -> None:
    """AC4: trigger → hidden write → egress → critical, egress_present=true."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-stage-crit")
        _add(s, "m-stage-crit", signal="cred.read.aws", minutes_ago=9, session_id="A")
        _add(s, "m-stage-crit", signal="fs.write.hidden", minutes_ago=6, session_id="A")
        _add(s, "m-stage-crit", signal="egress.network_tool", minutes_ago=3, session_id="A")
        finding = sequence_service.evaluate_one_staging(s, "m-stage-crit")
    assert finding is not None
    assert finding.severity == "critical"
    payload = json.loads(finding.payload_json)
    assert payload["egress_present"] is True


def test_normal_write_info(client) -> None:
    """AC5: trigger → normal write (no hidden, no egress) → info."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-stage-info")
        _add(s, "m-stage-info", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add(s, "m-stage-info", signal="fs.write.normal", minutes_ago=2, session_id="A")
        finding = sequence_service.evaluate_one_staging(s, "m-stage-info")
    assert finding is not None
    assert finding.severity == "info"


def test_cross_session_does_not_match(client) -> None:
    """AC6: trigger in session A, hidden write in session B → NO finding."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-stage-x")
        _add(s, "m-stage-x", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add(s, "m-stage-x", signal="fs.write.hidden", minutes_ago=2, session_id="B")
        finding = sequence_service.evaluate_one_staging(s, "m-stage-x")
    assert finding is None


def test_null_session_fallback_matches(client) -> None:
    """AC7: both links session_id=NULL → correlate via sentinel group."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-stage-null")
        _add(s, "m-stage-null", signal="cred.read.aws", minutes_ago=5, session_id=None)
        _add(s, "m-stage-null", signal="fs.write.hidden", minutes_ago=2, session_id=None)
        finding = sequence_service.evaluate_one_staging(s, "m-stage-null")
    assert finding is not None
    payload = json.loads(finding.payload_json)
    assert payload["session_id"] is None


def test_severity_always_valid_for_staging(client) -> None:
    """AC8: staging never emits an out-of-schema severity (e.g. 'high')."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-stage-sev")
        _add(s, "m-stage-sev", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add(s, "m-stage-sev", signal="fs.write.hidden", minutes_ago=2, session_id="A")
        finding = sequence_service.evaluate_one_staging(s, "m-stage-sev")
    assert finding is not None
    assert finding.severity in _VALID_SEVERITIES


def test_cred_egress_finding_severity_is_valid(client) -> None:
    """AC8: the existing cred→egress finding no longer writes invalid 'high'."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-credegress")
        _add(s, "m-credegress", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add(s, "m-credegress", signal="egress.network_tool", minutes_ago=2, session_id="A")
        finding = sequence_service.evaluate_one(s, "m-credegress")
    assert finding is not None
    assert finding.severity in _VALID_SEVERITIES
    assert finding.severity != "high"


def test_external_trigger_upgrades_early_chain_to_block(client) -> None:
    """AC2 (key test): external-read → hidden write, no egress → block (was warn),
    external_trigger=true. Early, confident IPI detection before exfil."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-ext-block")
        _add(s, "m-ext-block", signal="content.read.external", minutes_ago=5, session_id="A")
        _add(s, "m-ext-block", signal="fs.write.hidden", minutes_ago=2, session_id="A")
        finding = sequence_service.evaluate_one_staging(s, "m-ext-block")
    assert finding is not None
    assert finding.severity == "block"
    payload = json.loads(finding.payload_json)
    assert payload["external_trigger"] is True
    assert payload["external_signal"] == "content.read.external"


def test_external_full_chain_critical(client) -> None:
    """AC3: external-read → hidden write → egress → critical, external_trigger=true."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-ext-crit")
        _add(s, "m-ext-crit", signal="content.read.external", minutes_ago=9, session_id="A")
        _add(s, "m-ext-crit", signal="fs.write.hidden", minutes_ago=6, session_id="A")
        _add(s, "m-ext-crit", signal="egress.network_tool", minutes_ago=3, session_id="A")
        finding = sequence_service.evaluate_one_staging(s, "m-ext-crit")
    assert finding is not None
    assert finding.severity == "critical"
    payload = json.loads(finding.payload_json)
    assert payload["external_trigger"] is True


def test_non_external_early_chain_unchanged_warn(client) -> None:
    """AC4 (regression guard): cred.read (no external) → hidden, no egress → warn,
    external_trigger=false. Chain still matches without external."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-noext-warn")
        _add(s, "m-noext-warn", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add(s, "m-noext-warn", signal="fs.write.hidden", minutes_ago=2, session_id="A")
        finding = sequence_service.evaluate_one_staging(s, "m-noext-warn")
    assert finding is not None
    assert finding.severity == "warn"
    payload = json.loads(finding.payload_json)
    assert payload["external_trigger"] is False


def test_external_chain_session_scope(client) -> None:
    """AC5: external-read session A, write session B → NO finding."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-ext-x")
        _add(s, "m-ext-x", signal="content.read.external", minutes_ago=5, session_id="A")
        _add(s, "m-ext-x", signal="fs.write.hidden", minutes_ago=2, session_id="B")
        finding = sequence_service.evaluate_one_staging(s, "m-ext-x")
    assert finding is None


def test_external_chain_null_fallback(client) -> None:
    """AC6: external-read + write both NULL session → match via sentinel group."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-ext-null")
        _add(s, "m-ext-null", signal="content.read.external", minutes_ago=5, session_id=None)
        _add(s, "m-ext-null", signal="fs.write.hidden", minutes_ago=2, session_id=None)
        finding = sequence_service.evaluate_one_staging(s, "m-ext-null")
    assert finding is not None
    assert finding.severity == "block"


def test_tick_emits_staging_finding(client) -> None:
    """Staging detector runs from the same scheduler tick as cred→egress."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-stage-tick")
        _add(s, "m-stage-tick", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add(s, "m-stage-tick", signal="fs.write.hidden", minutes_ago=2, session_id="A")
        sequence_service.tick(s)
        from sqlmodel import select

        found = s.exec(
            select(FindingRecord).where(FindingRecord.rule_id == STAGING_RULE_ID)
        ).first()
    assert found is not None
