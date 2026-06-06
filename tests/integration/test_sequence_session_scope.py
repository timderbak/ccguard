"""ТЗ-01: exfil correlation is session-scoped, with machine-scope fallback for NULL.

The headline guarantee (acceptance #3): a cred-read in session A and an egress in
session B within the window must NOT be correlated — they are unrelated work that
merely shares a machine. Acceptance #4: same-session cred→egress still matches and
the finding payload carries the session_id. Acceptance #5: legacy events with
session_id=NULL fall back to the old machine-scope behavior (one sentinel group).
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import Machine, MachineBaseline, ToolUseEvent
from ccguard.server.services import sequence_service


def _warm_machine(session: Session, machine_id: str) -> None:
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


def _add_event(
    session: Session,
    machine_id: str,
    *,
    signal: str,
    minutes_ago: float,
    session_id: str | None,
) -> None:
    session.add(
        ToolUseEvent(
            machine_id=machine_id,
            ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            tool_name="Bash",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps([signal]),
            session_id=session_id,
        )
    )
    session.commit()


def test_cross_session_cred_egress_does_not_match(client) -> None:
    """Acceptance #3: cred in session A, egress in session B → NO finding."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm_machine(s, "m-cross")
        _add_event(s, "m-cross", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add_event(s, "m-cross", signal="egress.network_tool", minutes_ago=1, session_id="B")
        finding = sequence_service.evaluate_one(s, "m-cross")
    assert finding is None


def test_same_session_cred_egress_matches_with_session_in_payload(client) -> None:
    """Acceptance #4: cred→egress both in session A → finding tagged with session A."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm_machine(s, "m-same")
        _add_event(s, "m-same", signal="cred.read.aws", minutes_ago=5, session_id="A")
        _add_event(s, "m-same", signal="egress.network_tool", minutes_ago=1, session_id="A")
        finding = sequence_service.evaluate_one(s, "m-same")
    assert finding is not None
    payload = json.loads(finding.payload_json)
    assert payload["session_id"] == "A"
    assert payload["cred_signal"] == "cred.read.aws"
    assert payload["egress_signal"] == "egress.network_tool"


def test_null_session_events_still_correlate_machine_scope(client) -> None:
    """Acceptance #5: legacy NULL-session events fall back to machine-scope match."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm_machine(s, "m-null")
        _add_event(s, "m-null", signal="cred.read.aws", minutes_ago=5, session_id=None)
        _add_event(s, "m-null", signal="egress.network_tool", minutes_ago=1, session_id=None)
        finding = sequence_service.evaluate_one(s, "m-null")
    assert finding is not None
    payload = json.loads(finding.payload_json)
    assert payload["cred_signal"] == "cred.read.aws"
    assert payload["egress_signal"] == "egress.network_tool"


def test_null_group_isolated_from_real_sessions(client) -> None:
    """A NULL-session cred must not pair with a real-session egress (and vice
    versa): the sentinel group is independent of any named session."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm_machine(s, "m-mix")
        _add_event(s, "m-mix", signal="cred.read.aws", minutes_ago=5, session_id=None)
        _add_event(s, "m-mix", signal="egress.network_tool", minutes_ago=1, session_id="A")
        finding = sequence_service.evaluate_one(s, "m-mix")
    assert finding is None
