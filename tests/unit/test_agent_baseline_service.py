"""Unit tests for agent_baseline_service: bootstrap, drift severity, accept flow."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlmodel import Session, create_engine, select

from ccguard.schemas import AgentEntry
from ccguard.server.db.models import AgentBaseline
from ccguard.server.db.session import init_db
from ccguard.server.services.agent_baseline_service import (
    accept_all_pending,
    accept_baseline,
    compute_fingerprint,
    reject_and_mark,
    update_and_detect,
)


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite://", echo=False, connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as s:
        yield s


def _agent(
    name: str = "demo",
    file_hash: str = "AAA",
    origin: str = "local",
    parent_plugin: str | None = None,
    tools: list[str] | None = None,
    model: str | None = None,
) -> AgentEntry:
    return AgentEntry(
        name=name,
        path=f"/tmp/agents/{name}.md",
        file_hash=file_hash,
        tools=tools,
        model=model,
        description=None,
        origin=origin,  # type: ignore[arg-type]
        parent_plugin=parent_plugin,
        source_marketplace="mm" if parent_plugin else None,
    )


def test_fingerprint_changes_with_file_hash():
    a = compute_fingerprint("a", "local", None, "AAA")
    b = compute_fingerprint("a", "local", None, "BBB")
    assert a != b


def test_first_sync_is_silent(session):
    findings = update_and_detect(session, "m-1", [_agent()])
    session.commit()
    rows = session.exec(select(AgentBaseline)).all()
    assert len(rows) == 1
    assert rows[0].status == "pending"
    assert findings == []


def test_new_agent_after_bootstrap_emits_warn(session):
    update_and_detect(session, "m-2", [_agent(name="a1")])
    row = session.exec(select(AgentBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    findings = update_and_detect(session, "m-2", [_agent(name="a1"), _agent(name="a2")])
    session.commit()
    assert len(findings) == 1
    assert findings[0].rule_id == "agent.new"
    assert findings[0].severity == "warn"


def test_drift_with_dangerous_tools_emits_block(session):
    update_and_detect(
        session, "m-3",
        [_agent(name="risky", file_hash="A", tools=["Bash", "Read"])],
    )
    row = session.exec(select(AgentBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    findings = update_and_detect(
        session, "m-3",
        [_agent(name="risky", file_hash="B", tools=["Bash", "Read"])],
    )
    session.commit()
    block = [f for f in findings if f.rule_id == "agent.rug_pull.dangerous"]
    assert len(block) == 1
    assert block[0].severity == "block"


def test_drift_with_safe_tools_emits_warn(session):
    update_and_detect(
        session, "m-4",
        [_agent(name="safe", file_hash="A", tools=["Read", "Grep"])],
    )
    row = session.exec(select(AgentBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    findings = update_and_detect(
        session, "m-4",
        [_agent(name="safe", file_hash="B", tools=["Read", "Grep"])],
    )
    session.commit()
    drift = [f for f in findings if f.rule_id == "agent.drift.text"]
    assert len(drift) == 1
    assert drift[0].severity == "warn"


def test_drift_with_no_tools_emits_warn(session):
    """tools=None → не считается dangerous, warn."""
    update_and_detect(session, "m-5", [_agent(name="x", file_hash="A", tools=None)])
    row = session.exec(select(AgentBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    findings = update_and_detect(session, "m-5", [_agent(name="x", file_hash="B", tools=None)])
    session.commit()
    assert findings[0].rule_id == "agent.drift.text"


def test_removed_agent_marked_missing(session):
    update_and_detect(session, "m-6", [_agent()])
    row = session.exec(select(AgentBaseline)).one()
    row.status = "active"
    session.add(row)
    session.commit()

    update_and_detect(session, "m-6", [])
    session.commit()
    fresh = session.exec(select(AgentBaseline)).one()
    assert fresh.status == "missing"


def test_tools_csv_normalized_sorted(session):
    update_and_detect(
        session, "m-7",
        [_agent(tools=["Read", "Bash", "Grep"])],
    )
    session.commit()
    row = session.exec(select(AgentBaseline)).one()
    assert row.tools_csv == "Bash,Grep,Read"


def test_accept_flow(session):
    update_and_detect(session, "m-8", [_agent(name="a"), _agent(name="b")])
    session.commit()
    row_a = session.exec(select(AgentBaseline).where(AgentBaseline.name == "a")).one()
    accept_baseline(session, "m-8", row_a.id, "admin")
    session.commit()
    assert session.exec(select(AgentBaseline).where(AgentBaseline.name == "a")).one().status == "active"

    n = accept_all_pending(session, "m-8", "admin")
    session.commit()
    assert n == 1  # only `b` was still pending

    row_b = session.exec(select(AgentBaseline).where(AgentBaseline.name == "b")).one()
    reject_and_mark(session, "m-8", row_b.id)
    session.commit()
    assert session.exec(select(AgentBaseline).where(AgentBaseline.name == "b")).one().status == "removed"
