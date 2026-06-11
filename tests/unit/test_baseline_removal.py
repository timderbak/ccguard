"""P7: removal of a CONFIRMED (active/accepted_drift) hook/skill/agent baseline
emits a finding (tamper / supply-chain removal). Pending removals stay silent,
and an already-missing row does not re-emit.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, create_engine, select

from ccguard.server.db.models import AgentBaseline, HookBaseline, SkillBaseline
from ccguard.server.db.session import init_db
from ccguard.server.services import (
    agent_baseline_service,
    hook_baseline_service,
    skill_baseline_service,
)


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as s:
        yield s


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _rules(findings):
    return {f.rule_id for f in findings}


def _hook(status="active"):
    return HookBaseline(
        machine_id="m",
        event_name="PreToolUse",
        matcher="Bash",
        command_string="python /opt/ccguard-enforce.py",
        file_path="/opt/x.py",
        file_content_hash="aaaa",
        fingerprint="ffff",
        status=status,
        first_seen_at=_now(),
        last_seen_at=_now(),
    )


def _skill(status="active"):
    return SkillBaseline(
        machine_id="m",
        name="mal-skill",
        origin="plugin",
        parent_plugin="evil",
        source_marketplace="mp",
        dir_hash="d1",
        has_referenced_scripts=False,
        path="/s",
        fingerprint="sf",
        status=status,
        first_seen_at=_now(),
        last_seen_at=_now(),
    )


def _agent(status="active"):
    return AgentBaseline(
        machine_id="m",
        name="mal-agent",
        origin="plugin",
        parent_plugin="evil",
        source_marketplace="mp",
        file_hash="h1",
        tools_csv="Bash",
        model=None,
        path="/a",
        fingerprint="af",
        status=status,
        first_seen_at=_now(),
        last_seen_at=_now(),
    )


# --- hook (the EDR-tamper case) -------------------------------------------

def test_active_hook_removal_emits_finding(session):
    session.add(_hook()); session.commit()
    findings = hook_baseline_service.update_and_detect(session, "m", [])
    assert "hook.removed" in _rules(findings)
    assert session.exec(select(HookBaseline)).one().status == "missing"


def test_pending_hook_removal_is_silent(session):
    session.add(_hook(status="pending")); session.commit()
    findings = hook_baseline_service.update_and_detect(session, "m", [])
    assert "hook.removed" not in _rules(findings)
    assert session.exec(select(HookBaseline)).one().status == "missing"


def test_already_missing_hook_does_not_reemit(session):
    session.add(_hook()); session.commit()
    hook_baseline_service.update_and_detect(session, "m", [])
    session.commit()
    findings2 = hook_baseline_service.update_and_detect(session, "m", [])
    assert "hook.removed" not in _rules(findings2)


# --- skill + agent (supply-chain removal) ---------------------------------

def test_active_skill_removal_emits_finding(session):
    session.add(_skill()); session.commit()
    findings = skill_baseline_service.update_and_detect(session, "m", [])
    assert "skill.removed" in _rules(findings)


def test_active_agent_removal_emits_finding(session):
    session.add(_agent()); session.commit()
    findings = agent_baseline_service.update_and_detect(session, "m", [])
    assert "agent.removed" in _rules(findings)


def test_pending_skill_and_agent_removal_silent(session):
    session.add(_skill(status="pending"))
    session.add(_agent(status="pending"))
    session.commit()
    assert "skill.removed" not in _rules(
        skill_baseline_service.update_and_detect(session, "m", [])
    )
    assert "agent.removed" not in _rules(
        agent_baseline_service.update_and_detect(session, "m", [])
    )
