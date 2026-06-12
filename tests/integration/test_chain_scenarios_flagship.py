"""P2/P4: flagship kill-chain scenarios now fire end-to-end thanks to the
revived stages (defense-evasion / C2 / lateral-movement / impact) and MCP
external-content tagging. Scenarios are DATA — these prove the seeded rows
actually fire through the universal chain_engine.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import ChainScenario, ChainStep, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import chain_engine, chain_seed_service
from ccguard.server.services.chain_constants import _SIGNAL_STAGE_RULES


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/chain.db")
    init_db(eng)
    return eng


def _ev(s: Session, machine: str, *, signals: list[str], minutes_ago: float,
        session_id: str | None = "sess-1") -> None:
    s.add(ToolUseEvent(
        machine_id=machine,
        ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        received_at=datetime.now(UTC),
        tool_name="Bash",
        fingerprint="0123456789abcdef",
        decision="allow",
        result_status="success",
        signals_json=json.dumps(signals),
        session_id=session_id,
    ))
    s.commit()


def test_new_scenarios_loaded_and_no_dead_stages(tmp_path):
    producible = {stage for _, stage in _SIGNAL_STAGE_RULES}
    with Session(_engine(tmp_path)) as s:
        chain_seed_service.load_chain_seed(s)
        keys = {r.scenario_key for r in s.exec(select(ChainScenario)).all()}
        steps = s.exec(select(ChainStep)).all()
    assert {
        "injection_to_c2",
        "exfil_then_coverup",
        "evade_then_steal",
    } <= keys
    # every step tactic must resolve to a producible stage (no armed-waiting dead steps)
    for st in steps:
        assert st.tactic in producible, f"{st.scenario_key} uses dead stage {st.tactic}"


def test_injection_to_c2_fires(tmp_path):
    with Session(_engine(tmp_path)) as s:
        chain_seed_service.load_chain_seed(s)
        _ev(s, "m", signals=["content.read.external"], minutes_ago=5)  # initial-access
        _ev(s, "m", signals=["exec.pipe_to_shell"], minutes_ago=3)     # execution
        _ev(s, "m", signals=["c2.reverse_shell"], minutes_ago=1)       # command-and-control
        rule_ids = [f.rule_id for f in chain_engine.evaluate_machine(s, "m")]
    assert "ioa.chain.injection_to_c2" in rule_ids


def test_exfil_then_coverup_fires(tmp_path):
    with Session(_engine(tmp_path)) as s:
        chain_seed_service.load_chain_seed(s)
        _ev(s, "m", signals=["cred.read.aws"], minutes_ago=6)        # credential-access
        _ev(s, "m", signals=["egress.network_tool"], minutes_ago=4)  # exfiltration
        _ev(s, "m", signals=["defense.clear_logs"], minutes_ago=1)   # defense-evasion
        rule_ids = [f.rule_id for f in chain_engine.evaluate_machine(s, "m")]
    assert "ioa.chain.exfil_then_coverup" in rule_ids


def test_benign_cred_egress_without_coverup_stays_quiet(tmp_path):
    # A benign session (read .env, curl an internal health URL, write a build
    # log) produces credential-access + exfiltration but NO defense-evasion
    # signal — so the cover-up / evade chains must NOT fire.
    with Session(_engine(tmp_path)) as s:
        chain_seed_service.load_chain_seed(s)
        _ev(s, "m", signals=["cred.read.dotenv"], minutes_ago=5)
        _ev(s, "m", signals=["egress.network_tool"], minutes_ago=2)
        rule_ids = [f.rule_id for f in chain_engine.evaluate_machine(s, "m")]
    assert "ioa.chain.exfil_then_coverup" not in rule_ids
    assert "ioa.chain.evade_then_steal" not in rule_ids
