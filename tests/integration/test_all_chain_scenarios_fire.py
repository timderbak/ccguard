"""Досконально: КАЖДЫЙ сценарий из seed срабатывает end-to-end — ни один не «зря».

Data-driven audit: loads every ChainScenario from the DB, builds one event per
step (ordered, tight within the window), fires the engine and asserts the
scenario's own ``ioa.chain.<key>`` finding is produced. So no seeded scenario can
be dead (a tactic no signal maps to, an impossible order, a typo'd key) without
this test failing — and it auto-covers any scenario added later.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session, select

from ccguard.server.db.models import ChainScenario, ChainStep, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import chain_engine, chain_seed_service
from ccguard.server.services.chain_constants import _SIGNAL_STAGE_RULES, stage_for_signal

pytestmark = pytest.mark.integration

# One representative REAL catalog signal per kill-chain stage. Every tactic any
# seeded scenario uses must appear here — the test asserts that below, so a new
# scenario on an unmapped tactic fails loudly instead of being silently skipped.
STAGE_SIGNAL: dict[str, str] = {
    "initial-access": "content.read.external",
    "execution": "exec.pipe_to_shell",
    "persistence": "persist.cron",
    "privilege-escalation": "system.permissive_chmod",
    "defense-evasion": "defense.clear_logs",
    "credential-access": "cred.read.aws",
    "discovery": "discovery.recon",
    "collection": "collection.archive_staging",
    "command-and-control": "c2.reverse_shell",
    "exfiltration": "egress.network_tool",
    "impact": "impact.disk_wipe",
}


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/allchains.db")
    init_db(eng)
    return eng


def _ev(s: Session, machine: str, signal: str, minutes_ago: float) -> None:
    s.add(ToolUseEvent(
        machine_id=machine,
        ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        received_at=datetime.now(UTC),
        tool_name="Bash",
        fingerprint="0123456789abcdef",
        decision="allow",
        result_status="success",
        signals_json=json.dumps([signal]),
        session_id="sess-1",
    ))


def test_representative_signals_resolve_to_their_stage() -> None:
    """Each chosen signal must actually resolve to the stage it stands for —
    otherwise the audit below would build the wrong events."""
    for stage, signal in STAGE_SIGNAL.items():
        assert stage_for_signal(signal) == stage, f"{signal} does not resolve to {stage}"


def test_stage_map_covers_every_producible_stage() -> None:
    """Every stage that has a signal family (so a scenario could use it) is in the
    map — guards against a new scenario tactic slipping through unexercised."""
    producible = {stage for _, stage in _SIGNAL_STAGE_RULES}
    # lateral-movement is producible but intentionally has no scenario (ssh idiom);
    # allow the map to omit stages no scenario uses.
    missing = producible - set(STAGE_SIGNAL) - {"lateral-movement"}
    assert not missing, f"stages with signals but no test representative: {missing}"


def test_every_seeded_scenario_fires(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        chain_seed_service.load_chain_seed(s)
        scenarios = s.exec(select(ChainScenario)).all()
        steps_by_key: dict[str, list[ChainStep]] = {}
        for st in s.exec(select(ChainStep)).all():
            steps_by_key.setdefault(st.scenario_key, []).append(st)

        assert len(scenarios) >= 18, f"expected >=18 scenarios, got {len(scenarios)}"

        fired: dict[str, bool] = {}
        for sc in scenarios:
            steps = sorted(steps_by_key[sc.scenario_key], key=lambda x: x.step_index)
            # every tactic must be representable, else the audit is incomplete
            for st in steps:
                assert st.tactic in STAGE_SIGNAL, (
                    f"{sc.scenario_key} uses tactic '{st.tactic}' with no test signal"
                )
            # fire this scenario on its OWN machine so scenarios don't cross-fire
            machine = f"m-{sc.scenario_key}"
            n = len(steps)
            for k, st in enumerate(steps):
                # step 0 oldest → last step newest; tight so all fit the window
                _ev(s, machine, STAGE_SIGNAL[st.tactic], minutes_ago=(n - 1 - k) * 0.5 + 0.1)
            s.commit()
            rule_ids = {f.rule_id for f in chain_engine.evaluate_machine(s, machine)}
            fired[sc.scenario_key] = f"ioa.chain.{sc.scenario_key}" in rule_ids

    dead = [k for k, ok in fired.items() if not ok]
    assert not dead, f"scenarios that did NOT fire (dead/wasted): {dead}"


def test_no_two_scenarios_share_an_identical_tactic_sequence(tmp_path) -> None:
    """No wasted scenario: two scenarios with the SAME ordered tactic sequence
    would both fire on the same events — redundant. Each must be distinct."""
    eng = _engine(tmp_path)
    with Session(eng) as s:
        chain_seed_service.load_chain_seed(s)
        steps_by_key: dict[str, list[ChainStep]] = {}
        for st in s.exec(select(ChainStep)).all():
            steps_by_key.setdefault(st.scenario_key, []).append(st)

    seqs: dict[tuple[str, ...], str] = {}
    for key, steps in steps_by_key.items():
        seq = tuple(st.tactic for st in sorted(steps, key=lambda x: x.step_index))
        assert seq not in seqs, (
            f"redundant scenarios '{key}' and '{seqs[seq]}' share sequence {seq}"
        )
        seqs[seq] = key
