"""ТЗ-09: universal stage-chain engine — scenarios as data, stage-level matching.

Headline ACs: 2 (a step matches ANY technique of a stage) and 3 (catches a
channel never seen before, because the step is a STAGE not a channel). Plus the
ТЗ-08 tails (tactic_source, indicator control_type) and the "engines intact +
paradox alive" guard (AC12).
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ccguard.server.db.models import (
    ChainScenario,
    ChainStep,
    FindingRecord,
    Machine,
    ToolUseEvent,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import (
    atlas_seed_service,
    chain_engine,
    chain_seed_service,
    coverage_service,
    indicator_seed_service,
    taxonomy_seed_service,
)
from ccguard.server.services.chain_engine import _Event, _Step, match_scenario


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


def _scenario(s: Session, key: str, steps: list[tuple[int, str, bool]], *,
              window_seconds: int = 300, require_order: bool = True,
              severity: str = "critical") -> ChainScenario:
    sc = ChainScenario(scenario_key=key, name=key, window_seconds=window_seconds,
                       require_order=require_order, severity=severity)
    s.add(sc)
    for idx, tactic, optional in steps:
        s.add(ChainStep(scenario_key=key, step_index=idx, tactic=tactic, optional=optional))
    s.commit()
    s.refresh(sc)
    return sc


def _load_taxonomy(s: Session) -> None:
    indicator_seed_service.load_seed(s)
    atlas_seed_service.load_atlas_seed(s)
    atlas_seed_service.migrate_indicator_techniques(s)
    taxonomy_seed_service.load_crosswalk_seed(s)
    taxonomy_seed_service.load_detector_seed(s)


# --- pure kernel tests (no DB) ----------------------------------------------
def _mk(steps):
    return [_Step(i, t, o) for i, t, o in steps]


def test_kernel_ordered_matches_in_window():
    steps = _mk([(0, "initial-access", False), (1, "exfiltration", False)])
    base = datetime.now(UTC)
    events = [
        _Event(base, ("content.read.external",), "s"),
        _Event(base + timedelta(seconds=60), ("egress.bot_api",), "s"),
    ]
    assert match_scenario(steps, events, 300, True) is not None


def test_kernel_ordered_rejects_out_of_order():
    steps = _mk([(0, "credential-access", False), (1, "exfiltration", False)])
    base = datetime.now(UTC)
    events = [
        _Event(base, ("egress.bot_api",), "s"),               # exfil first
        _Event(base + timedelta(seconds=60), ("cred.read.aws",), "s"),
    ]
    assert match_scenario(steps, events, 300, True) is None


def test_kernel_unordered_accepts_any_order():
    steps = _mk([(0, "credential-access", False), (1, "exfiltration", False)])
    base = datetime.now(UTC)
    events = [
        _Event(base, ("egress.bot_api",), "s"),
        _Event(base + timedelta(seconds=60), ("cred.read.aws",), "s"),
    ]
    assert match_scenario(steps, events, 300, False) is not None


def test_kernel_window_excludes_late_steps():
    steps = _mk([(0, "initial-access", False), (1, "exfiltration", False)])
    base = datetime.now(UTC)
    events = [
        _Event(base, ("content.read.external",), "s"),
        _Event(base + timedelta(seconds=600), ("egress.bot_api",), "s"),  # > 300s
    ]
    assert match_scenario(steps, events, 300, True) is None


def test_kernel_optional_step_skippable():
    # initial → cred → [collection optional] → exfil, with NO collection event
    steps = _mk([(0, "initial-access", False), (1, "credential-access", False),
                 (2, "collection", True), (3, "exfiltration", False)])
    base = datetime.now(UTC)
    events = [
        _Event(base, ("content.read.external",), "s"),
        _Event(base + timedelta(seconds=30), ("cred.read.aws",), "s"),
        _Event(base + timedelta(seconds=60), ("egress.paste_site",), "s"),
    ]
    assert match_scenario(steps, events, 300, True) is not None


# --- AC1: scenarios as data, idempotent -------------------------------------
def test_scenarios_load_idempotently(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        first = chain_seed_service.load_chain_seed(s)
        again = chain_seed_service.load_chain_seed(s)
        scen = s.exec(select(ChainScenario)).all()
        steps = s.exec(select(ChainStep)).all()
    assert first > 0
    assert again == 0  # idempotent double-start
    keys = {sc.scenario_key for sc in scen}
    assert {"recon_to_exfil", "recon_stage_persist", "poison_to_destructive"} <= keys
    assert steps  # steps loaded


# --- AC2 (HEADLINE): a step matches ANY technique of a stage ----------------
@pytest.mark.parametrize("exfil_signal", [
    "egress.network_tool",     # ~ T1567 web service
    "egress.bot_api",          # ~ T1102 / Telegram-style bot
    "egress.dns_long_subdomain",  # ~ DNS exfil
    "cloud.exfil.storage",     # ~ cloud bucket
])
def test_exfil_step_matches_any_channel(tmp_path, exfil_signal):
    eng = _engine(tmp_path)
    machine = f"m-{exfil_signal}"
    with Session(eng) as s:
        _scenario(s, "x", [(0, "credential-access", False), (1, "exfiltration", False)])
        _ev(s, machine, signals=["cred.read.aws"], minutes_ago=3)
        _ev(s, machine, signals=[exfil_signal], minutes_ago=1)
        findings = chain_engine.evaluate_machine(s, machine)
        rule_ids = [f.rule_id for f in findings]
    # ONE scenario fires on FOUR different exfiltration channels (techniques).
    assert rule_ids == ["ioa.chain.x"]


# --- AC3 (THE GOLD): catches a channel never seen before --------------------
def test_catches_unseen_channel_same_stage(tmp_path):
    """recon_to_exfil 'trained' on one egress channel fires on a DIFFERENT one,
    because the step is the exfiltration STAGE, not a channel. A new channel is a
    new indicator under the stage — the scenario is never touched."""
    eng = _engine(tmp_path)
    with Session(eng) as s:
        chain_seed_service.load_chain_seed(s)  # real recon_to_exfil
        # "Telegram seen" — channel A on machine A
        _ev(s, "mA", signals=["content.read.external"], minutes_ago=4)
        _ev(s, "mA", signals=["cred.read.aws"], minutes_ago=3)
        _ev(s, "mA", signals=["egress.bot_api"], minutes_ago=1)
        # "WhatsApp never seen" — a DIFFERENT egress channel on machine B
        _ev(s, "mB", signals=["content.read.external"], minutes_ago=4)
        _ev(s, "mB", signals=["cred.read.gcp"], minutes_ago=3)
        _ev(s, "mB", signals=["egress.paste_site"], minutes_ago=1)  # different channel
        ra = [f.rule_id for f in chain_engine.evaluate_machine(s, "mA")]
        rb = [f.rule_id for f in chain_engine.evaluate_machine(s, "mB")]
    assert ra == ["ioa.chain.recon_to_exfil"]
    assert rb == ["ioa.chain.recon_to_exfil"]  # unseen channel caught, scenario untouched


# --- AC4: window -------------------------------------------------------------
def test_window_blocks_spread_out_chain(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _scenario(s, "w", [(0, "initial-access", False), (1, "exfiltration", False)],
                  window_seconds=120)
        _ev(s, "m1", signals=["content.read.external"], minutes_ago=30)
        _ev(s, "m1", signals=["egress.bot_api"], minutes_ago=1)  # 29 min gap > 2 min
        findings = chain_engine.evaluate_machine(s, "m1")
    assert findings == []


# --- AC5: session ------------------------------------------------------------
def test_different_sessions_do_not_combine(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _scenario(s, "ss", [(0, "initial-access", False), (1, "exfiltration", False)])
        _ev(s, "m1", signals=["content.read.external"], minutes_ago=3, session_id="A")
        _ev(s, "m1", signals=["egress.bot_api"], minutes_ago=1, session_id="B")
        findings = chain_engine.evaluate_machine(s, "m1")
    assert findings == []


# --- AC6: optional step ------------------------------------------------------
def test_optional_step_fires_with_and_without(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        chain_seed_service.load_chain_seed(s)  # recon_to_exfil has optional collection
        # without staging (collection skipped)
        _ev(s, "no-stage", signals=["content.read.external"], minutes_ago=4)
        _ev(s, "no-stage", signals=["cred.read.aws"], minutes_ago=3)
        _ev(s, "no-stage", signals=["egress.bot_api"], minutes_ago=1)
        # with staging present
        _ev(s, "with-stage", signals=["content.read.external"], minutes_ago=4)
        _ev(s, "with-stage", signals=["cred.read.aws"], minutes_ago=3)
        _ev(s, "with-stage", signals=["fs.write.hidden"], minutes_ago=2)
        _ev(s, "with-stage", signals=["egress.bot_api"], minutes_ago=1)
        r_no = [f.rule_id for f in chain_engine.evaluate_machine(s, "no-stage")]
        r_with = [f.rule_id for f in chain_engine.evaluate_machine(s, "with-stage")]
    assert r_no == ["ioa.chain.recon_to_exfil"]   # staging skipped (optional)
    assert r_with == ["ioa.chain.recon_to_exfil"]  # staging present


# --- AC7: require_order both modes ------------------------------------------
def test_require_order_true_vs_false(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _scenario(s, "ord", [(0, "credential-access", False), (1, "exfiltration", False)],
                  require_order=True)
        _scenario(s, "any", [(0, "credential-access", False), (1, "exfiltration", False)],
                  require_order=False)
        # exfil BEFORE cred (wrong order for "ord")
        _ev(s, "m1", signals=["egress.bot_api"], minutes_ago=2)
        _ev(s, "m1", signals=["cred.read.aws"], minutes_ago=1)
        ordered = chain_engine.evaluate_scenario(
            s, "m1", s.exec(select(ChainScenario).where(ChainScenario.scenario_key == "ord")).one())
        unordered = chain_engine.evaluate_scenario(
            s, "m1", s.exec(select(ChainScenario).where(ChainScenario.scenario_key == "any")).one())
    assert ordered is None       # strict order not satisfied
    assert unordered is not None  # any-order satisfied


# --- AC8: finding carries taxonomy ------------------------------------------
def test_finding_carries_taxonomy(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_taxonomy(s)          # so stage_techniques can be enriched
        chain_seed_service.load_chain_seed(s)
        _ev(s, "m1", signals=["content.read.external"], minutes_ago=4)
        _ev(s, "m1", signals=["cred.read.aws"], minutes_ago=3)
        _ev(s, "m1", signals=["egress.bot_api"], minutes_ago=1)
        findings = chain_engine.evaluate_machine(s, "m1")
        assert len(findings) == 1
        rule_id = findings[0].rule_id
        severity = findings[0].severity
        payload = json.loads(findings[0].payload_json)
    assert rule_id == "ioa.chain.recon_to_exfil"
    assert severity == "critical"
    assert payload["scenario_key"] == "recon_to_exfil"
    assert payload["control_type"] == "DETECT"
    tactics = {st["tactic"] for st in payload["matched_steps"]}
    assert {"initial-access", "credential-access", "exfiltration"} <= tactics
    # taxonomy enrichment: exfiltration stage lists real techniques across frameworks
    assert payload["stage_techniques"].get("exfiltration")


# --- AC9: dedup --------------------------------------------------------------
def test_dedup_one_finding_per_scenario(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _scenario(s, "d", [(0, "credential-access", False), (1, "exfiltration", False)])
        _ev(s, "m1", signals=["cred.read.aws"], minutes_ago=3)
        _ev(s, "m1", signals=["egress.bot_api"], minutes_ago=1)
        first = chain_engine.evaluate_machine(s, "m1")
        second = chain_engine.evaluate_machine(s, "m1")  # run again same day
        total = s.exec(select(FindingRecord).where(FindingRecord.rule_id == "ioa.chain.d")).all()
    assert len(first) == 1
    assert second == []        # deduped
    assert len(total) == 1


# --- AC10: tactic_source vetted ---------------------------------------------
def test_tactic_source_kill_chain_vs_risk_layer(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_taxonomy(s)
        d_attack = coverage_service.coverage_detail(s, "T1567")
        d_atlas = coverage_service.coverage_detail(s, "AML.T0051")
        d_owasp = coverage_service.coverage_detail(s, "ASI01")
    assert d_attack["tactic_source"] == "kill-chain"
    assert d_atlas["tactic_source"] == "kill-chain"
    assert d_owasp["tactic_source"] == "risk-layer"  # OWASP is unordered risk layer


# --- AC11: indicator control_type (PREV present) ----------------------------
def test_coverage_by_control_type_has_prev(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_taxonomy(s)
        by_ct = coverage_service.coverage_by_control_type(s)
    assert by_ct.get("PREV", 0) > 0   # dangerous-command indicators now PREV
    assert by_ct.get("SCOPE", 0) > 0  # path indicators still SCOPE
    assert by_ct.get("DETECT", 0) > 0  # correlations DETECT


# --- AC12: paradox still alive (engines intact verified separately) ---------
def test_tz08_paradox_still_alive(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_taxonomy(s)
        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
    assert "AML.T0051" in covered  # IPI still covered via correlation detector


# --- tick() smoke: iterates machines ----------------------------------------
def test_tick_emits_for_machine(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        chain_seed_service.load_chain_seed(s)
        s.add(Machine(machine_id="m1", hostname="h"))
        s.commit()
        _ev(s, "m1", signals=["content.read.external"], minutes_ago=4)
        _ev(s, "m1", signals=["cred.read.aws"], minutes_ago=3)
        _ev(s, "m1", signals=["egress.bot_api"], minutes_ago=1)
        summary = chain_engine.tick(s)
    assert summary["machines_evaluated"] == 1
    assert summary["scenarios_active"] >= 3
    assert summary["findings_emitted"] >= 1
    assert summary["errors"] == []


# --- step uniqueness guard ---------------------------------------------------
def test_chain_step_pair_unique(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(ChainStep(scenario_key="z", step_index=0, tactic="exfiltration"))
        s.commit()
        s.add(ChainStep(scenario_key="z", step_index=0, tactic="execution"))
        with pytest.raises(IntegrityError):
            s.commit()
