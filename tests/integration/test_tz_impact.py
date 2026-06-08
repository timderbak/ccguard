"""ТЗ-IMPACT: destructive-action signal + revival of poison_to_destructive.

AC1 destructive→signal/finding; AC2 allowlist (FP); AC3 (HEADLINE) the dead
poison_to_destructive scenario now fires; AC4 standalone; AC5 T1485 bound;
AC6 PREV(enforce)/DETECT(observe); AC8 engines intact + paradox alive.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.agent.enforce import decide
from ccguard.agent.signals.extractor import extract_signals
from ccguard.schemas import EnforceHookInput, Policy, PolicyMeta
from ccguard.server.db.models import ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import (
    atlas_seed_service,
    chain_engine,
    chain_seed_service,
    coverage_service,
    indicator_seed_service,
    taxonomy_seed_service,
)
from ccguard.server.services.chain_constants import stage_for_signal, stages_for_signals


def _policy(mode: str = "enforce") -> Policy:
    return Policy(
        meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)),
        enforcement_mode=mode,  # type: ignore[arg-type]
    )


def _bash(cmd: str) -> EnforceHookInput:
    return EnforceHookInput(
        hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": cmd}
    )


# --- AC6 / AC1: enforce blocks destructive (PREV); observe allows + records --
def test_enforce_blocks_destructive_delete() -> None:
    d = decide(_bash("rm -rf ~/.ssh"), _policy("enforce"))
    assert d.permission == "deny"
    assert d.rule_id == "dangerous.destructive/delete"


def test_observe_allows_but_records_destructive() -> None:
    d = decide(_bash("rm -rf ~/.ssh"), _policy("observe"))
    assert d.permission == "allow"  # observe never blocks
    assert d.rule_id == "dangerous.destructive/delete"  # ...but stays visible (DETECT)


def test_enforce_blocks_overwrite_secret() -> None:
    d = decide(_bash("echo x > ~/.aws/credentials"), _policy("enforce"))
    assert d.permission == "deny"
    assert d.rule_id == "dangerous.destructive/overwrite"


def test_db_destruction_warns_not_blocks() -> None:
    # SQL target-awareness is imperfect → finding (warn), never a hard block.
    d = decide(_bash("psql -c 'DROP TABLE users'"), _policy("enforce"))
    assert d.permission == "allow"
    assert "dangerous.destructive/db" in d.warning_signals


# --- AC2: allowlist — normal dev work is not blocked/recorded ----------------
def test_safe_delete_not_flagged() -> None:
    d = decide(_bash("rm -rf node_modules"), _policy("enforce"))
    assert d.permission == "allow"
    assert "destructive" not in (d.rule_id or "")
    assert not any("destructive" in w for w in d.warning_signals)


def test_safe_db_drop_not_flagged() -> None:
    d = decide(_bash("DROP TABLE test_db"), _policy("enforce"))
    assert d.permission == "allow"
    assert not any("destructive" in w for w in d.warning_signals)


# --- AC1: the agent emits the impact signal (DETECT / chain feed) ------------
def test_extractor_emits_impact_signal() -> None:
    assert "impact.delete" in extract_signals("Bash", {"command": "rm -rf ~/.ssh"})
    assert "impact.db" in extract_signals("Bash", {"command": "DROP TABLE customers"})
    assert "impact.overwrite" in extract_signals("Bash", {"command": "dd if=/dev/zero of=/dev/sda"})


def test_extractor_safe_target_no_impact_signal() -> None:
    sigs = extract_signals("Bash", {"command": "rm -rf node_modules"})
    assert not any(s.startswith("impact.") for s in sigs)


# --- chain_constants: impact signal resolves to the impact stage ------------
def test_impact_signal_maps_to_impact_stage() -> None:
    assert stage_for_signal("impact.delete") == "impact"
    assert stage_for_signal("impact.db") == "impact"
    assert stages_for_signals(["impact.overwrite", "exec.pipe_to_shell"]) == {"impact", "execution"}


# --- server-side fixtures ---------------------------------------------------
def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/impact.db")
    init_db(eng)
    return eng


def _ev(s: Session, machine: str, *, signal: str, minutes_ago: float, session_id="sess") -> None:
    s.add(ToolUseEvent(
        machine_id=machine,
        ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        received_at=datetime.now(UTC),
        tool_name="Bash",
        fingerprint="0" * 16,
        decision="allow",
        result_status="success",
        signals_json=json.dumps([signal]),
        session_id=session_id,
    ))
    s.commit()


def _load_all(s: Session) -> None:
    indicator_seed_service.load_seed(s)
    atlas_seed_service.load_atlas_seed(s)
    atlas_seed_service.migrate_indicator_techniques(s)
    taxonomy_seed_service.load_crosswalk_seed(s)
    taxonomy_seed_service.load_detector_seed(s)
    chain_seed_service.load_chain_seed(s)


# --- AC3 (HEADLINE): poison_to_destructive REVIVES --------------------------
def test_poison_to_destructive_revives(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        # initial-access → execution → impact, in order, one session, in window
        _ev(s, "m1", signal="content.read.external", minutes_ago=4)
        _ev(s, "m1", signal="exec.pipe_to_shell", minutes_ago=3)
        _ev(s, "m1", signal="impact.delete", minutes_ago=1)  # the once-dead step
        rule_ids = [f.rule_id for f in chain_engine.evaluate_machine(s, "m1")]
    assert "ioa.chain.poison_to_destructive" in rule_ids  # was dead before ТЗ-IMPACT


def test_poison_to_destructive_dead_without_impact(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        _ev(s, "m2", signal="content.read.external", minutes_ago=4)
        _ev(s, "m2", signal="exec.pipe_to_shell", minutes_ago=2)
        # no impact event → chain incomplete
        rule_ids = [f.rule_id for f in chain_engine.evaluate_machine(s, "m2")]
    assert "ioa.chain.poison_to_destructive" not in rule_ids


# --- AC5: T1485 now covered (indicator → impact) ----------------------------
def test_t1485_covered(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
        detail = coverage_service.coverage_detail(s, "T1485")
    assert "T1485" in covered  # destructive indicators bind it
    assert detail["indicators"]  # covered by ≥1 indicator
    assert "PREV" in detail["control_types"]  # dangerous_command → PREV


# --- AC8: paradox still alive + chain finding carries impact taxonomy --------
def test_paradox_alive_and_chain_taxonomy(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
        _ev(s, "m3", signal="content.read.external", minutes_ago=4)
        _ev(s, "m3", signal="exec.pipe_to_shell", minutes_ago=3)
        _ev(s, "m3", signal="impact.overwrite", minutes_ago=1)
        findings = chain_engine.evaluate_machine(s, "m3")
        payloads = [json.loads(f.payload_json) for f in findings
                    if f.rule_id == "ioa.chain.poison_to_destructive"]
    assert "AML.T0051" in covered  # ТЗ-08 paradox intact
    assert payloads
    assert "impact" in {st["tactic"] for st in payloads[0]["matched_steps"]}
    assert payloads[0]["stage_techniques"].get("impact")  # T1485/T1561 enrichment
