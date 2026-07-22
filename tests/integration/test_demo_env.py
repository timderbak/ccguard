"""Guard for the one-command demo bench (scripts/demo-env.py).

Runs the real seeder against a throwaway DB and asserts it populates one finding
of every tier plus machines, a published policy, and a pending proposed-signals
queue — so the "see the product working" bench (and the colleague demo) can't
silently rot as the schema/engines evolve.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    Machine,
    ProposedSignal,
)
from ccguard.server.db.session import make_engine
from ccguard.server.services import policy_service

pytestmark = pytest.mark.integration

_SEEDER = Path(__file__).resolve().parents[2] / "scripts" / "demo-env.py"

# One representative rule_id per detection tier the bench must light up.
_EXPECTED_TIERS = {
    "ioa.exfil_sequence",              # minutes correlation (real engine tick)
    "ioa.slow_chain",                  # days correlation (real engine tick)
    "mcp.rug_pull.description_changed",  # TOFU baseline
    "hook.rug_pull.content",           # TOFU baseline
    "skill.drift.text",                # drift
    "anomaly.mcp_calls_per_day",       # statistics
    "risk.elevated",                   # statistics
    "sensor.silent",                   # liveness (detect-by-absence)
    "prompt_injection.read_file.exfil_chain",  # content scan
    "ioa.ai_trigger_escalation",       # MOAT
    "ioa.fleet_campaign",              # MOAT (org-scoped)
}


def test_demo_env_seeds_every_tier(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path}/demo.db"
    proc = subprocess.run(
        [sys.executable, str(_SEEDER)],
        env={**os.environ, "CCGUARD_DB_URL": db_url, "CCGUARD_DISABLE_SCHEDULER": "1"},
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"seeder failed:\n{proc.stdout}\n{proc.stderr}"

    engine = make_engine(db_url)
    with Session(engine) as s:
        rule_ids = {f.rule_id for f in s.exec(select(FindingRecord))}
        machines = {m.machine_id for m in s.exec(select(Machine))}
        pending = [p for p in s.exec(select(ProposedSignal)) if p.status == "pending"]
        published = policy_service.get_current_published(s)

    missing = _EXPECTED_TIERS - rule_ids
    assert not missing, f"demo bench missing tiers: {sorted(missing)}"
    # machines registered (else correlation engines skip them silently)
    assert {"alice-laptop", "bob-laptop", "ci-runner", "carol-laptop"} <= machines
    # policy published (so /policy renders instead of 503) + review queue seeded
    assert published is not None
    assert len(pending) >= 2
