"""End-to-end: attack_simulator batches drive the expected findings."""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.services import risk_service, sequence_service
from ccguard.server.services.risk_constants import RISK_RULE_ID
from ccguard.server.services.sequence_constants import SEQUENCE_RULE_ID

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from attack_simulator import SCENARIOS, _build_batch, _fingerprint  # noqa: E402


def _warm(session: Session, mid: str) -> None:
    now = datetime.now(UTC)
    session.add(Machine(machine_id=mid, first_seen=now, last_seen=now))
    session.add(
        MachineBaseline(
            machine_id=mid,
            metric="bash_calls_per_day",
            mean=1.0,
            stdev=0.5,
            sample_count=14,
            baseline_ready=True,
        )
    )
    session.commit()


def test_fingerprint_is_deterministic_16hex():
    fp = _fingerprint("anything")
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)
    assert _fingerprint("anything") == fp


def test_every_scenario_builds_a_valid_batch():
    for name, scenario in SCENARIOS.items():
        batch = _build_batch(scenario, machine_id=f"m-{name}")
        assert batch["schema_version"] == "0.2"
        assert batch["machine_id"] == f"m-{name}"
        assert len(batch["events"]) == len(scenario.events)
        for evt in batch["events"]:
            assert len(evt["fingerprint"]) == 16
            assert evt["decision"] in ("allow", "deny", "error")
            assert isinstance(evt["signals"], list)


def test_exfil_scenario_drives_sequence_finding(client, auth_headers):
    mid = "m-sim-exfil"
    with Session(client.app.state.engine) as s:
        _warm(s, mid)

    batch = _build_batch(SCENARIOS["exfil"], machine_id=mid)
    resp = client.post("/api/v1/audit", content=json.dumps(batch), headers=auth_headers)
    assert resp.status_code == 200, resp.text

    with Session(client.app.state.engine) as s:
        summary = sequence_service.tick(s)
        assert summary["findings_emitted"] >= 1
        f = s.exec(
            select(FindingRecord).where(FindingRecord.rule_id == SEQUENCE_RULE_ID)
        ).first()
    assert f is not None
    assert f.severity == "high"


def test_kill_chain_fires_both_risk_and_sequence(client, auth_headers):
    mid = "m-sim-kc"
    with Session(client.app.state.engine) as s:
        _warm(s, mid)

    batch = _build_batch(SCENARIOS["kill_chain"], machine_id=mid)
    resp = client.post("/api/v1/audit", content=json.dumps(batch), headers=auth_headers)
    assert resp.status_code == 200, resp.text

    with Session(client.app.state.engine) as s:
        risk_service.tick(s)
        sequence_service.tick(s)
        rules = {r.rule_id for r in s.exec(select(FindingRecord))}
    assert RISK_RULE_ID in rules
    assert SEQUENCE_RULE_ID in rules


def test_reverse_order_scenario_emits_no_sequence_finding(client, auth_headers):
    mid = "m-sim-rev"
    with Session(client.app.state.engine) as s:
        _warm(s, mid)

    batch = _build_batch(SCENARIOS["reverse_order"], machine_id=mid)
    resp = client.post("/api/v1/audit", content=json.dumps(batch), headers=auth_headers)
    assert resp.status_code == 200, resp.text

    with Session(client.app.state.engine) as s:
        summary = sequence_service.tick(s)
        assert summary["findings_emitted"] == 0
