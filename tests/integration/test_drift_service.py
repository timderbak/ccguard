"""Config-drift detector — emits persist.agent_config when sensitive inventory changes."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    InventorySnapshot,
    Machine,
    MachineBaseline,
)
from ccguard.server.services import drift_service


_DRIFT_RULE = "persist.agent_config"


def _warm(session: Session, mid: str = "m-drift") -> str:
    now = datetime.now(UTC)
    session.add(Machine(machine_id=mid, first_seen=now, last_seen=now))
    session.add(
        MachineBaseline(
            machine_id=mid, metric="bash_calls_per_day",
            mean=1.0, stdev=0.5, sample_count=14, baseline_ready=True,
        )
    )
    session.commit()
    return mid


def _snap(session: Session, mid: str, payload: dict, age_minutes: int = 0) -> None:
    """Insert one inventory snapshot at `now - age_minutes`."""
    ts = datetime.now(UTC) - timedelta(minutes=age_minutes)
    session.add(InventorySnapshot(machine_id=mid, received_at=ts, payload_json=json.dumps(payload)))
    session.commit()


def _base_inv() -> dict:
    return {
        "schema_version": 1,
        "machine_id": "m-drift",
        "timestamp": datetime.now(UTC).isoformat(),
        "agent_version": "0.2.0",
        "os": "macos",
        "settings_sources": [],
        "mcp_servers": [],
        "skills": [],
        "hooks": [],
        "plugins": [],
        "permissions": {"allow": [], "deny": [], "ask": []},
        "agents": [],
        "commands": [],
    }


def test_first_inventory_emits_no_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _snap(s, mid, _base_inv())
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 0


def test_cold_machine_no_finding_even_if_drifted(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        now = datetime.now(UTC)
        s.add(Machine(machine_id="m-cold", first_seen=now, last_seen=now))
        s.commit()
        prev = _base_inv()
        cur = _base_inv()
        cur["skills"] = [{"name": "x", "path": "/p", "origin": "local",
                          "dir_hash": "h1", "has_referenced_scripts": False}]
        _snap(s, "m-cold", prev, age_minutes=10)
        _snap(s, "m-cold", cur)
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 0


def test_skill_dir_hash_change_triggers_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        prev = _base_inv()
        prev["skills"] = [{"name": "s1", "path": "/p", "origin": "local",
                           "dir_hash": "h-old", "has_referenced_scripts": False}]
        cur = _base_inv()
        cur["skills"] = [{"name": "s1", "path": "/p", "origin": "local",
                          "dir_hash": "h-new", "has_referenced_scripts": False}]
        _snap(s, mid, prev, age_minutes=10)
        _snap(s, mid, cur)
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 1
        f = s.exec(select(FindingRecord).where(FindingRecord.rule_id == _DRIFT_RULE)).first()
        assert f is not None
        assert f.severity == "warn"
        payload = json.loads(f.payload_json)
        changes = payload["changes"]
        assert any(c["kind"] == "skill_modified" and c["name"] == "s1" for c in changes)


def test_new_skill_addition_triggers_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        _snap(s, mid, _base_inv(), age_minutes=10)
        cur = _base_inv()
        cur["skills"] = [{"name": "s-new", "path": "/p", "origin": "marketplace",
                          "dir_hash": "h", "has_referenced_scripts": False}]
        _snap(s, mid, cur)
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 1
        f = s.exec(select(FindingRecord).where(FindingRecord.rule_id == _DRIFT_RULE)).first()
        payload = json.loads(f.payload_json)
        assert any(c["kind"] == "skill_added" and c["name"] == "s-new" for c in payload["changes"])


def test_mcp_server_args_change_triggers_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        prev = _base_inv()
        prev["mcp_servers"] = [{"name": "fs", "transport": "stdio",
                                "command": "node", "args": ["x.js"], "env_keys": [], "source": "user"}]
        cur = _base_inv()
        cur["mcp_servers"] = [{"name": "fs", "transport": "stdio",
                               "command": "node", "args": ["x.js", "--evil"], "env_keys": [], "source": "user"}]
        _snap(s, mid, prev, age_minutes=10)
        _snap(s, mid, cur)
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 1


def test_agent_file_hash_change_triggers_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        prev = _base_inv()
        prev["agents"] = [{"name": "a", "path": "/p", "file_hash": "h-old"}]
        cur = _base_inv()
        cur["agents"] = [{"name": "a", "path": "/p", "file_hash": "h-new"}]
        _snap(s, mid, prev, age_minutes=10)
        _snap(s, mid, cur)
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 1


def test_unchanged_inventory_no_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        inv = _base_inv()
        inv["skills"] = [{"name": "s", "path": "/p", "origin": "local",
                          "dir_hash": "h", "has_referenced_scripts": False}]
        _snap(s, mid, inv, age_minutes=10)
        _snap(s, mid, inv)
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 0


def test_same_day_dedup(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        prev = _base_inv()
        cur = _base_inv()
        cur["skills"] = [{"name": "s", "path": "/p", "origin": "local",
                          "dir_hash": "h", "has_referenced_scripts": False}]
        _snap(s, mid, prev, age_minutes=10)
        _snap(s, mid, cur)
        drift_service.tick(s)
        drift_service.tick(s)
        rows = list(s.exec(select(FindingRecord).where(FindingRecord.rule_id == _DRIFT_RULE)))
        assert len(rows) == 1


def test_multiple_drift_kinds_aggregated_into_one_finding(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        mid = _warm(s)
        prev = _base_inv()
        prev["skills"] = [{"name": "s", "path": "/p", "origin": "local",
                           "dir_hash": "h-old", "has_referenced_scripts": False}]
        cur = _base_inv()
        cur["skills"] = [{"name": "s", "path": "/p", "origin": "local",
                          "dir_hash": "h-new", "has_referenced_scripts": False}]
        cur["agents"] = [{"name": "a", "path": "/p", "file_hash": "new"}]
        _snap(s, mid, prev, age_minutes=10)
        _snap(s, mid, cur)
        summary = drift_service.tick(s)
        assert summary["findings_emitted"] == 1  # one finding aggregates multiple changes
        f = s.exec(select(FindingRecord).where(FindingRecord.rule_id == _DRIFT_RULE)).first()
        payload = json.loads(f.payload_json)
        kinds = {c["kind"] for c in payload["changes"]}
        assert "skill_modified" in kinds
        assert "agent_added" in kinds
