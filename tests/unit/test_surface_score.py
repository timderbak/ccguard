"""UI Фаза 1: surface_score_service — стартовый MCP-скор (read-only)."""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlmodel import Session

from ccguard.server.db.models import FindingRecord, InventorySnapshot, Machine
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.surface_score_service import compute_surface_score


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/surf.db")
    init_db(eng)
    return eng


def test_empty_db_is_perfect(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        r = compute_surface_score(s)
    assert r == {"score": 100, "mcp_count": 0, "risk_count": 0}


def test_counts_unique_mcp_and_penalizes_open_threats(tmp_path) -> None:
    eng = _engine(tmp_path)
    now = datetime.now(UTC)
    with Session(eng) as s:
        s.add(Machine(machine_id="m1", machine_label="box", first_seen=now, last_seen=now))
        s.add(InventorySnapshot(
            machine_id="m1", received_at=now,
            payload_json=json.dumps({"mcp_servers": [{"name": "fs"}, {"name": "shell"}]}),
        ))
        s.add(FindingRecord(machine_id="m1", inventory_id=None, rule_id="dangerous.x",
                            severity="block", discovered_at=now, payload_json="{}"))
        s.commit()
        r = compute_surface_score(s)
    assert r["mcp_count"] == 2
    assert r["risk_count"] == 1
    assert r["score"] == 92  # 100 − 8·1 − 2·max(0,2−5)
