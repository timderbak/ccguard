"""Demo seeder for P7-depth (slow_chain + anomaly-wider) — local verification.

Seeds a dev DB with synthetic ToolUseEvents that exercise the new engines, then
runs the engine ticks directly (so findings appear immediately instead of
waiting for the hourly scheduler). Point the server at the same DB to click
through the UI.

Usage:
    CCGUARD_DB_URL="sqlite:////tmp/ccguard-dev.db" .venv/bin/python scripts/demo_p7.py

Then bring up the server against the SAME CCGUARD_DB_URL and open:
    /machines/demo-lowslow      → the ioa.slow_chain finding with its stage timeline
    /anomalies                  → the 10-column metric matrix (P7 behavioral volume)
    /detectors/slow_chain       → the detector explanation
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import (
    anomaly_service,
    chain_engine,
    risk_service,
    sequence_service,
    slow_chain_service,
)

MACHINE = "demo-lowslow"


def _ev(s: Session, *, ts: datetime, tool: str, signals: list[str], session_id: str = "demo") -> None:
    s.add(
        ToolUseEvent(
            machine_id=MACHINE,
            ts=ts,
            tool_name=tool,
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps(signals),
            session_id=session_id,
        )
    )


def main() -> int:
    url = os.environ.get("CCGUARD_DB_URL", "sqlite:////tmp/ccguard-dev.db")
    eng = make_engine(url)
    init_db(eng)
    now = datetime.now(UTC)

    with Session(eng) as s:
        # Idempotent: clear prior demo rows so re-runs are clean.
        for row in s.exec(select(ToolUseEvent).where(ToolUseEvent.machine_id == MACHINE)):
            s.delete(row)
        for row in s.exec(select(FindingRecord).where(FindingRecord.machine_id == MACHINE)):
            s.delete(row)
        if s.get(Machine, MACHINE) is None:
            s.add(Machine(machine_id=MACHINE, machine_label="low-and-slow demo",
                          first_seen=now - timedelta(days=20), last_seen=now,
                          agent_version="0.1.0"))
        s.commit()

        # --- the low-and-slow kill chain: 3 distinct advanced stages, spread
        # across days so the minute/hour window engines miss it ---------------
        _ev(s, ts=now - timedelta(days=6), tool="Bash", signals=["cred.read.aws"])         # Mon
        _ev(s, ts=now - timedelta(days=3, hours=4), tool="Bash", signals=["egress.http_client"])  # Wed
        _ev(s, ts=now - timedelta(days=1, hours=2), tool="Bash", signals=["defense.clear_logs"])  # Fri

        # --- some benign daily volume so the anomaly matrix sparklines have
        # data to draw across the 14-day window -------------------------------
        for d in range(14):
            day = now - timedelta(days=d)
            for _ in range(2):
                _ev(s, ts=day, tool="Read", signals=[])
            _ev(s, ts=day, tool="Bash", signals=[])
        s.commit()

        # --- run the engines now (don't wait for the hourly scheduler) -------
        summaries = {
            "anomaly": anomaly_service.tick(s),
            "risk": risk_service.tick(s),
            "sequence": sequence_service.tick(s),
            "chain": chain_engine.tick(s),
            "slow_chain": slow_chain_service.tick(s),
        }
        findings = list(s.exec(select(FindingRecord).where(FindingRecord.machine_id == MACHINE)))

    print(f"DB: {url}")
    print(f"machine: {MACHINE}")
    for name, summ in summaries.items():
        print(f"  {name:11s} tick → findings_emitted={summ['findings_emitted']} errors={len(summ['errors'])}")
    print(f"\nfindings on {MACHINE}: {len(findings)}")
    for f in findings:
        print(f"  [{f.severity}] {f.rule_id}")
        if f.rule_id == "ioa.slow_chain":
            payload = json.loads(f.payload_json)
            print(f"      distinct_count={payload['distinct_count']} span_hours={payload['span_hours']}")
            for st in payload["stages"]:
                print(f"      · {st['stage']:20s} {st['example_signal']:22s} ×{st['count']}")
    print("\nNow point the server at this DB and open /machines/demo-lowslow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
