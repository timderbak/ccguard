"""End-to-end: signal ingest → sequence tick → FindingRecord('ioa.exfil_sequence')."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.services import sequence_service
from ccguard.server.services.sequence_constants import SEQUENCE_RULE_ID


def test_ingested_cred_then_egress_drives_sequence_finding(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        session.add(Machine(machine_id="m-seq-e2e", hostname="h"))
        session.add(
            MachineBaseline(
                machine_id="m-seq-e2e",
                metric="bash_calls_per_day",
                mean=1.0,
                stdev=0.5,
                sample_count=14,
                baseline_ready=True,
            )
        )
        session.commit()

    now = datetime.now(UTC)
    cred_ts = (now - timedelta(minutes=5)).isoformat()
    egress_ts = now.isoformat()
    body = {
        "schema_version": "0.2",
        "machine_id": "m-seq-e2e",
        "events": [
            {
                "ts": cred_ts,
                "tool_name": "Read",
                "fingerprint": "0123456789abcdef",
                "decision": "allow",
                "result_status": "success",
                "signals": ["cred.read.aws"],
            },
            {
                "ts": egress_ts,
                "tool_name": "Bash",
                "fingerprint": "fedcba9876543210",
                "decision": "allow",
                "result_status": "success",
                "signals": ["egress.network_tool"],
            },
        ],
    }
    resp = client.post("/api/v1/audit", content=json.dumps(body), headers=auth_headers)
    assert resp.status_code == 200, resp.text

    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        summary = sequence_service.tick(session)
        assert summary["findings_emitted"] >= 1
        finding = session.exec(
            select(FindingRecord).where(FindingRecord.rule_id == SEQUENCE_RULE_ID)
        ).first()
    assert finding is not None
    assert finding.severity == "high"
    payload = json.loads(finding.payload_json)
    assert payload["cred_signal"] == "cred.read.aws"
    assert payload["egress_signal"] == "egress.network_tool"
    assert 0.0 < payload["elapsed_seconds"] <= 600.0
