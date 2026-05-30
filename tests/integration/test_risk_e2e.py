"""End-to-end: signal ingest → risk tick → FindingRecord('risk.elevated')."""
from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.services import risk_service
from ccguard.server.services.risk_constants import RISK_RULE_ID


def test_ingested_signals_drive_a_risk_finding(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        session.add(Machine(machine_id="m-e2e", hostname="h"))
        session.add(
            MachineBaseline(
                machine_id="m-e2e",
                metric="bash_calls_per_day",
                mean=1.0,
                stdev=0.5,
                sample_count=14,
                baseline_ready=True,
            )
        )
        session.commit()

    body = {
        "schema_version": "0.2",
        "machine_id": "m-e2e",
        "events": [
            {
                "ts": datetime.now(UTC).isoformat(),
                "tool_name": "Bash",
                "fingerprint": "0123456789abcdef",
                "decision": "allow",
                "result_status": "success",
                "signals": [
                    "cred.read.aws",
                    "egress.network_tool",
                    "exec.pipe_to_shell",
                ],
            }
        ],
    }
    resp = client.post("/api/v1/audit", content=json.dumps(body), headers=auth_headers)
    assert resp.status_code == 200, resp.text

    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        summary = risk_service.tick(session)
        assert summary["findings_emitted"] >= 1
        finding = session.exec(
            select(FindingRecord).where(FindingRecord.rule_id == RISK_RULE_ID)
        ).first()
    assert finding is not None
    payload = json.loads(finding.payload_json)
    assert payload["score"] > payload["threshold"]
    assert set(payload["contributions"]) >= {
        "cred.read.aws",
        "egress.network_tool",
        "exec.pipe_to_shell",
    }
