"""machine_detail renders explainability for risk + sequence findings."""
from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord, Machine
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.risk_constants import RISK_RULE_ID
from ccguard.server.services.sequence_constants import SEQUENCE_RULE_ID
from ccguard.server.main import create_app


def _login(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-explain")
    return TestClient(create_app())


def test_risk_finding_renders_score_and_contributions(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(Machine(machine_id="m-r", machine_label="riskbox", first_seen=now, last_seen=now))
            s.add(
                FindingRecord(
                    machine_id="m-r",
                    inventory_id=None,
                    rule_id=RISK_RULE_ID,
                    severity="warn",
                    discovered_at=now,
                    payload_json=json.dumps(
                        {
                            "score": 13.0,
                            "threshold": 10.0,
                            "window_hours": 24.0,
                            "half_life_hours": 6.0,
                            "contributions": {
                                "cred.read.aws": 5.0,
                                "egress.network_tool": 4.0,
                            },
                            "event_count": 1,
                        }
                    ),
                )
            )
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get("/machines/m-r", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert RISK_RULE_ID in body
        # Score line.
        assert "13.0" in body and "threshold 10.0" in body
        # Contribution signal IDs and ATT&CK URLs.
        assert "cred.read.aws" in body
        assert "egress.network_tool" in body
        assert "https://attack.mitre.org/techniques/T1552/001/" in body
        assert "https://attack.mitre.org/techniques/T1041/" in body


def test_sequence_finding_renders_cred_and_egress(monkeypatch, tmp_path) -> None:
    with _login(monkeypatch, tmp_path) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(Machine(machine_id="m-s", machine_label="seqbox", first_seen=now, last_seen=now))
            s.add(
                FindingRecord(
                    machine_id="m-s",
                    inventory_id=None,
                    rule_id=SEQUENCE_RULE_ID,
                    severity="high",
                    discovered_at=now,
                    payload_json=json.dumps(
                        {
                            "cred_ts": "2026-05-30T11:55:00+00:00",
                            "cred_signal": "cred.read.aws",
                            "egress_ts": "2026-05-30T12:00:00+00:00",
                            "egress_signal": "egress.network_tool",
                            "elapsed_seconds": 300.0,
                            "window_minutes": 15.0,
                            "lookback_hours": 24.0,
                        }
                    ),
                )
            )
            s.commit()
            sid = create_session(s, user_id="admin")

        r = client.get("/machines/m-s", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert SEQUENCE_RULE_ID in body
        # high severity badge.
        assert "high" in body
        assert "cred → egress" in body
        assert "300s" in body
        assert "https://attack.mitre.org/techniques/T1552/001/" in body
        assert "https://attack.mitre.org/techniques/T1041/" in body
