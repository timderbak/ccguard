"""machine_detail рендерит секцию подозрительных сетевых вызовов.

Покрытие:

* FindingRecord с rule_id ``network.suspicious.egress/discord-webhook``
  → карточка с hostname и meta из дефолтного каталога.
* Машина без таких findings → empty-state «За последние 24 часа …».
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord, Machine
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password

from tests.integration.conftest import VALID_TOKEN


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret-net-find")
    monkeypatch.setenv("CCGUARD_TOKENS", VALID_TOKEN)
    return TestClient(create_app())


def _seed_machine_and_finding(
    engine,
    machine_id: str,
    *,
    rule_id: str,
    severity: str,
    target: str,
) -> str:
    with Session(engine) as s:
        s.add(
            Machine(
                machine_id=machine_id,
                machine_label="net-ui",
                last_seen=datetime.now(UTC),
                agent_version="0.2.0",
            )
        )
        s.add(
            FindingRecord(
                machine_id=machine_id,
                inventory_id=None,
                rule_id=rule_id,
                severity=severity,
                discovered_at=datetime.now(UTC) - timedelta(minutes=5),
                payload_json=json.dumps(
                    {"matched_value": target, "title": "from-agent-title"}
                ),
            )
        )
        s.commit()
        sid = create_session(s, user_id="admin")
    return sid


def test_machine_detail_renders_network_card(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        machine_id = "m-net-1"
        sid = _seed_machine_and_finding(
            client.app.state.engine,  # type: ignore[attr-defined]
            machine_id,
            rule_id="network.suspicious.egress/discord-webhook",
            severity="block",
            target="discord.com/api/webhooks/123/abc",
        )
        r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        html = r.text
        assert "Сетевые вызовы за сутки" in html
        assert "discord.com/api/webhooks/123/abc" in html
        # rule_id виден моноширинно
        assert "network.suspicious.egress/discord-webhook" in html
        # severity badge
        assert "block" in html


def test_machine_detail_empty_state(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        machine_id = "m-net-empty"
        with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
            s.add(
                Machine(
                    machine_id=machine_id,
                    machine_label="empty",
                    last_seen=datetime.now(UTC),
                    agent_version="0.2.0",
                )
            )
            s.commit()
            sid = create_session(s, user_id="admin")
        r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        assert "За последние 24 часа подозрительных сетевых вызовов не было." in r.text


def test_old_findings_outside_24h_window_are_excluded(monkeypatch, tmp_path) -> None:
    with _client(monkeypatch, tmp_path) as client:
        machine_id = "m-net-old"
        with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
            s.add(
                Machine(
                    machine_id=machine_id,
                    machine_label="old",
                    last_seen=datetime.now(UTC),
                    agent_version="0.2.0",
                )
            )
            s.add(
                FindingRecord(
                    machine_id=machine_id,
                    inventory_id=None,
                    rule_id="network.suspicious.egress/pastebin",
                    severity="block",
                    discovered_at=datetime.now(UTC) - timedelta(days=3),
                    payload_json=json.dumps(
                        {"matched_value": "pastebin.com/raw/old"}
                    ),
                )
            )
            s.commit()
            sid = create_session(s, user_id="admin")
        r = client.get(f"/machines/{machine_id}", cookies={"ccg_session": sid})
        assert r.status_code == 200
        # Старый finding не должен попасть в 24h-окно.
        assert "pastebin.com/raw/old" not in r.text
        assert "За последние 24 часа подозрительных сетевых вызовов не было." in r.text
