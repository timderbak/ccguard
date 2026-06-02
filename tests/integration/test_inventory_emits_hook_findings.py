"""POST /api/v1/inventory с hooks → HookBaseline rows + FindingRecord.

Smoke: первый sync — silent bootstrap. Второй с подменой content hash —
``hook.rug_pull.content`` block-finding.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import HookEntry, InventoryReport, SyncPayload
from ccguard.server.db.models import FindingRecord, HookBaseline


def _payload(machine_id: str, hooks: list[HookEntry]) -> dict:
    inv = InventoryReport(
        machine_id=machine_id,
        machine_label="hook-tofu-test",
        timestamp=datetime.now(UTC),
        agent_version="0.2.0",
        os="linux",
        hooks=hooks,
    )
    return SyncPayload(inventory=inv, findings=[], audit_events=[]).model_dump(mode="json")


def _hook(command: str = "python /opt/x.py", content_hash: str | None = "AAA") -> HookEntry:
    return HookEntry(
        event="PreToolUse",
        matcher="Bash",
        type="command",
        command=command,
        source="/root/.claude/settings.json",
        command_file_path="/opt/x.py",
        command_file_hash=content_hash,
    )


def test_first_inventory_creates_pending_baselines_no_findings(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/v1/inventory",
        json=_payload("m-hook-1", [_hook()]),
        headers=auth_headers,
    )
    assert r.status_code == 200, r.text

    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        baselines = s.exec(select(HookBaseline)).all()
        assert len(baselines) == 1
        assert baselines[0].status == "pending"

        hook_findings = s.exec(
            select(FindingRecord).where(FindingRecord.rule_id.like("hook.%"))
        ).all()
        assert hook_findings == []  # bootstrap silent


def test_second_inventory_with_content_drift_emits_block(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    machine_id = "m-hook-2"
    client.post(
        "/api/v1/inventory",
        json=_payload(machine_id, [_hook(content_hash="AAA")]),
        headers=auth_headers,
    )

    engine = client.app.state.engine  # type: ignore[attr-defined]
    # promote to active manually (simulate admin accept).
    with Session(engine) as s:
        row = s.exec(select(HookBaseline)).one()
        row.status = "active"
        s.add(row)
        s.commit()

    client.post(
        "/api/v1/inventory",
        json=_payload(machine_id, [_hook(content_hash="BBB")]),
        headers=auth_headers,
    )

    with Session(engine) as s:
        findings = s.exec(
            select(FindingRecord).where(FindingRecord.rule_id == "hook.rug_pull.content")
        ).all()
        assert len(findings) == 1
        assert findings[0].severity == "block"
