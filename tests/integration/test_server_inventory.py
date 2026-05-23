"""POST /inventory + GET /machines/{id} + GET /findings: create → get → verify."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from ccguard.schemas import (
    AuditEntry,
    Finding,
    InventoryReport,
    PermissionsSnapshot,
    SyncPayload,
)


def _make_payload(machine_id: str = "machine-abc") -> dict:
    inv = InventoryReport(
        machine_id=machine_id,
        machine_label="laptop-test",
        timestamp=datetime.now(UTC),
        agent_version="0.1.0",
        os="linux",
        permissions=PermissionsSnapshot(),
    )
    findings = [
        Finding(
            rule_id="mcp_servers.denylist",
            severity="block",
            title="Banned MCP server",
            description="server 'shell-mcp' is in denylist",
            source="/home/test/.claude/settings.json",
            recommendation="remove this server",
            matched_value="shell-mcp",
        ),
        Finding(
            rule_id="hooks.unknown",
            severity="warn",
            title="Unknown hook",
            description="hook not in allowlist",
            source="...",
            recommendation="add to allowlist or remove",
        ),
    ]
    audit = [
        AuditEntry(
            timestamp=datetime.now(UTC),
            tool_name="Bash",
            decision="deny",
            rule_id="commands.denylist",
            reason="matched rm -rf /",
            tool_input_fingerprint="abc123",
        )
    ]
    payload = SyncPayload(inventory=inv, findings=findings, audit_events=audit)
    return payload.model_dump(mode="json")


def test_inventory_post_and_get_machine(client: TestClient, auth_headers: dict[str, str]) -> None:
    body = _make_payload("machine-1")
    r = client.post("/api/v1/inventory", json=body, headers=auth_headers)
    assert r.status_code == 200, r.text
    resp = r.json()
    assert resp["accepted"] is True
    assert resp["machine_id"] == "machine-1"
    assert resp["stored_findings_count"] == 2
    assert resp["stored_audit_count"] == 1

    r2 = client.get("/api/v1/machines/machine-1", headers=auth_headers)
    assert r2.status_code == 200
    detail = r2.json()
    assert detail["machine_id"] == "machine-1"
    assert detail["machine_label"] == "laptop-test"
    assert detail["inventory"]["machine_id"] == "machine-1"
    assert len(detail["findings"]) == 2
    assert len(detail["recent_audit_events"]) == 1


def test_inventory_post_then_list_machines(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    for mid in ("m-a", "m-b", "m-c"):
        body = _make_payload(mid)
        r = client.post("/api/v1/inventory", json=body, headers=auth_headers)
        assert r.status_code == 200

    r = client.get("/api/v1/machines", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    ids = {m["machine_id"] for m in body["machines"]}
    assert ids == {"m-a", "m-b", "m-c"}


def test_machines_severity_filter(client: TestClient, auth_headers: dict[str, str]) -> None:
    body = _make_payload("m-block")
    client.post("/api/v1/inventory", json=body, headers=auth_headers)

    # Запрос с severity=block → видим только машины, где есть хоть один block.
    r = client.get("/api/v1/machines?severity=block", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["total"] == 1

    # severity=info → пусто (у нас нет info findings).
    r2 = client.get("/api/v1/machines?severity=info", headers=auth_headers)
    assert r2.json()["total"] == 0


def test_findings_list_and_filter(client: TestClient, auth_headers: dict[str, str]) -> None:
    body = _make_payload("m-findings")
    client.post("/api/v1/inventory", json=body, headers=auth_headers)

    r = client.get("/api/v1/findings", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["total"] == 2

    r2 = client.get("/api/v1/findings?severity=block", headers=auth_headers)
    assert r2.json()["total"] == 1
    assert r2.json()["findings"][0]["finding"]["rule_id"] == "mcp_servers.denylist"

    r3 = client.get("/api/v1/findings?rule_id=hooks.unknown", headers=auth_headers)
    assert r3.json()["total"] == 1


def test_get_unknown_machine_returns_404(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.get("/api/v1/machines/nope", headers=auth_headers)
    assert r.status_code == 404


def test_inventory_invalid_payload_returns_422(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r = client.post("/api/v1/inventory", json={"foo": "bar"}, headers=auth_headers)
    assert r.status_code == 422
