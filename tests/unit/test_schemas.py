"""Round-trip и валидационные тесты pydantic-схем."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ccguard.schemas import (
    AuditEntry,
    EnforceDecision,
    EnforceHookInput,
    Finding,
    InventoryReport,
    Policy,
    PolicyMeta,
    SyncPayload,
)


def test_inventory_round_trip(sample_inventory: InventoryReport) -> None:
    raw = sample_inventory.model_dump_json()
    restored = InventoryReport.model_validate_json(raw)
    assert restored == sample_inventory


def test_policy_round_trip(sample_policy: Policy) -> None:
    raw = sample_policy.model_dump_json()
    restored = Policy.model_validate_json(raw)
    assert restored == sample_policy


def test_extra_forbid_rejects_unknown_field() -> None:
    """Все схемы запрещают неизвестные поля (защита от опечаток)."""
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                "rule_id": "test",
                "severity": "warn",
                "title": "t",
                "description": "d",
                "source": "s",
                "recommendation": "r",
                "unknown_field": "boom",
            }
        )


def test_severity_literal_validation() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                "rule_id": "test",
                "severity": "critical",
                "title": "t",
                "description": "d",
                "source": "s",
                "recommendation": "r",
            }
        )


def test_policy_unknown_schema_version_rejected() -> None:
    """schema_version=Literal[1] не пропускает чужие версии."""
    with pytest.raises(ValidationError):
        PolicyMeta.model_validate(
            {"schema_version": 2, "revision": 1, "updated_at": datetime.now(UTC).isoformat()}
        )


def test_enforce_hook_input_ignores_extra() -> None:
    """В отличие от остальных схем, EnforceHookInput игнорирует чужие поля
    (Claude Code может прислать больше, чем нам нужно)."""
    parsed = EnforceHookInput.model_validate(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "cwd": "/tmp",
            "session_id": "abc",
            "transcript_path": "/some/path",  # не объявлено в схеме
            "permission_mode": "default",  # не объявлено
        }
    )
    assert parsed.tool_name == "Bash"
    assert parsed.tool_input == {"command": "ls"}


def test_enforce_decision_basic() -> None:
    d = EnforceDecision(permission="deny", reason="banned command", rule_id="cmd.denylist")
    assert d.permission == "deny"
    assert d.fail_open is False


def test_audit_entry_serializes() -> None:
    entry = AuditEntry(
        timestamp=datetime.now(UTC),
        tool_name="Bash",
        decision="deny",
        rule_id="cmd.denylist",
        reason="matched pattern",
        tool_input_fingerprint="abc123def456",
    )
    raw = entry.model_dump_json()
    restored = AuditEntry.model_validate_json(raw)
    assert restored == entry


def test_sync_payload_composes(sample_inventory: InventoryReport) -> None:
    payload = SyncPayload(inventory=sample_inventory, findings=[], audit_events=[])
    raw = payload.model_dump_json()
    restored = SyncPayload.model_validate_json(raw)
    assert restored.inventory.machine_id == sample_inventory.machine_id


def test_finding_optional_matched_value() -> None:
    f = Finding(
        rule_id="x",
        severity="info",
        title="t",
        description="d",
        source="s",
        recommendation="r",
    )
    assert f.matched_value is None


def test_policy_meta_revision_required() -> None:
    with pytest.raises(ValidationError):
        PolicyMeta.model_validate({"schema_version": 1, "updated_at": datetime.now(UTC).isoformat()})
