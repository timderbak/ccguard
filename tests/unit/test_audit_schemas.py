"""Pydantic validation matrix for ccguard.schemas.tool_use (TUA-01, TUA-02)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ccguard.schemas.tool_use import (
    SCHEMA_VERSION_AUDIT,
    AuditBatchIn,
    AuditBatchOut,
    ToolUseEventIn,
)


def _good_event() -> dict:
    return {
        "ts": datetime.now(UTC).isoformat(),
        "tool_name": "Bash",
        "fingerprint": "0123456789abcdef",
        "decision": "allow",
        "result_status": "success",
    }


def test_schema_version_constant() -> None:
    assert SCHEMA_VERSION_AUDIT == "0.2"


def test_tool_use_event_in_happy_path() -> None:
    e = ToolUseEventIn.model_validate(_good_event())
    assert e.tool_name == "Bash"
    assert e.fingerprint == "0123456789abcdef"


def test_fingerprint_must_be_16_hex_lowercase() -> None:
    bad = _good_event() | {"fingerprint": "NOTHEX!"}
    with pytest.raises(ValidationError):
        ToolUseEventIn.model_validate(bad)
    bad2 = _good_event() | {"fingerprint": "0123456789ABCDEF"}  # uppercase
    with pytest.raises(ValidationError):
        ToolUseEventIn.model_validate(bad2)
    bad3 = _good_event() | {"fingerprint": "abc"}  # too short
    with pytest.raises(ValidationError):
        ToolUseEventIn.model_validate(bad3)


def test_decision_literal_enforced() -> None:
    bad = _good_event() | {"decision": "ignore"}
    with pytest.raises(ValidationError):
        ToolUseEventIn.model_validate(bad)


def test_result_status_literal_enforced() -> None:
    bad = _good_event() | {"result_status": "ok"}
    with pytest.raises(ValidationError):
        ToolUseEventIn.model_validate(bad)


def test_tool_name_min_length() -> None:
    bad = _good_event() | {"tool_name": ""}
    with pytest.raises(ValidationError):
        ToolUseEventIn.model_validate(bad)


def test_audit_batch_in_empty_events_rejected() -> None:
    with pytest.raises(ValidationError):
        AuditBatchIn.model_validate(
            {
                "schema_version": SCHEMA_VERSION_AUDIT,
                "machine_id": "abc",
                "events": [],
            }
        )


def test_audit_batch_in_oversize_rejected() -> None:
    too_many = [_good_event() for _ in range(201)]
    with pytest.raises(ValidationError):
        AuditBatchIn.model_validate(
            {
                "schema_version": SCHEMA_VERSION_AUDIT,
                "machine_id": "abc",
                "events": too_many,
            }
        )


def test_audit_batch_in_max_size_accepted() -> None:
    ok = [_good_event() for _ in range(200)]
    batch = AuditBatchIn.model_validate(
        {
            "schema_version": SCHEMA_VERSION_AUDIT,
            "machine_id": "abc",
            "events": ok,
        }
    )
    assert len(batch.events) == 200


def test_audit_batch_in_machine_id_required() -> None:
    with pytest.raises(ValidationError):
        AuditBatchIn.model_validate(
            {
                "schema_version": SCHEMA_VERSION_AUDIT,
                "machine_id": "",
                "events": [_good_event()],
            }
        )


def test_audit_batch_out_roundtrip() -> None:
    out = AuditBatchOut(
        accepted=True,
        stored=10,
        rejected=0,
        server_schema_version=SCHEMA_VERSION_AUDIT,
    )
    assert out.model_dump()["accepted"] is True


def test_no_tool_input_field_exists() -> None:
    """Privacy invariant: ToolUseEventIn must NEVER carry raw tool_input."""
    assert "tool_input" not in ToolUseEventIn.model_fields
