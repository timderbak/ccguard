"""Audit-лог: запись об одном решении enforce.

Also defines the inbound wire schemas for the POST /api/v1/audit
``event_source=policy_apply`` branch added in plan 04-04.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from ccguard.schemas._base import SchemaBase


class AuditEntry(SchemaBase):
    timestamp: datetime
    tool_name: str
    decision: Literal["allow", "deny"]
    rule_id: str | None = None
    reason: str | None = None
    fail_open: bool = False
    tool_input_fingerprint: str


class PolicyApplyEventPayload(SchemaBase):
    """One agent-reported policy-apply outcome — wire schema for plan 04-04.

    Mirrors :class:`ccguard.server.db.models.PolicyApplyEvent`. Server stores
    ``ts`` as UTC; we enforce tz-awareness at the write boundary just like
    :class:`ccguard.schemas.tool_use.ToolUseEventIn`.

    WR-05: ``extra="ignore"`` so a v0.3 agent can post additional fields
    (e.g. ``token_id``) without 422-ing on a v0.2 server. Matches the
    Policy-schema pattern in ``policy.py``.
    """

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        frozen=False,
    )

    machine_id: str = Field(min_length=1, max_length=128)
    ts: datetime
    result: Literal["success", "rollback"]
    applied_count: int = 0
    snapshot_id: str | None = None
    reason: str | None = None
    failed_file: str | None = None
    policy_revision: int

    @field_validator("ts", mode="after")
    @classmethod
    def _enforce_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("ts must be timezone-aware (UTC)")
        if v.utcoffset() != UTC.utcoffset(v):
            return v.astimezone(UTC)
        return v


class PolicyApplyBatchIn(SchemaBase):
    """Inbound envelope when ``event_source='policy_apply'``.

    ``schema_version`` is OPTIONAL on this branch (D-1: backward-compat for
    v0.1 agents that don't stamp it on the new event type). The server stays
    at major schema_version=1.

    WR-05: ``extra="ignore"`` so future agent versions can add envelope-
    level fields without 422-ing on v0.2 servers.
    """

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        frozen=False,
    )

    schema_version: str | None = None
    events: list[PolicyApplyEventPayload] = Field(min_length=1, max_length=200)
