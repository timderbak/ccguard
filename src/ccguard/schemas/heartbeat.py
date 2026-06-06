"""Heartbeat schema (ТЗ-07) — the agent's explicit "I'm alive" ping.

Deliberately tiny: liveness metadata only, never raw activity. Sent on a fixed
cadence even when there is nothing to sync, so the server can distinguish an
idle-but-alive sensor from a dead/suppressed one.
"""
from __future__ import annotations

from ccguard.schemas._base import SchemaBase
from pydantic import Field


class HeartbeatIn(SchemaBase):
    machine_id: str = Field(min_length=1, max_length=128)
    agent_version: str | None = Field(default=None, max_length=64)
    # Agent self-integrity: is the ccguard hook still installed in settings.json?
    # None = agent couldn't determine (don't treat as removal).
    hooks_intact: bool | None = None
    # Agent-declared heartbeat cadence so the server knows when it's overdue.
    expected_interval_sec: int | None = Field(default=None, ge=1, le=86400)
