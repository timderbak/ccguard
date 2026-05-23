"""Audit-лог: запись об одном решении enforce."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from ccguard.schemas._base import SchemaBase


class AuditEntry(SchemaBase):
    timestamp: datetime
    tool_name: str
    decision: Literal["allow", "deny"]
    rule_id: str | None = None
    reason: str | None = None
    fail_open: bool = False
    tool_input_fingerprint: str
