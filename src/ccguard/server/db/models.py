"""SQLModel-таблицы сервера ccguard."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Machine(SQLModel, table=True):
    """Машина, идентифицируемая стабильным псевдонимом."""

    machine_id: str = Field(primary_key=True, index=True)
    machine_label: str | None = None
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    agent_version: str | None = None


class InventorySnapshot(SQLModel, table=True):
    """История inventory-снимков от агента."""

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    received_at: datetime = Field(default_factory=_utcnow)
    payload_json: str  # сериализованный InventoryReport


class FindingRecord(SQLModel, table=True):
    """Findings, ассоциированные с конкретным inventory."""

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    inventory_id: int = Field(index=True)
    rule_id: str = Field(index=True)
    severity: str = Field(index=True)
    discovered_at: datetime = Field(default_factory=_utcnow)
    payload_json: str  # сериализованный Finding


class AgentToken(SQLModel, table=True):
    """Hashed agent token. Replaces env-var list at runtime."""

    id: int | None = Field(default=None, primary_key=True)
    label: str
    token_hash: str = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class WebSession(SQLModel, table=True):
    """Browser session for ccguard web UI."""

    id: str = Field(primary_key=True)
    user_id: str = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime = Field(index=True)


class AuditRecord(SQLModel, table=True):
    """Audit-события (только deny + fail_open), присланные агентом."""

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    received_at: datetime = Field(default_factory=_utcnow)
    timestamp: datetime
    tool_name: str
    decision: str
    rule_id: str | None
    reason: str | None
    fail_open: bool
    tool_input_fingerprint: str
