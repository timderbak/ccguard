"""SQLModel-таблицы сервера ccguard."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

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
    """Findings.

    ``inventory_id`` is nullable from Phase 2 onward so anomaly findings — which
    are produced by server-side aggregation across a time window rather than by
    a single inventory snapshot — can be persisted without a synthetic snapshot
    link. Findings produced by Phase 1 check_engine continue to populate
    ``inventory_id`` with the snapshot they originated from.

    Note on migration: ``create_all`` is a no-op against an existing table, so
    pre-Phase-2 deployments will keep their NOT-NULL column constraint at the
    SQLite layer until the DB is re-created. This is acceptable because the
    Phase 2 writers (anomaly path) are not yet exposed to those deployments.
    Fresh installs get the nullable column immediately.
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    inventory_id: int | None = Field(default=None, index=True)
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


class PolicyVersion(SQLModel, table=True):
    """Policy revision history: draft / published / archived."""

    id: int | None = Field(default=None, primary_key=True)
    revision: int = Field(index=True)
    status: str = Field(index=True)  # "draft" | "published" | "archived"
    yaml_text: str
    comment: str | None = None
    created_by: str
    created_at: datetime = Field(default_factory=_utcnow)
    published_at: datetime | None = None


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


class ToolUseEvent(SQLModel, table=True):
    """Tool-use events from PostToolUse hook (TUA-02).

    Privacy: NO raw tool_input is ever stored; only a 16-hex fingerprint computed
    by the agent (see ``ccguard.agent.audit_hook.fingerprint``). This is the
    semantic counterpart of :class:`AuditRecord` (which captures only deny +
    fail-open enforcement events) — this table is the firehose of every tool
    invocation including allow/success outcomes.

    Auto-created via ``SQLModel.metadata.create_all`` (no Alembic per phase decision).
    Composite indexes for the dashboard query patterns are added by
    :func:`ccguard.server.db.session.init_db` as ``CREATE INDEX IF NOT EXISTS``.
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    ts: datetime = Field(index=True)
    received_at: datetime = Field(default_factory=_utcnow)
    tool_name: str = Field(index=True)
    fingerprint: str = Field(index=True)
    decision: str = Field(index=True)
    result_status: str


class MachineBaseline(SQLModel, table=True):
    """Cached per-machine per-metric anomaly baseline (Phase 2 / Plan 02-01).

    One row per (machine_id, metric) — composite uniqueness is enforced via a
    ``CREATE UNIQUE INDEX IF NOT EXISTS`` in
    :func:`ccguard.server.db.session.init_db`, NOT via a SQLModel
    ``UniqueConstraint``. We keep parity with the Phase 1 ``tool_use_event``
    index pattern (also DDL-driven) because mixing ``Field(index=True)`` with
    ``__table_args__`` UniqueConstraints is brittle under repeated
    ``create_all`` calls in tests.

    ``recent_points_json`` is a JSON-encoded ``list[float]`` of up to 14 recent
    daily observations, retained for sparkline reuse so the UI does not have to
    re-aggregate every render.
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    # One of ``ccguard.server.services.anomaly_constants.ALL_METRICS``.
    metric: str = Field(index=True)
    mean: float
    stdev: float
    sample_count: int
    baseline_ready: bool = Field(default=False)
    # JSON-encoded ``list[float]``; up to 14 entries.
    recent_points_json: str = Field(default="[]")
    updated_at: datetime = Field(default_factory=_utcnow)


# --- Phase 3 / Plan 03-01: LLM content scanner foundations ------------------


# ``scope`` is stored as ``str`` (not Literal) at the SQLModel layer so SQLite
# does not need a separate column-level CHECK constraint. The application layer
# validates the value via this alias when constructing rows.
ScanScope = Literal["agent", "skill"]


class ScanResult(SQLModel, table=True):
    """Cached LLM-scanner verdict per artifact, keyed by content hash.

    One row per unique ``file_hash`` (UNIQUE) — Plan 03-01 D-03 makes the hash
    the cache key, so re-scanning identical content is a no-op. ``ttl_expires_at``
    drives the cache-eviction sweep introduced in Plan 03-03.

    Plan 03-01 deliberately does NOT add a column-level CHECK on ``scope`` or
    ``risk_score`` — Phase 1+2 pattern keeps SQLite schemas Pydantic-validated
    at the write boundary, not enforced by the engine, so ``create_all`` stays
    a no-op against pre-existing tables.
    """

    id: int | None = Field(default=None, primary_key=True)
    file_hash: str = Field(unique=True, index=True)
    file_path: str
    # ``ScanScope`` Literal at the Python boundary; stored as plain str.
    scope: str = Field(index=True)
    risk_score: int  # 0–100, validated at write boundary by the scanner service.
    category: str = Field(index=True)
    rationale: str = Field(max_length=500)
    scanned_at: datetime = Field(default_factory=_utcnow, index=True)
    model: str
    ttl_expires_at: datetime = Field(index=True)


class LLMCallLog(SQLModel, table=True):
    """Audit log: one row per Anthropic API call made by the scanner.

    Drives:
    - daily call counter for the budget enforcer (Plan 03-03) via composite
      index ``(ts, model)`` installed in :func:`init_db`;
    - per-file_hash provenance for admin audits.

    No raw content is ever stored — only token counts, cost estimate, and a
    pointer to the corresponding ``ScanResult`` via ``file_hash``.
    """

    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=_utcnow, index=True)
    file_hash: str = Field(index=True)
    model: str
    input_tokens: int
    output_tokens: int
    cost_estimate_cents: int


class SettingsRecord(SQLModel, table=True):
    """Key/value store for admin-tunable server settings (Plan 03-01 D-04).

    Seeded on first startup by
    :func:`ccguard.server.services.settings_service.seed_llm_settings` with
    ``llm_scanner_enabled=false`` and ``daily_call_budget=100``. Subsequent
    re-seeds preserve admin edits (idempotent insert-or-skip, never overwrite).

    Values are plain strings so callers can store any literal (bool/int/etc.);
    typing is delegated to a thin accessor layer in ``settings_service``.
    """

    key: str = Field(primary_key=True)
    value: str
    updated_at: datetime = Field(default_factory=_utcnow)
