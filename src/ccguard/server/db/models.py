"""SQLModel-таблицы сервера ccguard."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import field_validator
from sqlalchemy import Index
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
    # ТЗ-07 sensor self-protection. ``last_heartbeat_at`` is the explicit "I'm
    # alive" ping (distinct from last_seen, which only moves on inventory/audit)
    # — lets the server tell an idle-but-alive sensor from a dead/suppressed one.
    # NULL = a legacy agent that never sent a heartbeat (never alerted on).
    # Additive columns are created on existing DBs via ALTER in init_db.
    last_heartbeat_at: datetime | None = None
    expected_interval_sec: int | None = None  # agent-declared heartbeat cadence
    hooks_intact: bool | None = None  # last self-check: ccguard hook still installed?
    silent_since: datetime | None = None  # open silence episode (dedup); NULL = active
    # C2: hook-config hash attestation. ``hooks_hash`` = last reported hash of the
    # ccguard hook config; ``hooks_hash_baseline`` = TOFU-pinned expected hash.
    # Drift between them raises sensor.hook_drift (catches decoy-shim repoint).
    hooks_hash: str | None = None
    hooks_hash_baseline: str | None = None


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
    # JSON-encoded list[str] of per-event behavioral signal IDs (Behavioral
    # Detection Stage 1). Default "[]" so v0.1 agents and create_all-on-existing
    # DBs degrade gracefully. NO raw tool_input is ever stored here.
    signals_json: str = Field(default="[]")
    # Per-User Attribution: shell user the tool call ran under. Nullable so
    # old agents (which don't send this) ingest cleanly.
    actor_user: str | None = Field(default=None, index=True)
    # Claude Code session id (ТЗ-01). Nullable — old agents don't send it;
    # sequence correlation groups by session_id and falls back to machine-scope
    # when NULL. Indexed because correlation filters on it. Additive column on
    # existing DBs is created by init_db's ALTER (create_all is a no-op there).
    session_id: str | None = Field(default=None, index=True)
    # --- Личность агента: «кто действовал и с какими правами» ----------------
    # Claude Code передаёт это в каждом вызове хука. Всё nullable: агенты
    # v0.1/v0.2 не шлют, и такие события просто остаются без атрибуции.
    #
    # permission_mode — режим прав на момент вызова (default | plan |
    # acceptEdits | auto | dontAsk | bypassPermissions). Значения dontAsk и
    # bypassPermissions означают работу БЕЗ подтверждений человеком — для ИБ
    # это то же, что «сотрудник отключил защиту», поэтому поле проиндексировано:
    # по нему строится сводка «сколько машин работают без подтверждений».
    permission_mode: str | None = Field(default=None, index=True)
    # Заполняются, только когда действовал субагент; NULL = основной агент.
    agent_type: str | None = Field(default=None, index=True)
    agent_id: str | None = None
    # Связывает цепочку действий с ОДНИМ запросом человека (Claude Code
    # v2.1.196+) — по нему отличается «человек попросил несколько вещей» от
    # «агент сам сделал десятки шагов после одной команды».
    prompt_id: str | None = Field(default=None, index=True)


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
    # Detailed rationale fields (feat/skills-detailed-rationale). Optional so
    # rows produced by pre-feature scanners keep loading; backfilled on next
    # rescan. The LLM tool-use schema requests these; the parser tolerates
    # absence so older Anthropic models that ignore the new field still work.
    # Caps mirror the LLM tool input_schema (2000 / 500); the scanner truncates
    # before persist so a misbehaving model cannot blow past the column type.
    explanation: str | None = Field(default=None, max_length=2000)
    quoted_snippet: str | None = Field(default=None, max_length=500)


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


# --- Phase 4 / Plan 04-01: push-install audit foundation -------------------


# Allowed values for ``PolicyApplyEvent.result``. SQLModel cannot infer a
# SQLAlchemy type from ``Literal`` directly, so the column is stored as plain
# TEXT in SQLite (Phase 1+2 pattern — no engine-level CHECK) and a Pydantic
# ``field_validator`` enforces the set at the write boundary.
_POLICY_APPLY_RESULTS: frozenset[str] = frozenset({"success", "rollback"})


class PolicyApplyEvent(SQLModel, table=True):
    """Agent-reported outcome of applying a policy revision (PUSH-01..04 audit).

    One row per apply attempt by the endpoint agent. Drives the
    ``/audit?event_source=policy_apply`` view (plan 05) and the rollback
    drill-down (failed_file + reason).

    Composite indexes (machine_id, ts) and (result, ts) match the two common
    query paths: per-machine timeline and "show all rollbacks across the fleet".
    Per D-3 NO orphan_deletion fields are added — deferred to v0.3.

    Auto-created via ``SQLModel.metadata.create_all`` (no Alembic per project
    constraint).
    """

    __table_args__ = (
        Index("ix_policy_apply_machine_ts", "machine_id", "ts"),
        Index("ix_policy_apply_result_ts", "result", "ts"),
    )

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    ts: datetime = Field(default_factory=_utcnow, index=True)
    # Stored as plain str in SQLite; the field_validator below enforces the
    # Literal set ``{"success", "rollback"}`` at the Pydantic write boundary.
    result: str
    applied_count: int = 0
    snapshot_id: str | None = None
    reason: str | None = None
    failed_file: str | None = None
    policy_revision: int

    @field_validator("result")
    @classmethod
    def _validate_result(cls, v: str) -> str:
        if v not in _POLICY_APPLY_RESULTS:
            raise ValueError(
                f"result must be one of {sorted(_POLICY_APPLY_RESULTS)}; got: {v!r}"
            )
        return v


class ProposedSignal(SQLModel, table=True):
    """LLM-drafted (or admin-drafted) catalog signal awaiting human approval.

    Stage E1 of the Rule Discovery Agent. Approval validates the draft's regex,
    writes a SettingsRecord override at ``catalog.override.<id>`` (consumed by
    later stages' policy sync), and stamps reviewer + timestamp here.

    Status lifecycle: ``pending`` → ``approved`` | ``rejected``. A given draft
    is reviewed exactly once — re-approval / re-rejection raise NotPending.
    """

    id: int | None = Field(default=None, primary_key=True)
    draft_json: str  # signal: {id, attack_technique, pattern, description}
                     # pi_pattern: {category, pattern, description}
    source_kind: str = Field(index=True)  # manual | mitre | atlas | atomic-red-team | lakera | cve | manual-pi | llm-pi
    source_url: str | None = None
    source_title: str | None = None
    llm_rationale: str | None = None
    status: str = Field(default="pending", index=True)
    # ``signal`` (default — behavioral signal catalog) or ``pi_pattern``
    # (prompt-injection regex). Drives approval validation + override key.
    kind: str = Field(default="signal", index=True)
    created_at: datetime = Field(default_factory=_utcnow, index=True)
    reviewed_at: datetime | None = None
    reviewed_by: str | None = None
    rejection_reason: str | None = None

    def id_in_draft(self) -> str:
        """Convenience: return signal/pattern id from the draft JSON."""
        import json as _json
        d = _json.loads(self.draft_json)
        return d.get("id") or d.get("category") or "(unknown)"


class MachineRiskHistory(SQLModel, table=True):
    """Daily snapshot of a machine's current decay-weighted risk score.

    Populated by ``risk_service.tick`` — UPSERT of (machine_id, date_utc).
    Drives the 14-day sparkline on machine_detail without re-running the
    scoring kernel on every page render.
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    date_utc: str = Field(index=True)  # ISO date 'YYYY-MM-DD'
    score: float
    top_signal: str | None = None
    updated_at: datetime = Field(default_factory=_utcnow)


class MachineUserRiskHistory(SQLModel, table=True):
    """Daily per-(machine, user) risk score snapshot.

    Complements the machine-level :class:`MachineRiskHistory`. Populated by
    ``risk_service.tick`` by grouping events on ``actor_user``. Events with
    ``actor_user IS NULL`` (v0.1/v0.2 agents) are aggregated under the
    sentinel ``"_unknown"`` so the table stays well-typed.
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    actor_user: str = Field(index=True)
    date_utc: str = Field(index=True)
    score: float
    top_signal: str | None = None
    updated_at: datetime = Field(default_factory=_utcnow)


class SourceFetchLog(SQLModel, table=True):
    """Per-URL fetch dedup for source monitors (Rule Discovery Agent · E3).

    A row exists for every URL ever pulled into the proposed-signals queue
    (one row per (monitor_name, item_url)). The unique constraint on
    ``item_url`` keeps a single source item from being re-drafted on every
    cron tick. ``proposed_signal_id`` is nullable so we can also record fetch
    attempts that failed before producing a draft (LLM error, budget gone).
    """

    id: int | None = Field(default=None, primary_key=True)
    monitor_name: str = Field(index=True)
    item_url: str = Field(unique=True, index=True)
    fetched_at: datetime = Field(default_factory=_utcnow)
    proposed_signal_id: int | None = Field(default=None, index=True)


class MCPServerBaseline(SQLModel, table=True):
    """Per-machine MCP server baseline for rug-pull detection.

    One row per (machine_id, mcp_name). Unique constraint installed via
    DDL in :func:`ccguard.server.db.session.init_db` (mirrors the
    Phase 2 ``machinebaseline`` pattern — keeps ``create_all`` idempotent
    against pre-existing tables).

    Hashes are optional so the table can be populated from v0.1 agents that
    don't yet send ``description_hash`` / ``definition_hash`` — the detection
    code then skips diffing for that row until the agent upgrades.

    ``description_preview`` is the first 200 chars of the description for UI
    diffing (we don't store the whole thing — could be long, and privacy is
    not a concern here since the description is meant to be read by the LLM).
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    mcp_name: str = Field(index=True)
    transport: str
    description_hash: str | None = None
    definition_hash: str | None = None
    description_preview: str | None = None
    # Raw (secret-masked) definition text — ``command args | url`` — stored so a
    # later diff can classify the CHANGE semantically (version bump vs binary
    # swap), not just note that the hash moved. Without it the anti-false-positive
    # classifier has only the new side. Nullable/back-compat: pre-feature rows and
    # v0.1 agents leave it None and the classifier falls back to "opaque change".
    definition_preview: str | None = None
    # P4b: hash of the runtime tool list (tools/list). Optional/back-compat:
    # old agents send None and the tools-drift diff is skipped for that row.
    tools_hash: str | None = None
    first_seen_at: datetime = Field(default_factory=_utcnow)
    last_seen_at: datetime = Field(default_factory=_utcnow)
    # Fleet review state (проверено/не проверено): every MCP starts unreviewed,
    # mirroring the Hook/Skill/AgentBaseline pending->active pattern. Unlike
    # those three, MCP has no missing/removed state -- disappearance stays
    # silent for v0.2 (see module docstring in mcp_baseline_service).
    status: str = Field(default="pending")  # pending | active
    accepted_at: datetime | None = None
    accepted_by: str | None = None
    # Provenance ("откуда этот MCP взялся") — denormalized from McpServerEntry,
    # same source-tracking shape SkillBaseline/AgentBaseline already carry.
    #   scope:  managed = раскатано организацией | user = поставил себе сам |
    #           project = лежит в репозитории | project_local = локально в проекте
    #   origin: local | plugin (+ parent_plugin / source_marketplace when plugin)
    # All nullable: a v0.1/v0.2 agent doesn't send them, and the UI then says
    # "источник неизвестен" instead of guessing.
    scope: str | None = Field(default=None, index=True)
    origin: str = Field(default="local")
    parent_plugin: str | None = None
    source_marketplace: str | None = None
    # Config file the entry was declared in — the audit answer to "где именно
    # это прописано" when an admin needs to go and remove it.
    source_path: str | None = None


class HookBaseline(SQLModel, table=True):
    """TOFU baseline for Claude Code hooks per machine (feat/hooks-tofu-baseline).

    A row = one "slot" in settings.json (unique by machine + event + matcher +
    command). ``fingerprint`` = sha256(event_name + matcher + command_string +
    file_content_hash). Status transitions: pending → active (admin accept) →
    missing/removed. NOTE: ``accepted_drift`` is a RESERVED status — the design
    envisaged re-accept-after-drift stamping it, but ``accept_baseline`` today
    unconditionally sets ``active`` (the ``accepted_at``/``accepted_by`` stamps
    already carry the audit trail), so ``accepted_drift`` is never assigned. The
    ``status in ("active", "accepted_drift")`` checks in the baseline services
    keep it purely for forward-compat — if a future re-accept path starts
    emitting it, removal/tamper detection already handles it. Composite UNIQUE
    ``(machine_id, event_name, matcher, command_string)`` installed via DDL in
    :func:`ccguard.server.db.session.init_db`, mirroring the
    ``MCPServerBaseline`` pattern (keeps ``create_all`` idempotent against
    pre-existing tables).
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)

    event_name: str = Field(index=True)
    matcher: str = Field(default="")
    command_string: str

    file_path: str | None = None
    file_content_hash: str | None = None
    fingerprint: str = Field(index=True)

    # pending | active | missing | removed  (accepted_drift = reserved, never
    # assigned today — see class docstring)
    status: str = Field(default="pending")

    first_seen_at: datetime
    last_seen_at: datetime
    accepted_at: datetime | None = None
    accepted_by: str | None = None


class SkillBaseline(SQLModel, table=True):
    """TOFU baseline for Claude Code skills per machine
    (specs/2026-06-02-skills-agents-baseline-design.md).

    Slot identity = (machine_id, name, origin, parent_plugin).
    fingerprint = sha256(name | origin | parent_plugin | dir_hash).

    Status transitions mirror HookBaseline: pending → active (admin
    accept) → missing on silent removal. ``accepted_drift`` is reserved but
    never assigned today (see HookBaseline docstring).

    parent_plugin / source_marketplace are denormalized copies from the
    inventory payload so fleet aggregates ("which marketplace ships the
    most skills") are single-table GROUP BYs.
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)

    name: str = Field(index=True)
    origin: str = Field(default="local")  # local | plugin
    parent_plugin: str | None = Field(default=None, index=True)
    source_marketplace: str | None = Field(default=None, index=True)

    dir_hash: str
    has_referenced_scripts: bool = False
    path: str | None = None
    fingerprint: str = Field(index=True)

    status: str = Field(default="pending")
    first_seen_at: datetime
    last_seen_at: datetime
    accepted_at: datetime | None = None
    accepted_by: str | None = None


class AgentBaseline(SQLModel, table=True):
    """TOFU baseline for Claude Code custom subagents per machine.

    Slot identity = (machine_id, name, origin, parent_plugin).
    fingerprint = sha256(name | origin | parent_plugin | file_hash).

    ``tools_csv`` is denormalized (sorted, comma-joined) so we can
    compute "dangerous tools present" without parsing JSON every check.
    """

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)

    name: str = Field(index=True)
    origin: str = Field(default="local")
    parent_plugin: str | None = Field(default=None, index=True)
    source_marketplace: str | None = Field(default=None, index=True)

    file_hash: str
    tools_csv: str | None = None  # e.g. "Bash,Edit,Read" (sorted)
    model: str | None = None
    path: str | None = None
    fingerprint: str = Field(index=True)

    status: str = Field(default="pending")
    first_seen_at: datetime
    last_seen_at: datetime
    accepted_at: datetime | None = None
    accepted_by: str | None = None


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


class ThreatIndicator(SQLModel, table=True):
    """Reference catalog of detection INDICATORS (ТЗ-05).

    An *indicator* is a rule/feature used to look for threats ("the path
    ``~/.aws/credentials`` is sensitive") — an INPUT to detection. This is
    distinct from :class:`FindingRecord`, which records detection EVENTS
    (outputs). Do not conflate the two in one table.

    Designed for MANY sources from day one so Path-2 autocollection (Atomic /
    Gitleaks / CVE feeds — a future ТЗ) plugs in with NO schema change: it just
    inserts rows with a new ``source`` and ``status="pending"`` for admin
    review, mirroring :class:`ProposedSignal`. Seed rows load as ``active``.

    Composite UNIQUE ``(indicator_type, value, source)`` is installed via DDL in
    :func:`ccguard.server.db.session.init_db` (mirrors ``MCPServerBaseline``):
    the same value attested by two sources is two rows (cross-corroboration),
    but one source never duplicates it.

    NOTE (ТЗ-05 §0.2): existing indicators still live scattered in their current
    places (dangerous-bash in ``schemas/policy.py``, suspicious hosts in
    ``agent/bash_url_parser.py``, sensitive paths in ``signals/catalog.py``,
    safe caches in ``signals/extractor.py``). They are duplicated into the seed
    here but NOT yet removed — engines are wired to this store in a later ТЗ.
    """

    id: int | None = Field(default=None, primary_key=True)
    # Identity: what to look for and how to match it.
    indicator_type: str = Field(index=True)  # sensitive_path|dangerous_command|suspicious_host|safe_path
    value: str
    value_kind: str = "exact"  # exact|glob|regex|prefix
    # Provenance — the key to Path-2 multi-source collection.
    source: str  # os-standard|atomic-red-team|manual|gitleaks|llm-proposed|...
    source_ref: str | None = None  # technique id / atomic name / URL in the source
    # Classification — the seed of the ATLAS/ATT&CK coverage map.
    technique: str | None = Field(default=None, index=True)  # T#### / AML.T####
    tactic: str | None = None  # credential-access|exfiltration|...
    # Scoring & applicability.
    weight: float = 1.0
    platform_relevant: bool = True  # applies to an AI agent (filters Atomic noise)
    # Lifecycle — seed=active; Path-2 sends pending → admin approves → active.
    status: str = Field(default="active", index=True)  # active|pending|rejected|disabled
    enabled: bool = True  # consumers read only enabled+active
    # Metadata.
    description: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    reviewed_by: str | None = None  # who promoted pending → active (Path 2)
    reviewed_at: datetime | None = None
    # ТЗ-06: DEPRECATED — single-technique attribution superseded by the
    # many-to-many IndicatorTechniqueMapping. Kept (not dropped) so the ТЗ-05
    # seed loader keeps writing it and the migration can read it; source of
    # truth for attribution is now the junction table.


class Technique(SQLModel, table=True):
    """Catalog of threat techniques across THREE equal frameworks (ТЗ-08).

    One table with a ``framework`` discriminator — three *equal* projections,
    NOT a nesting:
      - ``atlas``  : MITRE ATLAS AI-specific ``AML.T*`` techniques.
      - ``attack`` : classic MITRE ATT&CK ``T*`` techniques our indicators hit.
      - ``owasp``  : OWASP Top 10 for Agentic Applications ``ASI01..ASI10`` —
                     the agentic layer where our correlation detectors map.
    Horizontal relationships between frameworks live in
    :class:`TechniqueCrosswalk` (``ASI04 ≈ AML.T0010 ≈ T1195``), never as
    parent/child here. Intra-framework hierarchy (technique → sub-technique,
    e.g. ``T1552 → T1552.001``) uses the self-referential ``parent_technique``.

    Renamed from ``AtlasTechnique`` (ТЗ-06) since it is no longer ATLAS-only; a
    deprecation alias is kept below for backward compatibility. Hybrid load like
    ThreatIndicator: a vetted seed (``data/techniques_seed.yaml``) loads
    idempotently at startup. Network autoload of the full corpora is Path-2
    (future ТЗ) — hence the ``source`` column.
    """

    __tablename__ = "technique"

    id: int | None = Field(default=None, primary_key=True)
    technique_id: str = Field(index=True)  # "AML.T0051" / "T1552.001" / "ASI01"; UNIQUE via DDL
    framework: str = Field(index=True)  # atlas | attack | owasp
    name: str
    tactic: str = Field(index=True)  # credential-access | exfiltration | ...
    description: str | None = None
    parent_technique: str | None = None  # parent technique_id; NULL at top level
    url: str | None = None
    # ТЗ-06 fix: False for techniques an endpoint EDR structurally cannot cover
    # (model-internal: training-data poisoning, adversarial examples, model
    # access, inference-API exfil, jailbreak). Out-of-scope techniques are
    # excluded from coverage gaps so the map shows honest gaps, not noise.
    in_scope: bool = True
    source: str = "techniques-seed"
    # ТЗ-09: distinguishes ORDERED kill-chain stages (attack/atlas — a real
    # tactic axis the chain engine correlates over) from OWASP ASI's UNORDERED
    # risk classes (mapped to a nearest stage only for UI bucketing). Set to
    # "risk-layer" for owasp, "kill-chain" otherwise (derived in the loader).
    tactic_source: str = "kill-chain"  # kill-chain | risk-layer
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


# Deprecated alias (ТЗ-08): the class was ``AtlasTechnique`` through ТЗ-06. Kept
# so existing imports / ТЗ-05/06 regression keep resolving. New code uses
# ``Technique``.
AtlasTechnique = Technique


class IndicatorTechniqueMapping(SQLModel, table=True):
    """Junction table: ThreatIndicator ↔ AtlasTechnique (many-to-many, ТЗ-06).

    One indicator (e.g. reading ``~/.aws/credentials``) is relevant to several
    techniques (T1552 Unsecured Credentials AND T1005 Data from Local System) —
    hence the link lives here, not as a scalar on the indicator. Composite
    UNIQUE ``(indicator_id, technique_id)`` via DDL prevents double-linking.

    ``mapping_source`` records who linked it: ``seed`` (vetted), ``manual``,
    ``auto`` (heuristic remap when a new technique arrives — lower
    ``confidence``, distinguishable for review). Indexed both ways since queries
    run in both directions (a technique's indicators / an indicator's techniques).
    """

    id: int | None = Field(default=None, primary_key=True)
    indicator_id: int = Field(index=True)  # FK → ThreatIndicator.id
    technique_id: str = Field(index=True)  # FK → Technique.technique_id
    mapping_source: str = "seed"  # seed | manual | auto
    confidence: float = 1.0
    # ТЗ-08: how this detection protects (OWASP rationale taxonomy). An
    # indicator is an artefact path/command → it usually SCOPEs (limits access)
    # or PREVents reach to the artefact. Additive column (ALTER in init_db).
    control_type: str = "SCOPE"  # PREV | DETECT | SCOPE | GATE | ISOLATE | ...
    created_at: datetime = Field(default_factory=_utcnow)
    created_by: str | None = None


class TechniqueCrosswalk(SQLModel, table=True):
    """Horizontal links BETWEEN frameworks (ТЗ-08).

    The three frameworks are equal projections of the same threat space, so the
    same threat appears as ``ASI04`` (OWASP) ≈ ``AML.T0010`` (ATLAS) ≈ ``T1195``
    (ATT&CK). This is a many-to-many *sibling* relation, NOT the parent/child
    nesting of :attr:`Technique.parent_technique`. Stored once (a→b); queries
    look in both directions. Composite UNIQUE ``(technique_id_a, technique_id_b)``
    via DDL.
    """

    id: int | None = Field(default=None, primary_key=True)
    technique_id_a: str = Field(index=True)  # FK → Technique.technique_id
    technique_id_b: str = Field(index=True)  # FK → Technique.technique_id
    relation: str = "crosswalk"  # the "≈" sibling relation
    source: str = "owasp-crosswalk"  # owasp-crosswalk | manual
    created_at: datetime = Field(default_factory=_utcnow)


class Detector(SQLModel, table=True):
    """Registry of EXISTING correlation detectors (ТЗ-08).

    The behavioral detectors already live in code (``sequence_service``,
    ``hook_baseline_service``/TOFU, ``sensor_health_service``/heartbeat). This
    table does NOT implement detection — it gives each existing detector a
    stable ``detector_key`` so the coverage map can bind it to techniques. The
    detector code is NOT touched; the emitted finding ``rule_id``\\s are recorded
    here for traceability only.
    """

    id: int | None = Field(default=None, primary_key=True)
    detector_key: str = Field(index=True)  # staging_chain | exfil_sequence | ...; UNIQUE via DDL
    name: str
    kind: str = "correlation"  # correlation (room for other kinds later)
    description: str | None = None
    # The literal finding rule_id(s) this detector emits, for traceability
    # (comma-joined). Documentation only — coverage binds via detector_key.
    rule_ids: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class DetectorTechniqueMapping(SQLModel, table=True):
    """Junction: Detector ↔ Technique (ТЗ-08) — the fix for the coverage paradox.

    Correlation detectors are NOT indicators, so before ТЗ-08 the map could not
    see them and AML.T0051 (IPI), detected behaviorally, showed as a hole. This
    junction makes a technique *covered* when a detector binds to it, exactly as
    an indicator does. Composite UNIQUE ``(detector_key, technique_id)`` via DDL.
    """

    id: int | None = Field(default=None, primary_key=True)
    detector_key: str = Field(index=True)  # FK → Detector.detector_key
    technique_id: str = Field(index=True)  # FK → Technique.technique_id
    framework: str = Field(index=True)  # duplicated for convenient queries
    control_type: str = "DETECT"  # correlations DETECT (vs indicator SCOPE/PREV)
    relevance: str = "primary"  # primary | secondary
    confidence: float = 1.0
    mapping_source: str = "seed"
    created_at: datetime = Field(default_factory=_utcnow)


class ChainScenario(SQLModel, table=True):
    """A kill-chain scenario as DATA (ТЗ-09).

    A scenario is an ordered (or unordered) sequence of STAGES — not channels or
    concrete techniques. The universal :mod:`chain_engine` executor reads any
    scenario from this table and raises a finding when the stage sequence
    completes within ``window_seconds`` inside one correlation session. Adding a
    new attack scenario is a row here (data), NOT code; adding a new exfil
    channel is a new indicator under the exfiltration stage — the scenario is
    untouched. Loaded idempotently from ``data/chain_scenarios_seed.yaml``.
    """

    id: int | None = Field(default=None, primary_key=True)
    scenario_key: str = Field(index=True)  # "recon_to_exfil"; UNIQUE via DDL
    name: str
    description: str | None = None
    window_seconds: int = 300  # all steps must complete within this span
    severity: str = "high"  # finding severity when the chain completes
    enabled: bool = True
    require_order: bool = True  # steps strictly in order (True) or any order (False)
    source: str = "seed"
    created_at: datetime = Field(default_factory=_utcnow)


class ChainStep(SQLModel, table=True):
    """One step of a :class:`ChainScenario` — references a STAGE, not a technique.

    ``tactic`` is the kill-chain stage (from the ТЗ-08 taxonomy:
    exfiltration / credential-access / initial-access ...). The engine matches
    "any event whose derived stage == this step's tactic" — so the step fires on
    T1567 OR T1048 OR AML.T0024 (different techniques, one exfiltration stage).
    Composite UNIQUE ``(scenario_key, step_index)`` via DDL.
    """

    id: int | None = Field(default=None, primary_key=True)
    scenario_key: str = Field(index=True)  # FK → ChainScenario.scenario_key
    step_index: int  # order within the scenario (0,1,2,...)
    tactic: str = Field(index=True)  # STAGE, NOT a technique
    optional: bool = False  # absence does not break the chain
    description: str | None = None


class ChainMatch(SQLModel, table=True):
    """Trace of a fired scenario (ТЗ-09) — which real techniques/signals matched.

    Persisted alongside the FindingRecord for auditability: ``matched_steps`` is
    the JSON list of {step_index, tactic, signal, ts} that actually satisfied the
    chain, so an analyst can see WHICH channels filled each stage this time.
    """

    id: int | None = Field(default=None, primary_key=True)
    scenario_key: str = Field(index=True)
    machine_id: str = Field(index=True)
    session_id: str | None = Field(default=None, index=True)
    matched_at: datetime = Field(default_factory=_utcnow)
    finding_id: int | None = Field(default=None, index=True)
    matched_steps_json: str = "[]"  # JSON: [{step_index, tactic, signal, ts}, ...]
