"""Инициализация БД и сессии."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

# Composite indexes for ToolUseEvent (TUA-02). Defined here — not as SQLModel
# Index() — because we want explicit DESC ordering on the timestamp column and
# we want idempotent ``CREATE INDEX IF NOT EXISTS`` semantics so ``init_db`` is
# safe to call repeatedly (test fixtures, server lifespan, etc.).
_TOOL_USE_INDEX_DDL: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS ix_tooluseevent_machine_ts  "
    "ON tooluseevent(machine_id, ts DESC)",
    "CREATE INDEX IF NOT EXISTS ix_tooluseevent_tool_ts     "
    "ON tooluseevent(tool_name, ts DESC)",
    "CREATE INDEX IF NOT EXISTS ix_tooluseevent_decision_ts "
    "ON tooluseevent(decision, ts DESC)",
)

# Composite unique index for MachineBaseline (Plan 02-01). SQLModel auto-names
# tables as the lowercased class name without underscores — match the existing
# Phase 1 convention (``tooluseevent``), so the target table is
# ``machinebaseline``. Idempotent so ``init_db`` stays safe to re-run.
_MACHINE_BASELINE_INDEX_DDL: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_machinebaseline_machine_metric "
    "ON machinebaseline(machine_id, metric)",
)

# Composite indexes for Plan 03-01 LLM-scanner foundations. Same idempotent
# ``IF NOT EXISTS`` pattern as TUA-02.
#   ix_llmcalllog_ts_model — accelerates the daily-budget aggregate
#                            ``SELECT count(*) WHERE ts >= ? GROUP BY model``.
#   ix_scanresult_scanned_at_desc — accelerates the admin "last 10 scans"
#                            view (ORDER BY scanned_at DESC LIMIT 10).
_LLM_SCANNER_INDEX_DDL: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS ix_llmcalllog_ts_model "
    "ON llmcalllog(ts, model)",
    "CREATE INDEX IF NOT EXISTS ix_scanresult_scanned_at_desc "
    "ON scanresult(scanned_at DESC)",
)

# Composite unique index for MCPServerBaseline (feat/mcp-rug-pull). Same
# idempotent pattern as MachineBaseline — one baseline row per
# (machine_id, mcp_name).
_MCP_BASELINE_INDEX_DDL: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_mcpserverbaseline_machine_name "
    "ON mcpserverbaseline(machine_id, mcp_name)",
)

# Composite unique index for HookBaseline (feat/hooks-tofu-baseline). One row
# per "slot" — (machine_id, event_name, matcher, command_string). Same
# idempotent IF NOT EXISTS pattern as the other baseline tables.
_HOOK_BASELINE_INDEX_DDL: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_hookbaseline_slot "
    "ON hookbaseline(machine_id, event_name, matcher, command_string)",
)

# Composite unique indexes for SkillBaseline / AgentBaseline (specs/2026-06-02-
# skills-agents-baseline-design.md). Slot = (machine, name, origin,
# parent_plugin). COALESCE makes SQLite treat NULL parent_plugin as the
# literal "" so local entries (parent_plugin=NULL) don't all collide with
# each other.
_SKILL_AGENT_BASELINE_INDEX_DDL: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_skillbaseline_slot "
    "ON skillbaseline(machine_id, name, origin, COALESCE(parent_plugin, ''))",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_agentbaseline_slot "
    "ON agentbaseline(machine_id, name, origin, COALESCE(parent_plugin, ''))",
)

# Additive columns for ScanResult (feat/skills-detailed-rationale).
# ``create_all`` is a no-op on existing tables, so these explicit ALTERs make
# the new columns appear on pre-feature DBs. SQLite's ``ADD COLUMN`` is the
# only schema mutation it accepts cleanly, and there is no ``IF NOT EXISTS``
# clause — so we introspect ``PRAGMA table_info`` and skip if already there
# (idempotent / safe to re-run on fresh DBs where ``create_all`` already added
# the column).
_SCAN_RESULT_RATIONALE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("explanation", "ALTER TABLE scanresult ADD COLUMN explanation TEXT"),
    ("quoted_snippet", "ALTER TABLE scanresult ADD COLUMN quoted_snippet TEXT"),
)

# Additive column for ToolUseEvent (ТЗ-01: session-scoped correlation). Same
# PRAGMA-guarded ADD COLUMN pattern as the ScanResult rationale columns —
# ``create_all`` is a no-op on existing tables, so pre-feature DBs need this
# explicit ALTER to gain ``session_id``. The matching index is created
# separately below via CREATE INDEX IF NOT EXISTS (create_all only emits the
# model's ``index=True`` index on a freshly-created table).
_TOOL_USE_SESSION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("session_id", "ALTER TABLE tooluseevent ADD COLUMN session_id TEXT"),
)
_TOOL_USE_SESSION_INDEX_DDL: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS ix_tooluseevent_session_id "
    "ON tooluseevent(session_id)",
)


def make_engine(db_url: str) -> Engine:
    """Создать engine. Для SQLite — включить WAL и foreign_keys."""
    engine = create_engine(db_url, echo=False, connect_args={"check_same_thread": False})

    if db_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _record) -> None:  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.close()

    return engine


def init_db(engine: Engine) -> None:
    # Import models so SQLModel.metadata sees every table_=True class before
    # create_all. Phase 1+2 relied on call-site imports (test files / API
    # routers) to trigger registration; Plan 03-01 adds ScanResult / LLMCallLog
    # / SettingsRecord which may not be imported on every call path. An
    # explicit import here is the safe, idempotent fix.
    from ccguard.server.db import models  # noqa: F401  (side-effect import)

    SQLModel.metadata.create_all(engine)
    # Composite indexes for ToolUseEvent (TUA-02) and MachineBaseline (02-01).
    # Idempotent — safe to re-run.
    with engine.begin() as conn:
        for ddl in _TOOL_USE_INDEX_DDL:
            conn.execute(text(ddl))
        for ddl in _MACHINE_BASELINE_INDEX_DDL:
            conn.execute(text(ddl))
        for ddl in _LLM_SCANNER_INDEX_DDL:
            conn.execute(text(ddl))
        for ddl in _MCP_BASELINE_INDEX_DDL:
            conn.execute(text(ddl))
        for ddl in _HOOK_BASELINE_INDEX_DDL:
            conn.execute(text(ddl))
        for ddl in _SKILL_AGENT_BASELINE_INDEX_DDL:
            conn.execute(text(ddl))
        # Additive ALTERs for ScanResult. SQLite lacks IF NOT EXISTS on
        # ADD COLUMN — introspect via PRAGMA and skip when already present.
        existing_cols = {
            row[1] for row in conn.execute(text("PRAGMA table_info(scanresult)"))
        }
        for col_name, ddl in _SCAN_RESULT_RATIONALE_COLUMNS:
            if col_name not in existing_cols:
                conn.execute(text(ddl))
        # Additive ALTER for ToolUseEvent.session_id (ТЗ-01) + its index.
        tooluse_cols = {
            row[1] for row in conn.execute(text("PRAGMA table_info(tooluseevent)"))
        }
        for col_name, ddl in _TOOL_USE_SESSION_COLUMNS:
            if col_name not in tooluse_cols:
                conn.execute(text(ddl))
        for ddl in _TOOL_USE_SESSION_INDEX_DDL:
            conn.execute(text(ddl))


def session_factory(engine: Engine) -> Iterator[Session]:
    """Dependency для FastAPI."""
    with Session(engine) as session:
        yield session
