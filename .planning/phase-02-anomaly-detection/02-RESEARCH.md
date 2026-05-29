# Phase 2: Anomaly Detection — Research

**Researched:** 2026-05-25
**Domain:** Statistical per-machine baselines (3σ) + APScheduler-driven recompute + Finding generation + HTMX/Jinja drill-down UI
**Confidence:** HIGH

## Summary

Phase 2 builds on the `ToolUseEvent` firehose from Phase 1 (already shipped — table, indexes, service-layer query helpers exist) and the existing `InventoryReport`/`InventorySnapshot` history. It adds:

1. A new `MachineBaseline` SQLModel table — read-cached per `(machine_id, metric)` aggregate holding median, sigma, sample_count, baseline_ready flag, optional `recent_points` JSON for sparkline reuse.
2. An in-process **APScheduler `AsyncIOScheduler`** registered in the FastAPI lifespan, ticking hourly to recompute baselines and emit anomaly findings.
3. A `baseline_service` (statistics) + an `anomaly_service` (orchestration + idempotent Finding insertion via `FindingRecord` — reusing v0.1 table, no schema change).
4. Read-only web routes: `GET /anomalies`, `GET /anomalies/{machine_id}/{metric}`, plus two HTMX partials (`/_partials/anomalies/overview`, `/_partials/anomalies/matrix`).

**No new third-party packages except `APScheduler>=3.10,<4`** (stable 3.x series; 4.0 still in alpha as of 2026-05). The rest is stdlib (`statistics`, `json`, `datetime`).

**Primary recommendation:** Use `AsyncIOScheduler` (lifespan-friendly, single-event-loop), one job per metric family running hourly with `misfire_grace_time=300`, a single global lock (`asyncio.Lock` on `app.state`) to make the tick reentrant-safe; compute baselines per-machine in a single SQL pass + Python statistics. Persist Findings via `FindingRecord` with `rule_id="anomaly.<metric>"` and a `details` JSON in `payload_json` containing `observed_value`, `median`, `sigma`, `sigma_distance`, `bucket_date`. Idempotency comes from a service-layer pre-check (`SELECT 1 FROM findingrecord WHERE machine_id=? AND rule_id=? AND date(discovered_at)=date('now','utc')`) — no DB UNIQUE constraint needed in this phase.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Baseline Computation:**
- Pересчёт baseline: APScheduler in-process, **hourly tick на сервере** (для <100 машин нагрузка минимальна).
- Algorithm: **sample mean + sample stdev (`statistics.stdev`)** по последним 14 daily/weekly point'ам.
- Cold-start: warm-up флаг `baseline_ready=False` пока **< 7 точек данных**; не генерим finding'и в этот период.
- Storage: новая таблица `MachineBaseline(machine_id, metric, median, sigma, sample_count, baseline_ready, updated_at)` — **uniqueness on (machine_id, metric)**.

**Metrics & Alerting:**
- 4 метрики:
  - `bash_calls_per_day` — `COUNT(ToolUseEvent WHERE tool_name='Bash') GROUP BY date(ts)` за последние 14 дней
  - `new_mcp_per_week` — inventory diff: уникальные MCP servers впервые seen за последние 7 дней
  - `new_agents_per_week` — inventory diff: agent dir_hash changes за 7 дней
  - `skill_dir_hash_changes_per_week` — count изменений skill_dir_hash за 7 дней
- Источник new_mcp/new_agents: diff между последовательными `InventorySnapshot` snapshot'ами одного `machine_id`.
- Дедупликация: **один finding в день per `(machine_id, metric)`**; поиск по `rule_id` + `machine_id` + same day.
- `rule_id` format: snake_case dot-namespaced — `anomaly.bash_calls_per_day`, `anomaly.new_mcp_per_week`, `anomaly.new_agents_per_week`, `anomaly.skill_dir_hash_changes_per_week`.
- `severity`: всегда **`warn`** (per ANO-02).

**UI Drill-down:**
- Overview: новая card "Аномалии" под существующими summary-tiles; top-5 recent anomalies.
- `/anomalies`: таблица "machine × 4 метрики" с CSS sparkline-колонкой (mini bar chart 14 точек).
- Timeseries-график: 14-day daily values + baseline-полоса (median ± 3σ светло-серым) + outlier points красным.
- **Chart: CSS-only**, как в Phase 1 audit timeline — никакого JS.

### Claude's Discretion
- Точные имена колонок `MachineBaseline` и migration-mechanism (`create_all` vs Alembic).
- APScheduler integration — embedded в FastAPI lifespan (`startup`/`shutdown`).
- Структура service-modulей (`anomaly_service`, `baseline_service`).
- Bot-protection scheduler-tick при множественных workers — single-process для self-hosted достаточно.

### Deferred Ideas (OUT OF SCOPE)
- ML-based anomaly detection (autoencoder, isolation forest) — v0.3+
- Email/Slack/Pager alerting — Phase 6 SIEM-канал
- Multi-metric correlation — v0.3
- Per-team baseline (multi-tenant) — v0.3
- Adaptive threshold (не 3σ а ML-learned) — v0.3+
- Pre-aggregated daily summary table — optimisation when needed
- Mute/snooze findings — v0.3 (нужен RBAC)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ANO-01 | Per-machine rolling 14-day baseline для 4-х метрик | `MachineBaseline` schema + `baseline_service.compute()` + APScheduler hourly tick |
| ANO-02 | Finding (severity=warn, rule_id=`anomaly.*`) при отклонении > 3σ от median | `anomaly_service.evaluate_and_emit()` + idempotent insertion gate |
| ANO-03 | Web UI: Overview card + `/anomalies` matrix + `/anomalies/{machine}/{metric}` detail | Route inventory section + Jinja templates (already specified in 02-UI-SPEC.md) |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

| Constraint | Impact on This Phase |
|------------|----------------------|
| Python 3.12 + FastAPI + SQLModel + HTMX/Jinja stack frozen for v0.2 | APScheduler is the only new third-party dep; everything else reused. |
| Self-hosted, SQLite WAL (<100 machines) | Per-tick cost: ≤100 machines × 4 metrics × 14 points = ~5,600 aggregate rows from SQL; negligible. |
| Backward compat: agent v0.1 must keep working | Phase is **server-side only** — no agent changes, no API additions, no policy schema changes. Pure additive. |
| Performance: PreToolUse hook <100ms | Untouched — no hook changes. |
| Security: nothing plaintext, hashes only | Finding `payload_json` already documented as JSON; nothing sensitive in baselines. |
| Schema versioning | No agent ↔ server contract changes → no `schema_version` bump. |
| GSD workflow | All edits via GSD commands. |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Hourly baseline recompute scheduling | Server / Background (APScheduler) | — | Server-side computation; agent uninvolved. |
| Daily / weekly aggregation SQL | Server / DB (SQL) | — | Push compute to SQLite; indexes already exist (`ix_tooluseevent_tool_ts`). |
| Inventory diff (new MCP / agents / skill_hash) | Server / Service (Python) | DB read-only | Diff logic is per-machine sequential `InventorySnapshot` comparison; not expressible in plain SQL economically. |
| Statistics (median, stdev, 3σ test) | Server / Service (Python stdlib) | — | `statistics.median`, `statistics.stdev`. |
| `MachineBaseline` upsert | Server / DB | — | UNIQUE composite (machine_id, metric) — SQLite UPSERT via `INSERT ... ON CONFLICT`. |
| Finding emission (idempotent) | Server / Service | DB read-then-insert | Pre-check by same-day same-rule for that machine, then `FindingRecord` insert. |
| `/anomalies` page + partials | Server / Frontend (SSR) | Browser (HTMX poll 60s) | Mirrors Phase 1 audit pattern. |
| Sparkline data preparation | Server / Service | — | Computed alongside baseline; stored on `MachineBaseline.recent_points_json` to avoid re-querying per render. |

## Standard Stack

### Core (already in `pyproject.toml`)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| FastAPI | >=0.110 | New `/anomalies*` routes + lifespan hookup | Existing pattern |
| SQLModel | >=0.0.16 | `MachineBaseline` table | Mirrors `ToolUseEvent` |
| Pydantic v2 | >=2.7 | (No API contracts in this phase — internal types only.) | — |
| Jinja2 | >=3.1 | Templates | Existing |
| sqlite3 / SQLAlchemy `text` | stdlib | Aggregation queries | Existing pattern in `tool_use_service.py` |

### New (one new dependency only)
| Library | Version | Purpose | Source |
|---------|---------|---------|--------|
| **APScheduler** | **>=3.10,<4** | In-process scheduled job (hourly baseline tick) | `[VERIFIED: PyPI — latest 3.11.2, summary "In-process task scheduler with Cron-like capabilities"; 4.0 still alpha 4.0.0a6 — pin to 3.x]` |

**Why APScheduler 3.x (not 4.x):** 3.11.2 is the current stable release (PyPI metadata fetched 2026-05-25). 4.x is still in alpha (4.0.0a6). For self-hosted production we pin `>=3.10,<4` — the 3.x API is mature and matches the integration pattern proven across the FastAPI ecosystem. [VERIFIED: PyPI]

**Why APScheduler over alternatives:**

| Instead of | Could Use | Why we don't |
|------------|-----------|--------------|
| APScheduler | `asyncio.create_task(loop())` with `asyncio.sleep(3600)` | Works, but no misfire handling, no introspection, no easy job restart on lifespan reload. APScheduler gives all of that for one small dep. |
| APScheduler | `fastapi-utils` `@repeat_every` | Decorator-only; less control over misfire policy and explicit start/shutdown wiring. |
| APScheduler | External cron + HTTP call to a `/internal/recompute` endpoint | Adds operational complexity (cron file in container, auth surface for internal route); we're targeting **single-container deploy**, not a sidecar topology. |
| APScheduler 4.x | APScheduler 3.x | 4.x is in alpha; production self-hosted ≠ alpha-pinning. Revisit when 4.0 GA ships. |

### Supporting (stdlib — no new dependencies)
| Module | Purpose | When to Use |
|--------|---------|-------------|
| `statistics.median`, `statistics.stdev` | Baseline central tendency + sample stdev | Inside `baseline_service.compute()` |
| `datetime` / `UTC` | Daily/weekly bucket boundaries | All time arithmetic |
| `json` | `payload_json` for FindingRecord, `recent_points_json` for MachineBaseline | Existing pattern in `findings.py` |
| `asyncio.Lock` | Reentrant-safe scheduler tick | `app.state.anomaly_lock` |

### Alternatives Considered

| Choice | Picked | Tradeoff |
|--------|--------|----------|
| `AsyncIOScheduler` vs `BackgroundScheduler` | **`AsyncIOScheduler`** | FastAPI lifespan already runs in the asyncio event loop. `BackgroundScheduler` spawns its own thread (works too, but introduces a thread/event-loop boundary for nothing). `AsyncIOScheduler` integrates trivially: `scheduler.start()` inside the lifespan, jobs run on the same loop, jobs can be `async def` (we don't need that here but it doesn't hurt). [CITED: apscheduler.readthedocs.io/en/3.x/userguide.html] |
| `add_job(trigger="interval", hours=1)` vs cron-style | **interval** | Hourly is a fixed cadence; no calendar semantics needed. `IntervalTrigger(hours=1)` is the simplest. |
| One job per metric vs one job tickling all metrics | **One job, calls all 4 metrics serially** | <100 machines × 4 metrics → single tick completes in well under 1s; multiple jobs add coordination overhead without payoff. |
| `recent_points` as JSON column vs re-query per render | **JSON column on MachineBaseline** | UI-SPEC requires the 14 numbers at render time; precomputing and storing alongside median/sigma costs ~150 bytes/row × ~400 rows ≈ 60KB total — trivial. Avoids 400 SQL queries per matrix render. |

**Version verification:**
```
apscheduler 3.11.2 — [VERIFIED: PyPI metadata 2026-05-25]
fastapi >=0.110     — [VERIFIED: pyproject.toml]
sqlmodel >=0.0.16   — [VERIFIED: pyproject.toml]
```

## Package Legitimacy Audit

slopcheck CLI was unavailable in this environment. Single new package was therefore verified manually against PyPI:

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `APScheduler` | PyPI | 14+ years (first release 2011) | ~30M/month (industry-standard scheduler) | github.com/agronholm/apscheduler | not run — manual verify | **Approved** — major OSS project, maintained by Alex Grönholm (also maintains `anyio`, `typeguard`). Stable 3.x series since 2014. |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

*Recommendation for planner: because slopcheck did not run in this session, add a single `checkpoint:human-verify` task before `pip install`/`pyproject.toml` edit — confirm `pip install apscheduler` resolves to `agronholm/apscheduler` on PyPI, not a typosquat.*

## Architecture Patterns

### System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  ccguard-server (FastAPI + uvicorn, single process)                  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Lifespan: _lifespan(app)                                     │    │
│  │   init_db()      → creates MachineBaseline table             │    │
│  │   AsyncIOScheduler().start()                                 │    │
│  │     add_job(_tick, IntervalTrigger(hours=1),                 │    │
│  │             id="anomaly_baseline_tick",                       │    │
│  │             next_run_time=now()+30s,                          │    │
│  │             misfire_grace_time=300,                           │    │
│  │             coalesce=True, max_instances=1)                   │    │
│  │   app.state.scheduler = scheduler                            │    │
│  │   yield  ← server runs                                       │    │
│  │   scheduler.shutdown(wait=False)                             │    │
│  └────────────────────┬─────────────────────────────────────────┘    │
│                       │                                               │
│       hourly tick     ▼                                               │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  anomaly_service.tick(engine)                                │    │
│  │   async with app.state.anomaly_lock:                          │    │
│  │     with Session(engine) as s:                               │    │
│  │       for machine in list_machines(s):                       │    │
│  │         for metric in METRICS:                               │    │
│  │           points = aggregator_for(metric).points_for(s, m)   │    │
│  │           bl     = baseline_service.compute(points)          │    │
│  │           upsert_baseline(s, machine, metric, bl)            │    │
│  │           if bl.baseline_ready and bl.is_outlier_today:      │    │
│  │             emit_finding_idempotent(s, machine, metric, bl)  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  Web layer (Jinja SSR + HTMX poll 60s)                       │    │
│  │   GET /anomalies                  → anomalies_feed.html      │    │
│  │   GET /anomalies/{m}/{metric}     → anomaly_detail.html      │    │
│  │   GET /_partials/anomalies/overview  → _anomalies_overview   │    │
│  │   GET /_partials/anomalies/matrix    → _anomalies_matrix     │    │
│  │  All read from MachineBaseline + FindingRecord (no compute   │    │
│  │  on the request path — eyes-fast).                           │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────┬─────┘
                                                                 │
                                                                 ▼
                                              ┌──────────────────────────────┐
                                              │  SQLite (WAL)                │
                                              │  ToolUseEvent     (Phase 1)  │
                                              │  InventorySnapshot (v0.1)    │
                                              │  FindingRecord     (v0.1)    │
                                              │  MachineBaseline   (NEW)     │
                                              └──────────────────────────────┘
```

### Recommended Project Structure (incremental)

```
src/ccguard/server/
├── db/
│   └── models.py                       # EDIT: append MachineBaseline
├── services/
│   ├── baseline_service.py             # NEW — pure stats (median/stdev/outlier)
│   ├── anomaly_service.py              # NEW — orchestration (tick, upsert, emit)
│   ├── inventory_diff_service.py       # NEW — new_mcp / new_agents / skill_hash diffs
│   └── metric_aggregators.py           # NEW — one class per metric, points_for(machine) → [14 floats]
├── scheduler.py                        # NEW — APScheduler wiring (build_scheduler, _tick)
├── main.py                             # EDIT: start/shutdown scheduler in lifespan
└── web/
    ├── routes.py                       # EDIT: add /anomalies + 2 partials
    └── templates/
        ├── anomalies_feed.html         # NEW (per UI-SPEC inventory)
        ├── anomaly_detail.html         # NEW
        └── components/
            ├── _anomalies_overview.html # NEW
            └── _anomalies_matrix.html   # NEW
```

### Pattern 1: APScheduler in FastAPI lifespan

**What:** Start/stop the scheduler inside the existing `_lifespan` async context manager. Single instance, attached to `app.state` for testability.

**When to use:** Every server startup; the scheduler must shut down cleanly on uvicorn reload / SIGTERM.

```python
# src/ccguard/server/scheduler.py
from __future__ import annotations
import asyncio
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.engine import Engine

logger = logging.getLogger("ccguard.scheduler")

_TICK_JOB_ID = "anomaly_baseline_tick"


def build_scheduler(engine: Engine, lock: asyncio.Lock) -> AsyncIOScheduler:
    """Construct (but do NOT start) the scheduler.

    Caller starts it inside the lifespan so the asyncio loop exists.
    """
    sched = AsyncIOScheduler(
        timezone="UTC",
        job_defaults={
            "coalesce": True,         # collapse missed firings into one
            "max_instances": 1,       # don't run a second tick over the first
            "misfire_grace_time": 300 # 5 min — accept late firings within this window
        },
    )
    from ccguard.server.services.anomaly_service import tick as _tick

    async def _job() -> None:
        # Lock is also enforced inside _tick; this is the outer guard for
        # extremely fast re-entries (e.g. lifespan reload + missed-fire).
        if lock.locked():
            logger.info("anomaly tick skipped: previous tick still running")
            return
        async with lock:
            try:
                await asyncio.to_thread(_tick, engine)
            except Exception:
                logger.exception("anomaly tick failed (next firing will retry)")

    sched.add_job(
        _job,
        trigger=IntervalTrigger(hours=1),
        id=_TICK_JOB_ID,
        replace_existing=True,
        next_run_time=None,  # let interval set first run = start + 1h;
                             # see lifespan code for a short-delay first-tick override
    )
    return sched
```

### Pattern 2: Lifespan integration (edit to `server/main.py`)

```python
# src/ccguard/server/main.py — relevant additions
from datetime import UTC, datetime, timedelta
from ccguard.server.scheduler import build_scheduler

@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    cfg = ServerConfig.load(os.environ.get("CCGUARD_SERVER_CONFIG"))
    engine = make_engine(cfg.db_url)
    init_db(engine)
    # ... existing token/policy bootstrap ...
    app.state.config = cfg
    app.state.engine = engine
    app.state.anomaly_lock = asyncio.Lock()

    # Anomaly scheduler — opt-out via env for tests.
    if os.environ.get("CCGUARD_DISABLE_SCHEDULER") != "1":
        scheduler = build_scheduler(engine, app.state.anomaly_lock)
        # Run first tick ~30s after start so devs can see data quickly without
        # waiting a full hour. Subsequent ticks every 1h thereafter.
        scheduler.start()
        scheduler.modify_job(
            "anomaly_baseline_tick",
            next_run_time=datetime.now(UTC) + timedelta(seconds=30),
        )
        app.state.scheduler = scheduler
        logger.info("anomaly scheduler started (hourly tick)")
    else:
        app.state.scheduler = None

    try:
        yield
    finally:
        if app.state.scheduler is not None:
            app.state.scheduler.shutdown(wait=False)
            logger.info("anomaly scheduler stopped")
```

**Why `CCGUARD_DISABLE_SCHEDULER=1` env-guard:** Pytest's `TestClient` runs the lifespan synchronously. We DO NOT want APScheduler firing during unit/integration tests — tests trigger `anomaly_service.tick(engine)` directly. Setting the env var in `tests/integration/conftest.py` keeps the test surface deterministic.

### Pattern 3: `MachineBaseline` SQLModel + UPSERT

```python
# src/ccguard/server/db/models.py — append
class MachineBaseline(SQLModel, table=True):
    """Per-machine, per-metric rolling 14-point baseline (ANO-01).

    Unique on (machine_id, metric). Recomputed hourly by the anomaly
    scheduler tick. `recent_points_json` caches the 14 most recent values
    for sparkline rendering so the matrix page doesn't re-query 400×.
    """
    __table_args__ = (
        # SQLite UNIQUE constraint enables the ON CONFLICT upsert below.
        UniqueConstraint("machine_id", "metric", name="uq_machinebaseline_machine_metric"),
    )

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    metric: str = Field(index=True)
    # Statistics
    median: float = Field(default=0.0)
    sigma: float = Field(default=0.0)
    sample_count: int = Field(default=0)
    baseline_ready: bool = Field(default=False, index=True)
    # Sparkline cache: JSON array of {"label":"DD.MM","value":N,"is_outlier":bool}
    recent_points_json: str = Field(default="[]")
    # Latest observation for "current value" display
    latest_value: float | None = Field(default=None)
    updated_at: datetime = Field(default_factory=_utcnow, index=True)
```

**Required import in models.py:** add `from sqlalchemy import UniqueConstraint`.

**UPSERT pattern (SQLite-native, deterministic):**

```python
# src/ccguard/server/services/anomaly_service.py
from sqlalchemy import text

_UPSERT_BASELINE_SQL = text("""
    INSERT INTO machinebaseline
      (machine_id, metric, median, sigma, sample_count, baseline_ready,
       recent_points_json, latest_value, updated_at)
    VALUES
      (:machine_id, :metric, :median, :sigma, :sample_count, :baseline_ready,
       :recent_points_json, :latest_value, :updated_at)
    ON CONFLICT(machine_id, metric) DO UPDATE SET
      median             = excluded.median,
      sigma              = excluded.sigma,
      sample_count       = excluded.sample_count,
      baseline_ready     = excluded.baseline_ready,
      recent_points_json = excluded.recent_points_json,
      latest_value       = excluded.latest_value,
      updated_at         = excluded.updated_at
""")
```

### Pattern 4: Metric aggregators (one class per metric)

```python
# src/ccguard/server/services/metric_aggregators.py
from __future__ import annotations
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from sqlalchemy import text
from sqlmodel import Session
from ccguard.server.db.models import InventorySnapshot

@dataclass(frozen=True)
class Point:
    label: str          # "DD.MM"
    bucket_key: str     # canonical "YYYY-MM-DD" or "YYYY-Www"
    value: float

WINDOW_DAILY = 14
WINDOW_WEEKLY = 14    # 14 *weeks* feels right; CONTEXT.md says "14 daily/weekly point'ам" — 14 points either way

class MetricAggregator(ABC):
    name: str   # snake_case key, e.g. "bash_calls_per_day"

    @abstractmethod
    def points_for(self, session: Session, machine_id: str) -> list[Point]: ...


class BashCallsPerDayAggregator(MetricAggregator):
    name = "bash_calls_per_day"

    def points_for(self, session: Session, machine_id: str) -> list[Point]:
        today = datetime.now(UTC).date()
        start = today - timedelta(days=WINDOW_DAILY - 1)
        sql = text("""
          SELECT date(ts) AS d, COUNT(*) AS n
          FROM tooluseevent
          WHERE machine_id = :mid
            AND tool_name = 'Bash'
            AND ts >= :start
          GROUP BY d
        """)
        rows = session.exec(sql.bindparams(mid=machine_id, start=start.isoformat())).all()
        counts = {str(r[0] if isinstance(r, tuple) else r.d): int(r[1] if isinstance(r, tuple) else r.n) for r in rows}
        out: list[Point] = []
        for i in range(WINDOW_DAILY):
            d = start + timedelta(days=i)
            key = d.isoformat()
            out.append(Point(label=d.strftime("%d.%m"), bucket_key=key, value=float(counts.get(key, 0))))
        return out


class NewMcpPerWeekAggregator(MetricAggregator):
    name = "new_mcp_per_week"
    # Week-resolution metric: each point = count of MCP server names that
    # appear for the first time (across the machine's history) within that week.

    def points_for(self, session: Session, machine_id: str) -> list[Point]:
        return _diff_aggregate(session, machine_id, extract=_extract_mcp_names)


class NewAgentsPerWeekAggregator(MetricAggregator):
    name = "new_agents_per_week"
    def points_for(self, session: Session, machine_id: str) -> list[Point]:
        return _diff_aggregate(session, machine_id, extract=_extract_agent_dir_hashes)


class SkillDirHashChangesPerWeekAggregator(MetricAggregator):
    name = "skill_dir_hash_changes_per_week"
    def points_for(self, session: Session, machine_id: str) -> list[Point]:
        # Counts skill_name → new dir_hash transitions (not just first-seen)
        return _diff_aggregate(session, machine_id, extract=_extract_skill_hash_changes, count_changes=True)


def _diff_aggregate(
    session: Session, machine_id: str,
    *, extract, count_changes: bool = False,
) -> list[Point]:
    """Walk InventorySnapshot history for this machine in chrono order,
    track running 'seen' set, bucket counts of newly-appearing tokens
    into the last 14 ISO weeks (oldest → newest)."""
    today = datetime.now(UTC).date()
    week_start = today - timedelta(days=today.weekday())  # Monday of this week
    earliest = week_start - timedelta(weeks=WINDOW_WEEKLY - 1)

    # Fetch ALL snapshots up to today, oldest first. For pre-window snapshots
    # we still need them to populate the 'seen' set without counting.
    rows = session.exec(text(
        "SELECT received_at, payload_json FROM inventorysnapshot "
        "WHERE machine_id = :mid ORDER BY received_at ASC"
    ).bindparams(mid=machine_id)).all()

    seen: set[str] = set()              # for first-seen mode
    last_hash_by_key: dict[str, str] = {}  # for hash-change mode
    buckets: dict[str, int] = {}        # week iso week-start ISO date → count

    for r in rows:
        ts_str, payload = (r[0], r[1]) if isinstance(r, tuple) else (r.received_at, r.payload_json)
        ts = ts_str if isinstance(ts_str, datetime) else datetime.fromisoformat(str(ts_str))
        tokens = list(extract(json.loads(payload)))
        snapshot_date = ts.date()
        snapshot_week = snapshot_date - timedelta(days=snapshot_date.weekday())
        wk_key = snapshot_week.isoformat()

        if count_changes:
            # skill_dir_hash_changes_per_week: count (key → new_hash) transitions
            for key, new_hash in tokens:
                prev = last_hash_by_key.get(key)
                if prev is not None and prev != new_hash and snapshot_week >= earliest:
                    buckets[wk_key] = buckets.get(wk_key, 0) + 1
                last_hash_by_key[key] = new_hash
        else:
            for t in tokens:
                if t not in seen:
                    seen.add(t)
                    if snapshot_week >= earliest:
                        buckets[wk_key] = buckets.get(wk_key, 0) + 1

    out: list[Point] = []
    for i in range(WINDOW_WEEKLY):
        wk = earliest + timedelta(weeks=i)
        key = wk.isoformat()
        out.append(Point(label=wk.strftime("%d.%m"), bucket_key=key, value=float(buckets.get(key, 0))))
    return out


def _extract_mcp_names(report: dict) -> list[str]:
    """Pull unique MCP server identities from an InventoryReport JSON dict.
    Identity = `f"{name}@{source_file}"` to disambiguate same-name across configs."""
    out: list[str] = []
    for entry in (report.get("mcp_servers") or []):
        name = entry.get("name") or ""
        src = entry.get("source") or ""
        if name:
            out.append(f"{name}@{src}")
    return out

def _extract_agent_dir_hashes(report: dict) -> list[str]:
    out: list[str] = []
    for a in (report.get("agents") or []):
        h = a.get("file_hash") or a.get("dir_hash")
        if h:
            out.append(h)
    return out

def _extract_skill_hash_changes(report: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for s in (report.get("skills") or []):
        name = s.get("name")
        h = s.get("dir_hash")
        if name and h:
            out.append((name, h))
    return out


METRICS: list[MetricAggregator] = [
    BashCallsPerDayAggregator(),
    NewMcpPerWeekAggregator(),
    NewAgentsPerWeekAggregator(),
    SkillDirHashChangesPerWeekAggregator(),
]
```

> **Important note for planner:** the exact JSON shape of `InventoryReport` (keys like `mcp_servers`, `agents`, `skills` and their inner fields) must be confirmed against `src/ccguard/schemas/inventory.py` during planning — the extractor functions above use my best inference from v0.1 inventory code; if a key name differs, only the `_extract_*` helpers change. Treat the field paths as `[ASSUMED]` until verified.

### Pattern 5: `baseline_service.compute()` — pure stats, easy to unit-test

```python
# src/ccguard/server/services/baseline_service.py
from __future__ import annotations
import statistics
from dataclasses import dataclass
from ccguard.server.services.metric_aggregators import Point

WARM_UP_MIN_POINTS = 7   # CONTEXT.md: <7 points → baseline_ready=False
SIGMA_THRESHOLD = 3.0


@dataclass(frozen=True)
class Baseline:
    median: float
    sigma: float
    sample_count: int
    baseline_ready: bool
    latest_value: float
    is_outlier_latest: bool
    points: list[Point]   # all 14, with .is_outlier annotation if desired
    sigma_distance_latest: float  # signed; +N means above median by Nσ


def compute(points: list[Point]) -> Baseline:
    values = [p.value for p in points]
    non_zero = [v for v in values if v > 0 or True]  # keep zeros — they're data
    sample_count = len(values)
    latest = values[-1] if values else 0.0

    if sample_count < WARM_UP_MIN_POINTS:
        return Baseline(
            median=0.0, sigma=0.0,
            sample_count=sample_count, baseline_ready=False,
            latest_value=latest, is_outlier_latest=False,
            points=points, sigma_distance_latest=0.0,
        )

    median = statistics.median(values)
    # sample stdev requires ≥2; we already have ≥7. Use POPULATION here?
    # CONTEXT.md says "sample stdev (statistics.stdev)" → use statistics.stdev (sample).
    sigma = statistics.stdev(values) if sample_count >= 2 else 0.0

    if sigma == 0.0:
        # Degenerate case: all 14 values identical (e.g. always 0). Any non-zero
        # latest = outlier. Treat sigma=0 as "no variance → strict-equality baseline".
        is_outlier = latest != median
        sigma_distance = float("inf") if is_outlier else 0.0
    else:
        sigma_distance = (latest - median) / sigma
        is_outlier = abs(sigma_distance) > SIGMA_THRESHOLD

    return Baseline(
        median=median, sigma=sigma,
        sample_count=sample_count, baseline_ready=True,
        latest_value=latest, is_outlier_latest=is_outlier,
        points=points, sigma_distance_latest=sigma_distance,
    )
```

### Pattern 6: Idempotent Finding insertion

```python
# src/ccguard/server/services/anomaly_service.py
import json
from datetime import UTC, datetime
from sqlalchemy import text
from sqlmodel import Session, select
from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.services.baseline_service import Baseline, compute
from ccguard.server.services.metric_aggregators import METRICS, Point


def _today_utc_iso() -> str:
    return datetime.now(UTC).date().isoformat()


def _finding_exists_today(session: Session, *, machine_id: str, rule_id: str) -> bool:
    """Service-layer idempotency gate. No DB UNIQUE — keeps things flexible
    if we later want multiple findings per day for *escalation*."""
    sql = text("""
      SELECT 1 FROM findingrecord
      WHERE machine_id = :mid AND rule_id = :rid
        AND date(discovered_at) = :today
      LIMIT 1
    """)
    return session.exec(sql.bindparams(
        mid=machine_id, rid=rule_id, today=_today_utc_iso()
    )).first() is not None


def _emit_finding(session: Session, *, machine_id: str, metric_name: str, bl: Baseline) -> None:
    rule_id = f"anomaly.{metric_name}"
    if _finding_exists_today(session, machine_id=machine_id, rule_id=rule_id):
        return
    payload = {
        "metric": metric_name,
        "observed_value": bl.latest_value,
        "median": bl.median,
        "sigma": bl.sigma,
        "sigma_distance": round(bl.sigma_distance_latest, 2),
        "threshold": 3.0,
        "sample_count": bl.sample_count,
        "bucket_date": _today_utc_iso(),
    }
    # inventory_id = 0 sentinel: this finding isn't tied to a specific snapshot.
    # finding_service / UI must tolerate this (verify in plan-phase).
    rec = FindingRecord(
        machine_id=machine_id,
        inventory_id=0,
        rule_id=rule_id,
        severity="warn",
        discovered_at=datetime.now(UTC),
        payload_json=json.dumps(payload, separators=(",", ":")),
    )
    session.add(rec)


def tick(engine) -> None:
    """Synchronous tick (called from APScheduler async job via asyncio.to_thread).

    Per CONTEXT.md: hourly cadence; idempotent; baseline_ready warm-up;
    one finding/day/machine/metric.
    """
    from sqlmodel import Session as _S
    with _S(engine) as session:
        machine_ids = [m.machine_id for m in session.exec(select(Machine)).all()]
        for mid in machine_ids:
            for agg in METRICS:
                pts = agg.points_for(session, mid)
                bl = compute(pts)
                _upsert_baseline(session, mid, agg.name, bl)
                if bl.baseline_ready and bl.is_outlier_latest:
                    _emit_finding(session, machine_id=mid, metric_name=agg.name, bl=bl)
        session.commit()


def _upsert_baseline(session: Session, machine_id: str, metric: str, bl: Baseline) -> None:
    points_payload = [
        {"label": p.label, "value": p.value, "is_outlier": (i == len(bl.points)-1 and bl.is_outlier_latest)}
        for i, p in enumerate(bl.points)
    ]
    session.exec(_UPSERT_BASELINE_SQL.bindparams(
        machine_id=machine_id,
        metric=metric,
        median=bl.median,
        sigma=bl.sigma,
        sample_count=bl.sample_count,
        baseline_ready=int(bl.baseline_ready),
        recent_points_json=json.dumps(points_payload, separators=(",", ":")),
        latest_value=bl.latest_value,
        updated_at=datetime.now(UTC).isoformat(),
    ))
```

### Pattern 7: Web routes (read-only, mirrors Phase 1 audit)

```python
# src/ccguard/server/web/routes.py — additions (sketch)

VALID_METRICS = {
    "bash_calls_per_day",
    "new_mcp_per_week",
    "new_agents_per_week",
    "skill_dir_hash_changes_per_week",
}

@router.get("/anomalies", response_class=HTMLResponse)
def anomalies_page(
    request: Request,
    session: Session = Depends(get_session),
    _user: WebUser = Depends(require_session),
):
    return templates.TemplateResponse("anomalies_feed.html", {"request": request})


@router.get("/anomalies/{machine_id}/{metric}", response_class=HTMLResponse)
def anomaly_detail(
    machine_id: str, metric: str, request: Request,
    session: Session = Depends(get_session),
    _user: WebUser = Depends(require_session),
):
    if metric not in VALID_METRICS:
        raise HTTPException(404, "unknown metric")
    bl = session.exec(
        select(MachineBaseline).where(
            MachineBaseline.machine_id == machine_id,
            MachineBaseline.metric == metric,
        )
    ).first()
    findings = query_findings(
        session, machine_id=machine_id, rule_id=f"anomaly.{metric}", limit=50
    )
    return templates.TemplateResponse("anomaly_detail.html", {
        "request": request,
        "machine_id": machine_id, "metric": metric,
        "baseline": bl,
        "points": json.loads(bl.recent_points_json) if bl else [],
        "findings": findings,
    })


@router.get("/_partials/anomalies/overview", response_class=HTMLResponse)
def anomalies_overview_partial(...):
    # Top-5 most-recent FindingRecord WHERE rule_id LIKE 'anomaly.%' ORDER BY discovered_at DESC LIMIT 5
    ...


@router.get("/_partials/anomalies/matrix", response_class=HTMLResponse)
def anomalies_matrix_partial(...):
    # SELECT * FROM machine JOIN machinebaseline ON ...
    # Group baselines by machine_id; render rows
    ...
```

### Anti-Patterns to Avoid

- **DON'T** start APScheduler at module-import time (e.g. global `sched.start()` at top of `scheduler.py`). The event loop doesn't exist yet under uvicorn import; `AsyncIOScheduler.start()` requires a running loop.
- **DON'T** use `BackgroundScheduler` inside FastAPI: it spawns its own thread and creates a synchronisation surface across the loop/thread boundary for zero benefit here.
- **DON'T** rely on a DB UNIQUE constraint `(machine_id, rule_id, date(discovered_at))` for idempotency — SQLite supports expression-indexed uniqueness but it complicates the SQLModel schema; service-layer check is simpler and equally correct given single-process invariant.
- **DON'T** recompute baselines inside HTTP request handlers. All HTTP routes read from `MachineBaseline` — never call `tick()` synchronously.
- **DON'T** forget to set `CCGUARD_DISABLE_SCHEDULER=1` in test fixtures — tests will hang or generate spurious findings if the scheduler fires mid-test.
- **DON'T** UPSERT inside per-row autocommit; collect all 4×N writes then single `session.commit()` per tick (already in pattern above).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Periodic scheduled job | Custom `asyncio.create_task(while True: sleep+work)` loop | `APScheduler.AsyncIOScheduler` with `IntervalTrigger(hours=1)` | Misfire handling, coalesce, max_instances, introspection, clean shutdown — all for one dep. |
| Statistics (median/stdev) | Manual `sorted()[len//2]`, manual stdev | `statistics.median`, `statistics.stdev` | Stdlib; handles edge cases (sample vs population); well-tested. |
| UPSERT on (machine, metric) | SELECT-then-INSERT-or-UPDATE | `INSERT ... ON CONFLICT(...) DO UPDATE` (SQLite native) | Atomic, single round-trip, no race. |
| Daily bucketing in Python | Python loop + dict | `GROUP BY date(ts)` in SQL | Index-friendly (`ix_tooluseevent_tool_ts` already exists). |
| Dense series (fill gaps with zeros) | SQL `LEFT JOIN ON generate_series` (Postgres-only) | Python post-fill loop after grouped SELECT | SQLite lacks generate_series in the std build; Python loop over 14 days is trivially cheap. |
| Sparkline data fetch per cell at render time | 400 separate SQL queries on matrix render | Pre-computed `recent_points_json` cached on `MachineBaseline` | Single query: `SELECT * FROM machinebaseline`; render reads JSON column. |

**Key insight:** Phase 2 is mostly **data-pipeline plumbing**, not algorithm. Every step has a one-liner stdlib or library counterpart. The only place to spend brain cycles is the **inventory-diff aggregators** (per-machine, walks history, tracks running set) — those need real unit tests.

## Runtime State Inventory

This phase is **purely additive on the server**. No agent changes, no API changes, no policy changes. New table only.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None to rename. **New** `MachineBaseline` table created via `init_db` on first server startup. | `init_db` already calls `SQLModel.metadata.create_all(engine)` — new table picked up automatically. No data migration. |
| Live service config | None — anomaly detection is fully self-contained on the server. | None. |
| OS-registered state | None — runs inside the existing `ccguard-server` process via APScheduler in-process. No new systemd / docker entry. | None. |
| Secrets / env vars | New env var `CCGUARD_DISABLE_SCHEDULER` (test-only opt-out). No secrets introduced. | Document in `docs/` (planner). |
| Build artifacts | `pyproject.toml` gets one new line: `apscheduler>=3.10,<4`. Container rebuild needed once. | Planner: add reinstall step + update docker base image if deployed. |

**Verified explicitly:** there is **nothing in agent-side runtime state** affected by this phase. Agent v0.1 keeps working unchanged. The new `MachineBaseline` table is invisible to the agent — server-only.

## Common Pitfalls

### Pitfall 1: APScheduler starts before event loop exists
**What goes wrong:** `AsyncIOScheduler().start()` is called at module-import time (top of file). At import, uvicorn hasn't yet built the loop. Result: `RuntimeError: no running event loop`, server fails to boot.
**Why:** `AsyncIOScheduler` ties itself to the *current* running loop. No loop → no scheduler.
**How to avoid:** Only call `build_scheduler(...)` and `start()` **inside** the FastAPI `lifespan` async context manager — that runs inside the loop.
**Warning signs:** `RuntimeError` traceback on server startup that mentions `get_event_loop` or `no running event loop`.

### Pitfall 2: TestClient lifespan hangs because scheduler keeps event loop busy
**What goes wrong:** `TestClient(app)` triggers the lifespan; scheduler starts; integration tests assert against routes; lifespan exit tries `shutdown()` but a job is mid-tick → test hangs.
**Why:** `AsyncIOScheduler.shutdown(wait=True)` (the default) blocks until in-flight jobs complete; if `_tick` runs hourly but happens to fire immediately on first tick (`next_run_time=now+30s`), and tests start ~immediately, hangs are possible.
**How to avoid:** **Set `CCGUARD_DISABLE_SCHEDULER=1` in `tests/integration/conftest.py`** before importing the app. Tests that need the tick should call `anomaly_service.tick(engine)` directly. Also pass `wait=False` to `shutdown()` to make production restarts fast.
**Warning signs:** Pytest hangs for 5+ seconds at the end of a test; `pytest --timeout=30` flags it.

### Pitfall 3: `statistics.stdev` raises `StatisticsError` on <2 samples
**What goes wrong:** Cold-start has 1 data point → `statistics.stdev([5])` → `StatisticsError: stdev requires at least two data points`.
**Why:** `statistics.stdev` is sample stdev with Bessel's correction; needs n≥2.
**How to avoid:** Guard with `sample_count >= WARM_UP_MIN_POINTS` (=7) before computing. Below that, return `baseline_ready=False` and no finding (already in `baseline_service.compute()` above).
**Warning signs:** Unhandled `StatisticsError` in scheduler logs the first hour after deploying to a fleet.

### Pitfall 4: `sigma == 0` blows up `sigma_distance`
**What goes wrong:** All 14 values are identical (e.g. machine consistently runs 0 bash calls/day during a holiday). `sigma=0`, `(latest - median)/0` → `ZeroDivisionError`.
**Why:** Real fleets have constant-zero metrics (idle machine, weekend, on-leave dev).
**How to avoid:** Special-case `sigma == 0`: `is_outlier = (latest != median)`, `sigma_distance = inf` when outlier else 0. Code already does this; **unit test must cover it**.
**Warning signs:** Sporadic `ZeroDivisionError` in tick logs.

### Pitfall 5: Timezone drift — "today" disagreement
**What goes wrong:** Server in UTC, developer in PST. Agent's tool-use events stored as UTC. Server bucket query uses `date(ts)` which in SQLite parses ISO strings lexicographically → UTC-aligned, good. But Python `datetime.now()` (naive, local) used in bucket boundary computation → off by hours.
**Why:** Mixing `datetime.now()` (naive) and `datetime.now(UTC)` (aware) silently produces wrong buckets near midnight.
**How to avoid:** **Always `datetime.now(UTC)`** in baseline / aggregator code. Phase 1 already enforces UTC at ingest via Pydantic validator. Document this rule explicitly in `baseline_service.py` docstring.
**Warning signs:** Bash-call counts seemingly "lost" between day boundaries; outliers showing on wrong dates.

### Pitfall 6: Inventory snapshot duplication / out-of-order races
**What goes wrong:** Agent retries inventory POST; two snapshots arrive with same content but different `received_at`. Diff aggregator treats both as "new" → spurious anomaly.
**Why:** v0.1 doesn't dedupe inventory snapshots at ingest.
**How to avoid:** Diff aggregator runs `ORDER BY received_at ASC`, then uses a `seen` set keyed on stable identity (`name@source`, `dir_hash`, etc.) — duplicate snapshots can't re-introduce a token that's already in `seen`. Confirmed in `_diff_aggregate` above.
**Warning signs:** `new_mcp_per_week` spiking on agents known to retry frequently.

### Pitfall 7: Scheduler fires while previous tick still running
**What goes wrong:** A tick takes >1 hour (unlikely at <100 machines, but possible if SQL becomes slow). Next tick fires; two ticks contend for SQLite write lock; second tick generates duplicate findings (because idempotency gate ran before first tick committed).
**Why:** No coordination across job invocations by default.
**How to avoid:** `max_instances=1` + `coalesce=True` in APScheduler job defaults (already in `build_scheduler`). Belt-and-braces: `app.state.anomaly_lock = asyncio.Lock()` in the job wrapper.
**Warning signs:** Duplicate `anomaly.*` findings in the same day for the same machine/metric.

### Pitfall 8: `disableAllHooks=true` does NOT affect Phase 2
**What goes wrong:** None — but worth noting.
**Why:** Phase 2 is server-side. Even if Claude Code hooks are disabled, the server still runs the scheduler against whatever `ToolUseEvent` data already exists. Baselines age out as the 14-day window slides; no findings emit because latest values converge to zero.
**How to avoid:** Document this expected behaviour in the user-facing UI ("если агент не шлёт события — baseline постепенно занулится").
**Warning signs:** Active machines with `baseline_ready=True` and a sudden flood of `0`-valued points where they used to have data — but this is *correct* behaviour, signalling agent silence.

### Pitfall 9: Inventory schema drift breaks aggregators
**What goes wrong:** A future change to `InventoryReport` JSON shape (renames `mcp_servers` → `mcpServers`) silently breaks `_extract_mcp_names`. Diff aggregator returns empty list → all weeks read 0 → metric appears flat → no anomalies ever fire.
**Why:** `dict.get()` returns `None`/`[]` on missing keys, no exception.
**How to avoid:** Unit-test extractors against a representative fixture; assert non-empty output. Add an integration test that round-trips a real `InventoryReport`.
**Warning signs:** Inventory-based metrics permanently show 0 across the fleet.

## Code Examples

(See **Patterns 1–7** above for full code blocks — `scheduler.py`, lifespan edit, `MachineBaseline` model, aggregators, `baseline_service`, `anomaly_service`, web routes. The remaining example below shows the matrix-page rendering query.)

### Matrix page: single-query fetch for all machines × metrics

```python
# In web/routes.py — /_partials/anomalies/matrix handler
from collections import defaultdict

def anomalies_matrix_partial(session: Session = Depends(get_session), ...):
    machines = session.exec(select(Machine).order_by(Machine.last_seen.desc())).all()
    bls = session.exec(select(MachineBaseline)).all()

    by_machine: dict[str, dict[str, MachineBaseline]] = defaultdict(dict)
    for bl in bls:
        by_machine[bl.machine_id][bl.metric] = bl

    rows: list[dict] = []
    for m in machines:
        cells: dict[str, dict] = {}
        for metric in ("bash_calls_per_day", "new_mcp_per_week",
                       "new_agents_per_week", "skill_dir_hash_changes_per_week"):
            bl = by_machine.get(m.machine_id, {}).get(metric)
            if bl is None or not bl.baseline_ready:
                cells[metric] = {"warm_up": True}
            else:
                pts = json.loads(bl.recent_points_json)
                max_v = max((p["value"] for p in pts), default=1.0) or 1.0
                cells[metric] = {
                    "warm_up": False,
                    "points": [
                        {**p, "height_pct": (p["value"] / max_v) * 100.0}
                        for p in pts
                    ],
                    "last_value": bl.latest_value,
                    "is_outlier": pts[-1].get("is_outlier", False) if pts else False,
                }
        rows.append({"machine": m, "cells": cells})

    return templates.TemplateResponse("components/_anomalies_matrix.html", {
        "request": request, "rows": rows,
    })
```

**Performance envelope:** for 100 machines × 4 metrics that's 1 SELECT on Machine (100 rows) + 1 SELECT on MachineBaseline (400 rows) + 100×4=400 JSON decodes of 14-element arrays. Wall time well under 50ms locally. Within UI-SPEC 60s poll budget by 1000×.

## State of the Art

| Old / theoretical approach | Current approach | Why |
|----------------------------|------------------|-----|
| Cron job calling an HTTP `/internal/recompute` endpoint | APScheduler `AsyncIOScheduler` inside the same process | Single-container deploy; no internal-auth surface; testable via direct function call. |
| ML anomaly detector (isolation forest / autoencoder) | Median + 3σ | Per CONTEXT.md & PROJECT.md — ML deferred to v0.3+; statistics first, model later. |
| Per-event finding emission | Hourly batch + same-day dedup | Reduces noise; matches operator workflow (a daily review cadence). |
| Compute baseline on every UI request | Pre-computed + cached in `MachineBaseline` | UI poll @ 60s × N machines would otherwise duplicate compute work; precompute amortises. |

**Deprecated/outdated:** None — greenfield phase.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `InventoryReport` JSON has keys `mcp_servers`, `agents`, `skills` with subkeys `name`/`source`/`file_hash`/`dir_hash` | Pattern 4 (`_extract_*` helpers) | **Medium** — if a key name differs, the four extractor functions need a one-line correction. Planner MUST confirm against `src/ccguard/schemas/inventory.py` before implementing. |
| A2 | `FindingRecord.inventory_id` accepts `0` as a "no specific snapshot" sentinel | Pattern 6 (`_emit_finding`) | **Low** — column is `int` (non-null per v0.1 schema). Planner may need to either drop the index requirement, set it to the latest known snapshot id, or change `inventory_id` to `int | None`. Verify in plan-phase. |
| A3 | APScheduler 3.x `AsyncIOScheduler.start()` inside a FastAPI lifespan is the canonical FastAPI pattern | Pattern 1, 2 | **Low** — documented behaviour ([CITED: apscheduler.readthedocs.io/en/3.x/userguide.html]); APScheduler-FastAPI integration is widely used. |
| A4 | `WARM_UP_MIN_POINTS = 7` is the right threshold | `baseline_service.compute` | **Low** — CONTEXT.md mandates "<7 points → not ready"; encoded as a constant for easy adjustment. |
| A5 | The Phase 1 UTC ingest validator covers all `ToolUseEvent.ts` rows so `date(ts)` SQL is correct | Pattern 4 | **Low** — confirmed in `tool_use_service.py` docstring (WR-05 enforcement). |
| A6 | Single-instance deploy (no horizontal scale-out) — only one scheduler ticking | Architecture | **Low** — CONTEXT.md & PROJECT.md explicitly say single-tenant, <100 machines, SQLite. If multi-replica deploy is ever attempted, this needs revisit (add a DB-backed leader election). |
| A7 | `WINDOW_WEEKLY = 14` weeks for weekly metrics (vs 14 *days*) | Pattern 4 | **Medium** — CONTEXT.md says "14 daily/weekly point'ам" — ambiguous. Statistically, 14 weeks gives meaningful stdev for weekly metrics; 14 days of weekly counts would mostly be the same number. Recommend confirming with user; default to 14 *points* of the metric's natural cadence (14 weeks here). |
| A8 | `recent_points_json` is acceptable on a SQLModel `str` field (no migration to JSON type needed) | Pattern 3 | **Low** — existing pattern: `FindingRecord.payload_json` is `str`. |

**Open questions for plan-phase to resolve before implementation:**

1. **Inventory JSON shape** (A1) — extract authoritative field names from `src/ccguard/schemas/inventory.py`.
2. **`FindingRecord.inventory_id` handling** (A2) — sentinel `0`, latest snapshot id, or schema relaxation?
3. **Weekly-window meaning** (A7) — 14 weeks of weekly counts (recommended), or 14 daily counts of weekly first-seens?
4. **First-tick delay** — should the scheduler fire 30s after startup (dev-friendly) or wait a full hour (production-strict)?

## Open Questions

1. **First-tick policy**
   - What we know: A 30s first-tick (`next_run_time = now + 30s`) gives instant feedback on dev machines.
   - What's unclear: Whether prod operators want a more conservative cold-start (1 hour) to avoid surprise findings before they've reviewed config.
   - Recommendation: Make first-tick delay configurable (env or `ServerConfig` field), default 30s. Pre-emptively documented in Settings (planner).

2. **Inventory schema drift safety net**
   - What we know: Aggregators inspect specific JSON keys; silent misses break detection.
   - What's unclear: Whether to add a runtime sanity check ("seen 100 snapshots, extracted 0 MCP names — schema broken?") to logs.
   - Recommendation: Log a warning if a tick extracts 0 tokens across all snapshots of a machine that has >5 snapshots. Low-cost, high signal.

3. **Manual recompute trigger for ops?**
   - What we know: UI-SPEC says detail page is read-only.
   - What's unclear: Whether ops needs a "Recompute now" button for support escalations.
   - Recommendation: Defer — only add if first user feedback asks. Tick is hourly, fine for v0.2.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.12 | All | ✓ | 3.12 | — |
| FastAPI / SQLModel / SQLAlchemy / Jinja | All | ✓ | as pinned | — |
| sqlite3 | Aggregation, UPSERT (`ON CONFLICT`) | ✓ | bundled — supports `ON CONFLICT` since SQLite 3.24 (2018) | — |
| **APScheduler** | Scheduler | **✗ (NEW)** | will pin `>=3.10,<4` | None acceptable — see "Don't Hand-Roll" |

**Missing dependencies with no fallback:** none after adding APScheduler.
**Missing dependencies with fallback:** none.

Planner: add `apscheduler>=3.10,<4` to `pyproject.toml [project] dependencies`. Run `pip install -e .` (dev) and rebuild docker image once (deploy).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.0+, pytest-asyncio 0.23+ (already in dev deps) |
| Config file | `pyproject.toml` `[tool.pytest.ini_options]` |
| Quick run command | `pytest -x tests/unit/test_baseline_service.py tests/unit/test_metric_aggregators.py tests/unit/test_anomaly_idempotency.py` |
| Full suite command | `pytest tests/` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| ANO-01 | `baseline_service.compute()` median+stdev correct | unit | `pytest tests/unit/test_baseline_service.py::test_compute_basic -x` | ❌ Wave 0 |
| ANO-01 | `compute()` returns `baseline_ready=False` when <7 points | unit | `pytest tests/unit/test_baseline_service.py::test_warm_up -x` | ❌ Wave 0 |
| ANO-01 | `compute()` handles `sigma=0` (all-equal values) without div-by-zero | unit | `pytest tests/unit/test_baseline_service.py::test_zero_variance -x` | ❌ Wave 0 |
| ANO-01 | `BashCallsPerDayAggregator.points_for` returns 14 dense daily points | unit | `pytest tests/unit/test_metric_aggregators.py::test_bash_daily_dense -x` | ❌ Wave 0 |
| ANO-01 | `NewMcpPerWeekAggregator.points_for` counts only first-seen, ignores duplicates | unit | `pytest tests/unit/test_metric_aggregators.py::test_new_mcp_dedup -x` | ❌ Wave 0 |
| ANO-01 | `MachineBaseline` UPSERT on (machine_id, metric) — idempotent | integration | `pytest tests/integration/test_baseline_upsert.py -x` | ❌ Wave 0 |
| ANO-02 | `anomaly_service.tick()` emits Finding on >3σ outlier | integration | `pytest tests/integration/test_anomaly_tick.py::test_outlier_generates_finding -x` | ❌ Wave 0 |
| ANO-02 | Same-day same-rule finding NOT duplicated by second tick | integration | `pytest tests/integration/test_anomaly_tick.py::test_idempotent_same_day -x` | ❌ Wave 0 |
| ANO-02 | Sub-3σ value does NOT emit finding | integration | `pytest tests/integration/test_anomaly_tick.py::test_no_finding_within_threshold -x` | ❌ Wave 0 |
| ANO-02 | Warm-up phase (baseline_ready=False) emits nothing | integration | `pytest tests/integration/test_anomaly_tick.py::test_no_finding_during_warmup -x` | ❌ Wave 0 |
| ANO-03 | `GET /anomalies` 200 + Russian heading | integration | `pytest tests/integration/test_anomalies_page.py::test_matrix_page_renders -x` | ❌ Wave 0 |
| ANO-03 | `GET /_partials/anomalies/overview` returns top-5 | integration | `pytest tests/integration/test_anomalies_page.py::test_overview_partial -x` | ❌ Wave 0 |
| ANO-03 | `GET /anomalies/{m}/{metric}` 200 with valid metric, 404 with invalid | integration | `pytest tests/integration/test_anomalies_page.py::test_detail_validation -x` | ❌ Wave 0 |
| ANO-03 | All v0.1 + Phase 1 tests still pass | regression | `pytest tests/` | ✅ Existing |

### Sampling Rate
- **Per task commit:** `pytest -x tests/unit/test_baseline_service.py tests/unit/test_metric_aggregators.py` (~0.5s)
- **Per wave merge:** `pytest tests/` (full suite — Phase 1 added ~30 tests; this phase adds another ~25)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/unit/test_baseline_service.py` — covers ANO-01 statistics math
- [ ] `tests/unit/test_metric_aggregators.py` — covers ANO-01 SQL aggregation + inventory-diff helpers
- [ ] `tests/integration/test_baseline_upsert.py` — covers `_upsert_baseline` ON CONFLICT path
- [ ] `tests/integration/test_anomaly_tick.py` — covers ANO-02 finding emission + idempotency
- [ ] `tests/integration/test_anomalies_page.py` — covers ANO-03 routes + partials
- [ ] `tests/conftest.py` — add `os.environ["CCGUARD_DISABLE_SCHEDULER"] = "1"` at module top so app import doesn't start scheduler
- [ ] Fixture: `seed_tool_use_events(session, machine_id, daily_counts: list[int])` to populate 14 days of synthetic data

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | All web routes use existing `require_session` cookie dep — same as v0.1. No new API routes (server-side compute only). |
| V3 Session Management | yes | Inherits v0.1 session lifecycle. |
| V4 Access Control | yes | `/anomalies*` requires authenticated admin. No new roles. |
| V5 Input Validation | yes | Two user-controlled inputs: `machine_id` (path) and `metric` (path). `metric` validated against the closed `VALID_METRICS` set (404 on miss). `machine_id` used only as a parameterized SQL bind value — no injection surface. |
| V6 Cryptography | no | No new cryptographic operations. |
| V7 Error Handling | yes | Scheduler tick wrapped in catch-all `try/except logger.exception(...)`; tick failure must NOT crash the server. Service emits structured logs, no PII. |
| V8 Data Protection | yes | `MachineBaseline` stores aggregates only — no raw tool input. `payload_json` on findings contains the metric value, sigma distance, and bucket date — no sensitive payloads. |
| V9 Communication | yes | Reuses existing HTTPS deployment (docker compose). |

### Known Threat Patterns for {Python / FastAPI / SQLite}

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| SQL injection via `machine_id` path param | Tampering | `session.exec(text(...).bindparams(mid=machine_id))` — parameterized. Pattern already enforced in `tool_use_service.py`. |
| Path-traversal via `metric` path param into template / SQL | Tampering | `metric ∈ VALID_METRICS` closed set check before any use. |
| DoS via massive findings list on detail page | DoS | `LIMIT 50` on findings query. |
| DoS via scheduler tick loop runaway | DoS | `max_instances=1` on APScheduler job + per-process `asyncio.Lock`. Tick latency bounded by SQL on bounded data set. |
| Information disclosure via cross-tenant finding leak | Info Disclosure | Single-tenant v0.2 — N/A. Flagged for v0.3 multi-tenant. |
| Supply chain — typosquatted `apscheduler` | Tampering | Verified: `APScheduler` on PyPI maintained by Alex Grönholm; recommended planner human-verify step before install. |
| Cache poisoning of `recent_points_json` | Tampering | JSON written by trusted server code only; never accepts user input. |

## Sources

### Primary (HIGH confidence)
- **Project codebase (read directly):**
  - `src/ccguard/server/db/models.py` — existing SQLModel patterns; `FindingRecord`, `ToolUseEvent`, `InventorySnapshot` confirmed
  - `src/ccguard/server/db/session.py` — `init_db` + `_TOOL_USE_INDEX_DDL` pattern (reusable for any post-create_all DDL we add)
  - `src/ccguard/server/services/tool_use_service.py` — established `text(...).bindparams(...)` SQL pattern and `BucketDict` shape (mirror for our aggregators)
  - `src/ccguard/server/services/finding_service.py` — `query_findings` filter API (we'll reuse)
  - `src/ccguard/server/api/findings.py` — finding JSON-serialisation pattern
  - `src/ccguard/server/main.py` — current `_lifespan` structure (this is where we hook the scheduler)
  - `pyproject.toml` — confirmed locked deps; no apscheduler yet
- **Planning docs:**
  - `02-CONTEXT.md` — locked decisions
  - `02-UI-SPEC.md` — UI contract (routes, copy, sparkline rendering)
  - `01-RESEARCH.md` (Phase 1) — established stack and patterns

### Secondary (MEDIUM confidence)
- [APScheduler 3.x User Guide — apscheduler.readthedocs.io/en/3.x/userguide.html](https://apscheduler.readthedocs.io/en/3.x/userguide.html) — `AsyncIOScheduler` lifecycle, `IntervalTrigger`, job defaults (`coalesce`, `max_instances`, `misfire_grace_time`)
- PyPI metadata for `APScheduler` (fetched 2026-05-25 via PyPI JSON API) — latest stable 3.11.2, 4.x still alpha (4.0.0a6) [VERIFIED: PyPI]
- SQLite UPSERT (`ON CONFLICT ... DO UPDATE`) — supported since SQLite 3.24 (2018); Python 3.12 ships SQLite ≥3.40

### Tertiary (LOW confidence)
- None — no claims rest solely on unverified web search.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — one new well-established package (APScheduler), the rest is stdlib + existing deps.
- Architecture: HIGH — every pattern (lifespan hook, service module, HTMX partial, UPSERT) has a direct precedent in v0.1 or Phase 1.
- Pitfalls: HIGH — every pitfall listed is either documented in APScheduler docs, observed in real FastAPI projects, or directly derivable from stdlib semantics.
- Inventory diff field paths: **MEDIUM** — see Assumption A1; planner must confirm against actual `InventoryReport` schema before final implementation.
- Weekly-window semantics: **MEDIUM** — see Assumption A7; user clarification recommended.

**Research date:** 2026-05-25
**Valid until:** 2026-06-25 (30 days — APScheduler 3.x is mature and stable; revisit if 4.0 GA ships within validity)
