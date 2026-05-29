# Phase 1: Tool-Use Audit (Foundation) — Research

**Researched:** 2026-05-25
**Domain:** Claude Code PostToolUse hook integration + SQLite buffering + FastAPI batch ingest + HTMX timeline
**Confidence:** HIGH

## Summary

Phase 1 wires a new PostToolUse hook through the existing `ccguard-enforce` shim (or a new sibling shim), buffers events to a per-machine SQLite WAL database, and flushes them to a new `POST /api/v1/audit` endpoint on the server. The server persists into a **new** `ToolUseEvent` table (decision locked in CONTEXT.md — not extending `AuditRecord`). A new `/audit` admin page renders a 24h CSS bar chart + filtered events table, polled via HTMX every 30s.

All major decisions (fingerprinting, batching thresholds, schema split, no Alembic) are pre-locked in `01-CONTEXT.md`. This research focuses on **how** to wire them given the existing codebase (no Alembic, SQLModel `create_all`, Pydantic v2, typer agent CLI, HTMX + Jinja).

**Primary recommendation:** Add a new `ccguard hook-audit` subcommand (analogous to `enforce`) as the PostToolUse entrypoint, a new shim `ccguard-audit` registered in `settings.json` under `PostToolUse`, a `ToolBufferDB` helper using `sqlite3` stdlib (not SQLModel — minimise per-invocation startup cost), and a background flush via a detached child process (double-fork) so the hook returns in <20ms.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Fingerprinting & Privacy:**
- Algorithm: `sha256(tool_name + ":" + normalized_token).hexdigest()[:16]` — 16 hex chars, deterministic
- Bash normalization: shlex/shell-parse → take **first command** before pipes / `&&` / `;`; drop flags (`git status -uall && echo ok` → fp by `git status`)
- Edit/Write/Read: fingerprint of `tool_name + ":" + basename(file_path)` — no full path
- Other tools (Task, Glob, etc.): fingerprint of `tool_name` only, or most semantically-significant field with no content leak
- **No raw `tool_input`** in DB (neither server nor agent buffer) — strictly fingerprint + `tool_name` + `decision` + `result_status` + `ts` + `machine_id`

**Agent-Side Buffering & Batching:**
- Local buffer: SQLite `~/.ccguard/audit_buffer.db` (WAL, survives hook process restart)
- Flush trigger: **50 events OR 30 seconds** (whichever first); manual flush at agent graceful exit (`atexit`)
- Backpressure: cap 10k events; on overflow — drop-oldest + warning in local log
- PostToolUse hook latency: **< 20ms inline** (INSERT into local SQLite only); flush to server in background process/thread, doesn't block hook
- Flush failure handling: retry with exponential backoff (3 attempts), final failure leaves events in buffer (subject to overflow rule)

**Server Schema & Timeline Aggregation:**
- **New `ToolUseEvent` table** (semantic split from existing `AuditRecord`):
  - Fields: `id` PK, `machine_id`, `tool_name`, `fingerprint`, `decision` (allow/deny/error), `result_status` (success/error/blocked), `ts` (UTC datetime), `received_at`
  - SQLModel + Alembic migration  *(note: the project has **no** existing Alembic — see Architecture Patterns)*
- AuditRecord stays for policy-decision-aware events (as in v0.1) — untouched
- Schema versioning: `schema_version` in API request → minor bump (`0.1` → `0.2`); server graceful: v0.1 agents keep working, `/api/v1/audit` — new endpoint, v0.1 agent simply doesn't call it
- Timeline aggregation: **on-the-fly** via SQL `strftime('%Y-%m-%d %H', ts)` GROUP BY; no caching needed for <100 machines with SQLite WAL
- Indexes: composite `(machine_id, ts DESC)`, `(tool_name, ts DESC)`, `(decision, ts DESC)` — covers all UI-SPEC filters

### Claude's Discretion
- Exact column names and Alembic revision id  *(translates to "exact column names and migration mechanism" — see Standard Stack)*
- Async-flush mechanism name (thread vs process vs httpx+ThreadPoolExecutor) — pick minimally-invasive for existing agent code
- Auxiliary module structure (`fingerprinter.py`, `buffer.py`, `flusher.py`) — defer to plan-phase

### Deferred Ideas (OUT OF SCOPE)
- ML classification of tool-use patterns — Phase 2 / v0.3
- Full `tool_input` retention with TTL — out of scope (privacy-by-design)
- Real-time push (WebSocket/SSE) timeline — 30s polling is enough
- Audit export to CSV/JSON — possibly Phase 6 (SIEM)
- Per-tool-name drill-down pages — after data collected
- Cross-machine fingerprint aggregation — Phase 2 anomaly territory
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TUA-01 | PostToolUse hook collects `(tool_name, fingerprint, decision, result_status, ts)` without storing full `tool_input` | Hook protocol section (PostToolUse stdin schema); fingerprint algorithm in Code Examples |
| TUA-02 | Agent aggregates and batches to `POST /api/v1/audit` | Buffer + async flush sections; ToolUseEvent table + API endpoint sections |
| TUA-03 | Web UI `/audit` with filters and 24h timeline | HTMX partial endpoints + timeline SQL aggregation + Jinja template inventory (in UI-SPEC) |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

| Constraint | Impact on This Phase |
|------------|----------------------|
| Python 3.12 + FastAPI + SQLModel + HTMX/Jinja stack frozen for v0.2 | No new DB/web frameworks. Use existing patterns. |
| Self-hosted, SQLite WAL (<100 machines) | No external services. Aggregate in SQL on the fly. |
| Backward compat: agent v0.1 must keep working against server v0.2 | `/api/v1/audit` is **new** endpoint — v0.1 agent never calls it. Existing `/api/v1/inventory` schema unchanged. |
| Performance: PreToolUse <100ms (current ≈30ms) | PostToolUse must be similarly fast (target <20ms per CONTEXT.md). Background flush is mandatory. |
| Security: nothing plaintext, hashes only | Fingerprint is sha256[:16] — already privacy-safe. No `tool_input` stored. |
| Schema versioning: `schema_version` constant; agent sends version, server graceful | New request body includes `schema_version: "0.2"`. Server accepts and stores; missing → reject 422. |
| GSD workflow: all file edits via GSD commands | Standard workflow applies to plan execution. |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| PostToolUse hook handling (parse stdin, fingerprint, INSERT) | Agent / Endpoint | — | Must run inline in the developer's shell, sub-20ms. Cannot live on server. |
| Local buffering (SQLite WAL) | Agent / Endpoint | — | Survives offline server, gives agent backpressure independence. |
| Async batch flush (HTTP POST) | Agent / Endpoint | — | Decoupled from hook hot path. Background process. |
| Token-authenticated ingest | Server / API | — | Reuses existing `X-CCGuard-Token` middleware (`require_token`). |
| ToolUseEvent persistence | Server / DB | — | Single source of truth across the fleet. |
| Timeline aggregation (hourly buckets) | Server / DB (SQL) | — | Push compute to SQL where index helps; no app-layer counting. |
| `/audit` page rendering | Server / Frontend (SSR) | Browser (HTMX poll) | Server-rendered Jinja matches existing v0.1 pattern; HTMX only swaps the timeline partial. |
| Filter form state | Browser (URL query params) | Server (echoes via Jinja) | Native browser navigation; no JS. |

## Standard Stack

### Core (already in `pyproject.toml` — nothing to add)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| FastAPI | >=0.110 | New `/api/v1/audit` router + admin `/audit` route | Matches existing routers |
| SQLModel | >=0.0.16 | `ToolUseEvent` table | Mirrors existing `AuditRecord` |
| Pydantic | >=2.7 (v2) | Request/response models for `POST /api/v1/audit` | Pydantic v2 throughout the project |
| Jinja2 | >=3.1 | `audit_feed.html` + partials | Existing template engine |
| httpx | >=0.27 | Agent flush client | Already used in `sync.py` |
| sqlite3 | stdlib | Agent-side local buffer | No new dep; cold-start cost minimal |
| typer | >=0.12 | New CLI subcommand for hook entrypoint | Already used in `cli.py` |

### Supporting (stdlib — no new dependencies introduced)
| Module | Purpose | When to Use |
|--------|---------|-------------|
| `hashlib.sha256` | Fingerprint | In `fingerprinter.py`; matches `_fingerprint` in `enforce.py` |
| `shlex` | Bash command tokenization for first-command extraction | Bash-specific fingerprint path |
| `os.path.basename` | Edit/Write/Read filename extraction | File-tool fingerprint path |
| `atexit` | Trigger final flush from long-running typer commands | Not from hook (hook is short-lived) — from `ccguard sync` |
| `multiprocessing` or `os.fork`/`os.spawn` | Detached background flush | See Async Flush Mechanism section |
| `logging.handlers.RotatingFileHandler` | Local error log when flush fails | Pattern reused from `agent/audit.py` |

### Alternatives Considered
| Instead of | Could Use | Why we don't |
|------------|-----------|--------------|
| sqlite3 stdlib for buffer | SQLModel/SQLAlchemy | Adds ~100–200ms cold-start; we have a strict <20ms budget |
| Detached subprocess flush | Python `threading.Thread` (daemon) | Hook process exits immediately after writing; daemon thread is killed too. **Subprocess survives.** |
| `apscheduler` for periodic flush | Stdlib subprocess | apscheduler runs only while a parent process is alive; our hook is per-tool-call ephemeral |
| Alembic migration | `SQLModel.metadata.create_all` (existing pattern) | **No Alembic exists in the repo today** — see Architecture Patterns; CONTEXT.md mentions Alembic but the repo doesn't have it. We MUST clarify in plan-phase: either introduce Alembic (one-time setup cost) or keep `create_all` and accept it covers the new table automatically. |

**Version verification:**
```
fastapi: 0.110+ [VERIFIED: pyproject.toml]
sqlmodel: 0.0.16+ [VERIFIED: pyproject.toml]
httpx: 0.27+ [VERIFIED: pyproject.toml]
sqlite3: stdlib (Python 3.12) [VERIFIED: stdlib]
```

No new third-party packages are required. **Package Legitimacy Audit is therefore unnecessary** for this phase — every recommended library is either already pinned in `pyproject.toml` (verified) or part of CPython stdlib.

## Package Legitimacy Audit

| Package | Registry | Disposition |
|---------|----------|-------------|
| _(no new packages)_ | — | N/A — phase introduces zero new dependencies |

## Architecture Patterns

### System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                       Developer machine                          │
│                                                                  │
│  Claude Code  ── PostToolUse stdin JSON ──>  ccguard-audit shim  │
│       │                                              │           │
│       │                                              ▼           │
│       │                                  fingerprint + INSERT    │
│       │                                              │           │
│       │                                              ▼           │
│       │                              ~/.ccguard/audit_buffer.db  │
│       │                                              │           │
│       └─ (hook returns <20ms) ──┐                    │           │
│                                 │                    ▼           │
│                                 │      detached flusher process  │
│                                 │              │                 │
│                                 │              ▼ (50 ev OR 30s)  │
│                                 │       POST /api/v1/audit       │
│                                 │      X-CCGuard-Token header    │
└─────────────────────────────────┼────────────────┼───────────────┘
                                  │                │
                                  ▼                ▼
                             ┌────────────────────────────────┐
                             │   ccguard-server (FastAPI)     │
                             │                                │
                             │   /api/v1/audit                │
                             │   require_token dep            │
                             │   batch insert ToolUseEvent    │
                             │   ─────────────────────        │
                             │   GET /audit (Jinja SSR)       │
                             │   GET /_partials/audit/timeline│
                             │     SQL strftime hour bucket   │
                             │     ORDER BY ts DESC LIMIT 200 │
                             └────────────────────────────────┘
                                            │
                                            ▼
                             ┌────────────────────────────────┐
                             │      SQLite (WAL)              │
                             │   ToolUseEvent (new table)     │
                             │   AuditRecord  (unchanged)     │
                             │   indexes on (machine,ts),     │
                             │              (tool,ts),        │
                             │              (decision,ts)     │
                             └────────────────────────────────┘
```

### Recommended Project Structure (incremental additions)

```
src/ccguard/
├── agent/
│   ├── audit_hook/                  # NEW — post-tool-use hook subsystem
│   │   ├── __init__.py
│   │   ├── fingerprint.py           # NEW — Bash/Edit/Write/Read fingerprinting
│   │   ├── buffer.py                # NEW — local sqlite3 buffer (WAL)
│   │   ├── flusher.py               # NEW — detached flush process logic
│   │   └── hook_main.py             # NEW — stdin parser + INSERT + spawn flusher
│   ├── install.py                   # EDIT — add PostToolUse registration
│   └── cli.py                       # EDIT — add `ccguard hook-audit` command
├── schemas/
│   └── tool_use.py                  # NEW — Pydantic v2 ToolUseEvent + batch
├── server/
│   ├── api/
│   │   └── audit.py                 # NEW — POST /api/v1/audit
│   ├── db/
│   │   └── models.py                # EDIT — append ToolUseEvent SQLModel
│   ├── services/
│   │   └── tool_use_service.py      # NEW — queries (list events, timeline buckets)
│   └── web/
│       ├── routes.py                # EDIT — /audit + /_partials/audit/timeline
│       └── templates/
│           ├── base.html            # EDIT — add `<a href="/audit">Аудит</a>`
│           ├── audit_feed.html      # NEW
│           └── components/
│               ├── _audit_timeline.html       # NEW
│               └── _audit_events_table.html   # NEW
```

### Pattern 1: PostToolUse hook lifecycle (mirrors `enforce.py` for PreToolUse)

**What:** Short-lived CLI invoked per tool call. Reads stdin JSON, fingerprints, INSERTs into local SQLite, optionally spawns flusher, exits.

**When to use:** Every PostToolUse invocation.

**Example skeleton:**
```python
# src/ccguard/agent/audit_hook/hook_main.py
from __future__ import annotations
import json, sys
from datetime import UTC, datetime
from ccguard.agent.audit_hook.buffer import ToolBufferDB
from ccguard.agent.audit_hook.fingerprint import compute_fingerprint
from ccguard.agent.audit_hook.flusher import maybe_spawn_flusher
from ccguard.agent.config import default_config_dir

def main_cli(stdin_text: str | None = None) -> int:
    # Fail-open: never block tool execution.
    try:
        text = stdin_text if stdin_text is not None else sys.stdin.read()
        data = json.loads(text) if text.strip() else {}
        tool_name = data.get("tool_name", "(unknown)")
        tool_input = data.get("tool_input") or {}
        tool_response = data.get("tool_response") or {}
        decision = _decision_from_response(tool_response)  # see Fingerprint section
        result_status = _result_status_from_response(tool_response)
        fp = compute_fingerprint(tool_name, tool_input)
        ts = datetime.now(UTC).isoformat()
        with ToolBufferDB(default_config_dir() / "audit_buffer.db") as buf:
            buf.insert(ts=ts, tool_name=tool_name, fingerprint=fp,
                       decision=decision, result_status=result_status)
            row_count = buf.row_count()
        maybe_spawn_flusher(row_count_hint=row_count)
    except Exception:
        # absolutely never raise — fail-open
        pass
    return 0
```

### Pattern 2: SQLite buffer with WAL + short transaction

```python
# src/ccguard/agent/audit_hook/buffer.py (sketch)
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,                    -- ISO-8601 UTC
  tool_name TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  decision TEXT NOT NULL,
  result_status TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_id ON events(id);
"""

class ToolBufferDB:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        # isolation_level=None for explicit BEGIN IMMEDIATE; 5s busy timeout.
        self.conn = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)
        return self

    def __exit__(self, *exc):
        self.conn.close()

    def insert(self, *, ts, tool_name, fingerprint, decision, result_status):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute(
                "INSERT INTO events(ts,tool_name,fingerprint,decision,result_status) "
                "VALUES (?,?,?,?,?)",
                (ts, tool_name, fingerprint, decision, result_status),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def row_count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM events")
        return cur.fetchone()[0]
```

### Pattern 3: HTMX-polled timeline partial (mirrors `overview.html`)

```html
{# audit_feed.html — abridged #}
{% extends "base.html" %}
{% block content %}
<h2 class="text-2xl font-semibold mb-6">Аудит</h2>

<form method="GET" action="/audit" class="bg-white rounded-lg shadow p-4 mb-4 flex gap-4">
  <input name="machine_id" value="{{ filters.machine_id or '' }}" placeholder="machine_id"
         class="rounded border border-slate-300 text-sm" />
  <input name="tool_name" value="{{ filters.tool_name or '' }}" placeholder="tool_name"
         class="rounded border border-slate-300 text-sm" />
  <select name="decision" class="rounded border border-slate-300 text-sm">
    <option value="">все решения</option>
    {% for d in ["allow","deny","error"] %}
      <option value="{{d}}" {% if filters.decision==d %}selected{% endif %}>{{d}}</option>
    {% endfor %}
  </select>
  <select name="timeframe" class="rounded border border-slate-300 text-sm">
    {% for tf,label in [("1h","за 1 час"),("24h","за 24 часа"),("7d","за 7 дней")] %}
      <option value="{{tf}}" {% if filters.timeframe==tf %}selected{% endif %}>{{label}}</option>
    {% endfor %}
  </select>
  <button class="bg-slate-900 text-white text-sm rounded px-4 py-2">Фильтр</button>
  <a href="/audit" class="text-sm text-slate-500 hover:underline self-center">Сбросить</a>
</form>

<div class="bg-white rounded-lg shadow p-4 mb-4"
     hx-get="/_partials/audit/timeline"
     hx-trigger="every 30s"
     hx-include="closest form">
  {% include "components/_audit_timeline.html" %}
</div>

<div class="bg-white rounded-lg shadow p-4">
  {% include "components/_audit_events_table.html" %}
</div>
{% endblock %}
```

### Anti-Patterns to Avoid

- **DON'T** open a SQLModel session inside the hook entrypoint — SQLAlchemy import alone costs ~100ms; use raw `sqlite3`.
- **DON'T** use `threading.Thread(daemon=True)` to flush — the hook process exits within milliseconds, killing daemon threads before they finish.
- **DON'T** keep a long-running write transaction during the hook — use BEGIN IMMEDIATE → INSERT → COMMIT.
- **DON'T** store full `tool_input` even temporarily (privacy-by-design — CONTEXT.md). Fingerprint inline, then drop the dict.
- **DON'T** introduce Alembic only for this phase if not already present — adds a new build step. **Confirm with planner/user** whether to (a) keep `create_all` (existing pattern) or (b) introduce Alembic now.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Stdin JSON parsing | Custom regex/manual JSON-shape checks | Pydantic v2 model `PostToolUseHookInput(SchemaBase)` (analogous to `EnforceHookInput`) | Type safety + `extra="ignore"` already used in project |
| Bash command tokenization | Custom string split on `|;&&` | `shlex.split` with `posix=True`, then take token before first `;`/`&&`/`||`/`|` — see Fingerprint section | shlex handles quotes, escapes, heredocs reasonably |
| Hourly buckets | Python `datetime` looping + dict aggregation | SQLite `strftime('%Y-%m-%d %H', ts) AS bucket GROUP BY bucket` | Index-friendly, server-side |
| Background flush scheduling | apscheduler | `subprocess.Popen` with `start_new_session=True` + double-fork (Unix) or `DETACHED_PROCESS` (Windows — out of scope per `install.py` comment "MVP focused on Linux") | Survives parent-process exit; no extra dep |
| Local buffer concurrency | File locking + JSON-lines | SQLite WAL + `BEGIN IMMEDIATE` + short tx + `PRAGMA busy_timeout=5000` | Multiple short-lived hooks safely contend; WAL minimises reader blocking |
| Schema versioning negotiation | Custom version-comparison code | Static module constant `SCHEMA_VERSION_AUDIT = "0.2"` in both client and server schemas package | One line of code; planner adds a compatibility check in API handler |

**Key insight:** Every hot-path step has a battle-tested stdlib primitive. The agent CLI deliberately avoids heavy ORM imports for the same reason `enforce.py` doesn't import SQLAlchemy.

## Runtime State Inventory

This is a greenfield phase (new files, new endpoint, new table). No renames or migrations of existing runtime state.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — new `ToolUseEvent` table, no rename of existing tables | None |
| Live service config | New PostToolUse entries in `~/.claude/settings.json` (written by `ccguard install` extension). Existing PreToolUse entries unchanged. | Extend `install.py` HOOK_MATCHERS handling to register a `PostToolUse` entry. |
| OS-registered state | None — agent is a per-user pip install; no systemd/launchd/Windows tasks | None |
| Secrets/env vars | Reuses existing `X-CCGuard-Token` (already in `~/.ccguard/config.yaml`) | None |
| Build artifacts | None — pyproject.toml gets a new entry point (`ccguard-audit-bin`?) optionally; pip reinstall covers it | Document in install/upgrade notes (planner). |

## Common Pitfalls

### Pitfall 1: Daemon thread killed before flush
**What goes wrong:** Hook spawns a daemon thread to send HTTP POST, then the parent exits in 5ms and the daemon thread is terminated mid-request.
**Why:** PostToolUse hook is a short-lived CPython process. Daemon threads die with the process. Non-daemon threads block process exit (hangs Claude Code).
**How to avoid:** Use `subprocess.Popen` (Unix double-fork pattern) so the flusher runs in an independent process group. Parent exits cleanly; flusher continues.
**Warning signs:** Local buffer fills but server `ToolUseEvent` table stays empty.

### Pitfall 2: SQLite "database is locked" under concurrent hooks
**What goes wrong:** Two simultaneous Bash invocations both trigger PostToolUse; both try to INSERT; second one gets `OperationalError: database is locked`.
**Why:** WAL allows concurrent readers, but **only one writer at a time**. Default busy_timeout is 0.
**How to avoid:** `PRAGMA busy_timeout=5000` + `BEGIN IMMEDIATE` (acquires write lock upfront, fails fast if can't) + short transactions (single INSERT).
**Warning signs:** Sporadic missing events; `OperationalError` in agent error log.

### Pitfall 3: Timezone drift between agent and server
**What goes wrong:** Agent writes `datetime.now()` (local TZ), server interprets as UTC; buckets are off by N hours.
**Why:** `datetime.now()` is naive. `strftime('%Y-%m-%d %H', ts)` on a naive-but-actually-local string returns local bucketing.
**How to avoid:** Always `datetime.now(UTC).isoformat()` on agent. Server stores as UTC datetime. UI renders with explicit `%H:%M` and a note that times are UTC (or convert in the partial — defer to planner).
**Warning signs:** Bars appear in wrong hour slots; events near midnight stuck in "wrong day".

### Pitfall 4: HTMX `hx-include="closest form"` doesn't escape special chars
**What goes wrong:** User types `machine_id=foo bar` and HTMX URL-encodes ambiguously.
**Why:** HTMX uses `URLSearchParams` semantics; spaces become `+`. FastAPI handles `+` correctly **but** if the user pastes `&` or `=` in a text input, the form serialisation eats it.
**How to avoid:** Treat `machine_id` and `tool_name` as fragment-match (server-side `LIKE`) but document in UI: only token-safe chars expected (matches existing v0.1 form behaviour in `findings_feed.html`).
**Warning signs:** Filter returns no results when machine_id contains punctuation; check server access log for malformed query string.

### Pitfall 5: `tool_input` PII leaking via fingerprint salt collision
**What goes wrong:** Fingerprint is short (16 hex chars = 64 bits). Two different bash commands hash to same value with non-trivial probability across 100M events.
**Why:** Birthday paradox at 64 bits is ~4B events for 50% collision — we're nowhere near. But also: `sha256(tool_name+":"+token)` with a constant separator could let someone with knowledge of common bash invocations build a rainbow table.
**How to avoid:** Accept it — fingerprint is a non-secret identifier for grouping, not a privacy boundary. Privacy comes from **not storing** the input, not from fingerprint opacity. Document this in code comments so it's not later "hardened" with a per-machine salt (which would break cross-machine pattern detection in Phase 2).
**Warning signs:** N/A — this is a design clarification, not a runtime failure mode.

### Pitfall 6: `disableAllHooks=true` silently breaks audit
**What goes wrong:** User flips `disableAllHooks=true` in settings.json. Enforce shim already handles this (tamper-detect in `verify_installation`); the new audit hook would inherit silently dropping events.
**Why:** Claude Code's setting kills ALL hooks at once.
**How to avoid:** Existing `verify_installation` in `install.py` already flags `disableAllHooks=true`. Extend it to also check PostToolUse registration. UI Overview can later show "audit hook disabled" warning.
**Warning signs:** Buffer stays at 0 rows on an active machine. Server sees `last_seen` updates but no audit events.

## Code Examples

### Fingerprint algorithm — matches CONTEXT.md spec exactly

```python
# src/ccguard/agent/audit_hook/fingerprint.py
from __future__ import annotations
import hashlib
import os
import shlex
from typing import Any

_BASH_BREAKERS = {"|", "||", "&&", ";", "&"}

def _normalize_bash(command: str) -> str:
    """Take the first command before any pipe/separator; drop flags."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        # malformed quotes — fall back to a rough split
        tokens = command.split()
    head: list[str] = []
    for t in tokens:
        if t in _BASH_BREAKERS:
            break
        # drop flags (-x, --long)
        if t.startswith("-"):
            continue
        # drop env var assignments like FOO=bar before the program name
        if not head and "=" in t and t.split("=", 1)[0].isidentifier():
            continue
        head.append(t)
        # take just the program (first non-flag token)
        if len(head) == 1:
            break
    return " ".join(head) if head else command.strip()[:64]

def _normalize_token(tool_name: str, tool_input: dict[str, Any]) -> str:
    if tool_name == "Bash":
        return _normalize_bash(str(tool_input.get("command", "")))
    if tool_name in ("Edit", "Write", "Read", "MultiEdit", "NotebookEdit"):
        fp = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        return os.path.basename(fp) if fp else ""
    # Other tools (Task, Glob, WebFetch, WebSearch, mcp__*): fingerprint by name only.
    return ""

def compute_fingerprint(tool_name: str, tool_input: dict[str, Any]) -> str:
    token = _normalize_token(tool_name, tool_input)
    raw = f"{tool_name}:{token}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]
```

### `ToolUseEvent` SQLModel (append to `src/ccguard/server/db/models.py`)

```python
class ToolUseEvent(SQLModel, table=True):
    """Tool-use events from PostToolUse hook. Privacy: no raw tool_input."""

    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    ts: datetime = Field(index=True)             # UTC tool-call timestamp
    received_at: datetime = Field(default_factory=_utcnow)
    tool_name: str = Field(index=True)
    fingerprint: str = Field(index=True)
    decision: str = Field(index=True)            # allow | deny | error
    result_status: str                           # success | error | blocked
```

**Composite index DDL (executed after `create_all`, in a one-shot migration helper or via `event.listens_for(engine, "connect")`):**

```sql
CREATE INDEX IF NOT EXISTS ix_tooluseevent_machine_ts  ON tooluseevent (machine_id, ts DESC);
CREATE INDEX IF NOT EXISTS ix_tooluseevent_tool_ts     ON tooluseevent (tool_name, ts DESC);
CREATE INDEX IF NOT EXISTS ix_tooluseevent_decision_ts ON tooluseevent (decision, ts DESC);
```

> **Migration mechanism note:** Project currently uses `SQLModel.metadata.create_all` (see `server/db/session.py`). For a fresh database this picks up `ToolUseEvent` automatically. **For an existing v0.1 database (production), `create_all` will create the new table** (SQLAlchemy/SQLModel does add new tables) but **WILL NOT add composite indexes** if they're added later. Recommendation: run the index DDL via an idempotent on-startup helper alongside `init_db`. Planner should choose between (a) keep this lightweight approach or (b) introduce Alembic in this phase. **Both are acceptable; CONTEXT.md said "Alembic" but the repo doesn't have it today — surface this to the user.**

### Pydantic v2 request schema for POST /api/v1/audit

```python
# src/ccguard/schemas/tool_use.py
from __future__ import annotations
from datetime import datetime
from typing import Literal
from ccguard.schemas._base import SchemaBase

SCHEMA_VERSION_AUDIT = "0.2"

class ToolUseEventIn(SchemaBase):
    ts: datetime
    tool_name: str
    fingerprint: str
    decision: Literal["allow", "deny", "error"]
    result_status: Literal["success", "error", "blocked"]

class AuditBatchIn(SchemaBase):
    schema_version: str             # MUST equal SCHEMA_VERSION_AUDIT or compatible
    machine_id: str
    events: list[ToolUseEventIn]    # batch — server enforces len <= 200

class AuditBatchOut(SchemaBase):
    accepted: bool
    stored: int
    rejected: int
    server_schema_version: str
```

### POST /api/v1/audit endpoint

```python
# src/ccguard/server/api/audit.py
from __future__ import annotations
from datetime import UTC, datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session
from ccguard.schemas.tool_use import AuditBatchIn, AuditBatchOut, SCHEMA_VERSION_AUDIT
from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import ToolUseEvent

router = APIRouter(prefix="/api/v1")

MAX_BATCH = 200

@router.post("/audit", response_model=AuditBatchOut)
def post_audit(
    payload: AuditBatchIn,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> AuditBatchOut:
    if payload.schema_version.split(".")[0] != SCHEMA_VERSION_AUDIT.split(".")[0]:
        # major-version mismatch — reject.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"schema_version {payload.schema_version} incompatible with server {SCHEMA_VERSION_AUDIT}")
    if len(payload.events) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"batch too large (max {MAX_BATCH})")
    now = datetime.now(UTC)
    stored = 0
    for e in payload.events:
        session.add(ToolUseEvent(
            machine_id=payload.machine_id,
            ts=e.ts, received_at=now,
            tool_name=e.tool_name, fingerprint=e.fingerprint,
            decision=e.decision, result_status=e.result_status,
        ))
        stored += 1
    session.commit()
    return AuditBatchOut(accepted=True, stored=stored, rejected=0,
                         server_schema_version=SCHEMA_VERSION_AUDIT)
```

### Timeline SQL aggregation (24h hourly buckets)

```python
# src/ccguard/server/services/tool_use_service.py
from __future__ import annotations
from datetime import UTC, datetime, timedelta
from typing import Any
from sqlalchemy import text
from sqlmodel import Session

_TIMEFRAMES = {"1h": 1, "24h": 24, "7d": 168}

def timeline_buckets(
    session: Session,
    *, hours: int = 24,
    machine_id: str | None = None,
    tool_name: str | None = None,
    decision: str | None = None,
) -> list[dict[str, Any]]:
    """
    Returns dense list of `hours` buckets (oldest first), each with
    `bucket_iso`, `hour_label`, `count`.
    Empty hours are explicitly returned with count=0 so the chart has no gaps.
    """
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)
    sql = """
      SELECT strftime('%Y-%m-%d %H', ts) AS bucket, COUNT(*) AS n
      FROM tooluseevent
      WHERE ts >= :start
        AND (:machine_id IS NULL OR machine_id LIKE :machine_id_like)
        AND (:tool_name  IS NULL OR tool_name = :tool_name)
        AND (:decision   IS NULL OR decision  = :decision)
      GROUP BY bucket
    """
    rows = session.exec(text(sql), params={
        "start": start.isoformat(),
        "machine_id": machine_id, "machine_id_like": f"%{machine_id}%" if machine_id else None,
        "tool_name": tool_name or None,
        "decision":  decision  or None,
    }).all()
    counts = {r[0]: r[1] for r in rows}
    out: list[dict[str, Any]] = []
    for i in range(hours):
        b = start + timedelta(hours=i)
        key = b.strftime("%Y-%m-%d %H")
        out.append({
            "bucket_iso": b.isoformat(),
            "hour_label": b.strftime("%H:%M %d.%m"),
            "count": counts.get(key, 0),
        })
    return out
```

### Async flush — detached subprocess (Unix double-fork pattern)

```python
# src/ccguard/agent/audit_hook/flusher.py
from __future__ import annotations
import os, sys, subprocess
from pathlib import Path
from ccguard.agent.config import default_config_dir

_FLUSH_LOCK = default_config_dir() / "audit_flush.lock"  # PID file
_BATCH_THRESHOLD = 50
_TIME_THRESHOLD_S = 30

def maybe_spawn_flusher(row_count_hint: int) -> None:
    """Spawn detached flusher if (a) batch-size threshold exceeded OR
    (b) no flusher has run in the last 30s. Holds a pidfile lock so we
    don't spawn duplicates."""
    if not _should_spawn(row_count_hint):
        return
    # Double-fork on Unix to detach.
    if hasattr(os, "fork"):
        pid = os.fork()
        if pid > 0:
            return  # parent: hook keeps moving
        os.setsid()
        pid2 = os.fork()
        if pid2 > 0:
            os._exit(0)
        # grandchild — run flusher then exit
        try:
            _run_flush_loop()
        finally:
            os._exit(0)
    else:
        # Windows fallback (out of scope for v0.2 per install.py)
        subprocess.Popen(
            [sys.executable, "-m", "ccguard.agent.audit_hook.flusher_main"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True,
        )

def _should_spawn(row_count: int) -> bool:
    # ... pidfile / mtime check ...
    return row_count >= _BATCH_THRESHOLD or _last_flush_older_than(_TIME_THRESHOLD_S)

def _run_flush_loop() -> None:
    # 1. Read up to MAX_BATCH events from buffer (oldest first)
    # 2. POST to /api/v1/audit
    # 3. On 200: DELETE those rows from buffer
    # 4. On failure: exponential backoff, max 3 attempts; then exit (events remain)
    ...
```

> **Trade-off:** Detached subprocess is the cleanest "survives parent exit" mechanism. Alternative: have `ccguard sync` (already periodic) also drain the buffer, and use a daemon thread only as a best-effort instant-flush at the 50-event mark. **Planner should pick one** — both are minimally invasive; the daemon-thread variant is the smaller diff but loses events near hook exit.

### Settings.json PostToolUse registration (extension of `install.py`)

```jsonc
// ~/.claude/settings.json (after install)
{
  "hooks": {
    "PreToolUse":  [ /* existing ccguard-enforce entries — unchanged */ ],
    "PostToolUse": [
      {
        "matcher": "*",                    // capture everything
        "hooks": [
          { "type": "command",
            "command": "/home/user/.ccguard/bin/ccguard-audit",
            "timeout": 3 }
        ]
      }
    ]
  }
}
```

`install.py` already has the matcher-merge logic for `PreToolUse`. Extend `install_hook()` to take a hook-event argument (`PreToolUse` or `PostToolUse`) and a matcher set (`HOOK_MATCHERS` for enforce, `["*"]` for audit). Mirror the existing idempotency check.

## Test Strategy

### Unit tests (mirror existing `tests/unit/test_*.py` patterns)

| File | Coverage |
|------|----------|
| `tests/unit/test_audit_fingerprint.py` | Bash `git status -uall && echo ok` → fp by "git status"; heredocs; pipes; env var prefix; Edit basename; Read basename; mcp__ tools by name only; collision-resistance smoke |
| `tests/unit/test_audit_buffer.py` | Insert + count; concurrent INSERT from two processes (multiprocessing test) — both succeed under WAL + busy_timeout; overflow at 10k cap drops oldest; survives reopen |
| `tests/unit/test_audit_flusher.py` | `maybe_spawn_flusher` no-op when below threshold; pidfile prevents duplicate; backoff math |
| `tests/unit/test_db_models.py` | Add `ToolUseEvent` round-trip test (already exists for other models — extend) |
| `tests/unit/test_schemas.py` | `AuditBatchIn` validates schema_version; rejects malformed decision/result_status; rejects empty machine_id |

### Integration tests (use existing `client` fixture in `tests/integration/conftest.py`)

| File | Coverage |
|------|----------|
| `tests/integration/test_audit_api.py` | `POST /api/v1/audit` with valid batch → 200, rows persisted; no token → 401; wrong schema_version → 422; batch too large → 413 |
| `tests/integration/test_audit_page.py` | GET /audit (authenticated) → 200, Russian heading present; filter form echoes selected values; empty state when no events |
| `tests/integration/test_audit_timeline_partial.py` | GET /_partials/audit/timeline → 24 buckets returned; filter params honoured; counts correct against seed data |

### E2E (extend `tests/integration/test_web_smoke.py` style)

- Seed N=1000 events across 24 hours via direct SQLModel insert
- GET /audit → assert table has rows, timeline has correct max-bar
- Apply filter `tool_name=Bash` → assert table shrinks

### Test infrastructure already covers needs
- `client` fixture provides in-memory-ish SQLite + auth → reuse directly
- `_patch_httpx_to_testclient` from `test_agent_sync.py` → reuse for testing the **agent flusher end-to-end** against the in-process app

### Wave 0 Gaps
- Need a fixture for `tmp_path / "audit_buffer.db"` in unit tests → trivial
- No multiprocessing fixture exists yet; add `tests/conftest.py` helper that spawns a worker subprocess hitting a shared sqlite path
- `tests/integration/test_audit_api.py` — new file, depends on `ToolUseEvent` model existing

## State of the Art

| Old Approach (theoretical) | Current Approach | Why |
|----------------------------|------------------|-----|
| Hook writes JSON-lines to a flat file, separate cron-like job ingests | SQLite WAL buffer with detached subprocess flush | File-based requires file-locking semantics; SQLite gives it for free + supports overflow cap |
| Synchronous POST inside hook | Detached background flusher | Hook latency budget is <20ms; HTTP round-trip is 50–500ms |
| Server stores raw `tool_input` for retroactive analysis | Fingerprint-only (privacy-by-design) | Privacy-by-design is a v0.2 selling point vs. classical EDRs; fingerprint preserves "same command repeated" insight |

**Deprecated/outdated:** None — this is a greenfield phase.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Claude Code PostToolUse stdin schema includes `tool_name`, `tool_input`, `tool_response`, `hook_event_name`, `cwd`, `session_id` exactly as PreToolUse + `tool_response` | Hook protocol / Pattern 1 | Low — sourced from official docs ([CITED]); if a field name changes, Pydantic `extra="ignore"` keeps parsing graceful |
| A2 | `decision` semantics for PostToolUse: agent infers from `tool_response.success` boolean (or absence of error) — Claude Code doesn't surface a "decision" field in PostToolUse | Pattern 1 | Medium — `tool_response` shape is tool-dependent; planner should pick a conservative heuristic (e.g., `decision = "allow"` always for PostToolUse, since PreToolUse decided; `result_status` carries the actual success/error) |
| A3 | SQLite WAL + busy_timeout=5s handles concurrent hook writes from up to ~10 simultaneous Bash invocations on the same machine | Common Pitfalls #2 | Low — well-documented behaviour; integration test (multiprocessing) verifies it |
| A4 | The repo will accept `SQLModel.metadata.create_all` for the new table without introducing Alembic | Standard Stack alternatives | Medium — CONTEXT.md said "Alembic migration", but the repo has none. **User confirmation needed.** |
| A5 | Detached subprocess (double-fork) works on Linux/macOS; Windows out of scope per `install.py` MVP comment | Async flush mechanism | Low — install.py explicitly says "MVP focused on Linux" |
| A6 | `decision` enum values `allow | deny | error` cover all PostToolUse outcomes (`error` = hook saw a tool_response with error) | Schema | Low — easy to extend later via Pydantic Literal |

## Open Questions

1. **Alembic introduction in this phase or stick with `create_all`?**
   - What we know: CONTEXT.md says "SQLModel + Alembic migration". Repo has no Alembic config or `alembic/` directory today.
   - What's unclear: Whether the user wants Alembic introduced now (one-time setup task) or to keep the existing `create_all` pattern.
   - Recommendation: Ask the user during plan-phase. If unclear, default to `create_all` + an idempotent index-creation helper (smaller diff, matches v0.1 pattern).

2. **`decision` semantics for PostToolUse — what value to record?**
   - What we know: PostToolUse fires *after* the tool ran; PreToolUse decision already happened.
   - What's unclear: Should `decision` reflect the PreToolUse outcome (always `allow` because deny would've stopped the call), or be derived from `tool_response` status, or always `allow` with `result_status` carrying the truth?
   - Recommendation: `decision = "allow"` always in PostToolUse (since denied calls never reach PostToolUse). The user-facing `decision` filter on `/audit` then meaningfully distinguishes between this table (allowed-and-ran) and the existing `AuditRecord` table (deny / fail-open audit trail). Document in API docstring.

3. **Single shim binary or two?**
   - What we know: v0.1 has `ccguard-enforce` shim for PreToolUse.
   - What's unclear: Should we add a second shim `ccguard-audit` (clean separation, two binaries to maintain) or extend the existing shim with a `--mode=post` flag (one binary, branches by hook_event_name)?
   - Recommendation: New separate shim `ccguard-audit` mirroring `ccguard-enforce`. Easier to reason about, easier to disable independently, mirrors Claude Code's own separation of PreToolUse/PostToolUse settings. Surface to user.

4. **HOOK_MATCHERS for PostToolUse: `["*"]` or narrow set?**
   - What we know: PreToolUse uses `["Bash", "mcp__.*", "WebFetch", "WebSearch"]`.
   - What's unclear: Audit benefits from capturing **everything** (`Edit`, `Write`, `Read`, `Task`, `Glob`, `Grep` too — all useful for behavioral baseline in Phase 2).
   - Recommendation: `["*"]` matcher — capture every tool. Volume risk: a busy developer might see 1k events/hour, well within batch-flush budget (50 events / 30s = ~6k/hour).

## Environment Availability

This phase has no new external dependencies — only Python 3.12 stdlib + libraries already in `pyproject.toml`.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.12 | Whole project | ✓ (existing) | 3.12 | — |
| sqlite3 | Agent buffer | ✓ (stdlib) | 3.x | — |
| FastAPI / SQLModel / httpx | Server endpoint, agent flush | ✓ (pyproject) | as pinned | — |
| `os.fork` | Detached flush on Unix | ✓ (Linux/macOS) | — | Windows: `subprocess.Popen` + `DETACHED_PROCESS` — out of scope |

**No missing dependencies.** No package install step beyond `pip install -e .` reinstall after `pyproject.toml` adds the new entry point (if planner chooses to add `ccguard-audit-bin`).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.0+, pytest-asyncio 0.23+ |
| Config file | `pyproject.toml` [tool.pytest.ini_options] |
| Quick run command | `pytest -x tests/unit/test_audit_fingerprint.py tests/unit/test_audit_buffer.py` |
| Full suite command | `pytest tests/` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| TUA-01 | Fingerprint deterministic, no raw input | unit | `pytest tests/unit/test_audit_fingerprint.py -x` | ❌ Wave 0 |
| TUA-01 | Buffer INSERT survives concurrent hooks | unit (multiprocessing) | `pytest tests/unit/test_audit_buffer.py -x` | ❌ Wave 0 |
| TUA-02 | POST /api/v1/audit happy path | integration | `pytest tests/integration/test_audit_api.py -x` | ❌ Wave 0 |
| TUA-02 | POST /api/v1/audit auth/version errors | integration | same file | ❌ Wave 0 |
| TUA-02 | Agent flusher → server end-to-end | integration | `pytest tests/integration/test_audit_flush_e2e.py -x` | ❌ Wave 0 |
| TUA-03 | /audit page renders with filters | integration | `pytest tests/integration/test_audit_page.py -x` | ❌ Wave 0 |
| TUA-03 | /_partials/audit/timeline returns 24 buckets | integration | `pytest tests/integration/test_audit_timeline_partial.py -x` | ❌ Wave 0 |
| TUA-03 | All v0.1 tests still pass | regression | `pytest tests/` | ✅ Existing |

### Sampling Rate
- **Per task commit:** `pytest -x tests/unit/test_audit_*.py`  (~1s)
- **Per wave merge:** `pytest tests/`  (full 185 + new ≈ 205 tests)
- **Phase gate:** full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/unit/test_audit_fingerprint.py` — covers TUA-01 fingerprint algorithm
- [ ] `tests/unit/test_audit_buffer.py` — covers TUA-01 buffering + concurrency
- [ ] `tests/unit/test_audit_flusher.py` — covers TUA-02 flush logic
- [ ] `tests/integration/test_audit_api.py` — covers TUA-02 server endpoint
- [ ] `tests/integration/test_audit_flush_e2e.py` — covers TUA-02 agent→server full path (uses `_patch_httpx_to_testclient`)
- [ ] `tests/integration/test_audit_page.py` — covers TUA-03 page rendering
- [ ] `tests/integration/test_audit_timeline_partial.py` — covers TUA-03 timeline endpoint
- [ ] Helper fixture for `tmp_path/audit_buffer.db` (small `conftest.py` addition)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Reuse existing `X-CCGuard-Token` (sha256-hashed in DB) for `POST /api/v1/audit`. Reuse cookie-session + CSRF for `/audit` admin page (read-only, but auth required). |
| V3 Session Management | yes | Existing `require_session` cookie dep already covers /audit. |
| V4 Access Control | yes | New `/audit` requires admin session. New `/api/v1/audit` requires valid token. **No new roles introduced.** |
| V5 Input Validation | yes | Pydantic v2 `AuditBatchIn` validates schema_version, machine_id, event fields, decision/result_status Literal enums. Batch size capped at 200 (413 on overflow). |
| V6 Cryptography | no (passive) | Fingerprint uses sha256 (stdlib); not used as a security boundary — privacy property comes from absence of raw input, not from hash strength. |
| V7 Error Handling | yes | Hook MUST fail-open; never crash the user's Claude Code session. Catch-all `try/except` around hook entrypoint. Same pattern as `enforce.py`. |
| V8 Data Protection | yes | No raw `tool_input` ever crosses agent→server boundary. Documented in API schema docstring. Buffer DB has 0600 file mode (extend `agent/config.py` chmod pattern). |
| V9 Communication | yes | HTTPS recommended in deploy doc (already covered in v0.1 docker compose). |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Hook DoS via flood of tool calls (10k+/min) | Denial of Service | Backpressure: 10k cap in buffer with drop-oldest; flusher rate limited by 200/batch + retry backoff. Server can return 429 (not implemented in v0.2; add to v0.3 if real fleet hits it). |
| Token replay against `/api/v1/audit` from outside the fleet | Spoofing | Reuses v0.1 token model (per-machine token, sha256-hashed at rest). Rotate via Settings UI. |
| Forged `machine_id` in batch payload | Tampering | Server logs `received_at` plus the actual `X-CCGuard-Token` association; admin can detect mismatched machine_id↔token. **Note:** v0.2 doesn't pin tokens to machine_id — that's a known v0.3 hardening. Document as known limitation. |
| Buffer DB path traversal | Tampering | `default_config_dir()` is resolved before buffer construction; never accepts user input. |
| SQL injection via filter params on `/audit` | Tampering | Pydantic + parameterized SQL (`session.exec(text(sql), params={...})`). The example in this doc already uses bind params. |
| Privacy leak via fingerprint rainbow table | Information Disclosure | Documented design choice: fingerprint is a non-secret grouping ID; privacy comes from not storing input, not from fingerprint obscurity. (See Pitfall 5.) |
| Timing side-channel on token comparison | Information Disclosure | `require_token` already uses constant-time compare (verify in `token_service.is_token_valid`). |

## Sources

### Primary (HIGH confidence)
- Project codebase (read directly):
  - `src/ccguard/server/db/models.py` — existing SQLModel patterns
  - `src/ccguard/server/api/{inventory,findings,deps}.py` — router + auth pattern
  - `src/ccguard/agent/{enforce,install,sync,audit,config}.py` — agent CLI pattern, settings.json manipulation, sync HTTP pattern
  - `src/ccguard/server/web/{routes.py, templates/*.html}` — Jinja + HTMX patterns
  - `src/ccguard/schemas/{audit,enforce,sync,_base}.py` — Pydantic v2 SchemaBase
  - `tests/integration/conftest.py` and `test_agent_sync.py` — `client` fixture + `_patch_httpx_to_testclient`
  - `pyproject.toml` — locked deps
- `.planning/PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `01-CONTEXT.md`, `01-UI-SPEC.md` — locked decisions

### Secondary (MEDIUM confidence)
- [Claude Code Hooks Reference](https://code.claude.com/docs/en/hooks) — PostToolUse stdin schema, exit codes, settings.json structure
- [Claude Code Hooks Complete Guide (claudefa.st)](https://claudefa.st/blog/tools/hooks/hooks-guide) — corroborating stdin/JSON output formats
- [ClaudeLog Hooks Mechanics](https://claudelog.com/mechanics/hooks/) — additional examples
- [SQLite Concurrent Writes and "database is locked"](https://tenthousandmeters.com/blog/sqlite-concurrent-writes-and-database-is-locked-errors/) — WAL + busy_timeout guidance
- [Concurrent Writing with SQLite3 in Python](https://www.pythontutorials.net/blog/concurrent-writing-with-sqlite3/) — BEGIN IMMEDIATE + short tx pattern
- [Going Fast with SQLite and Python (Charles Leifer)](https://charlesleifer.com/blog/going-fast-with-sqlite-and-python/) — PRAGMA tuning

### Tertiary (LOW confidence)
- None — every architectural decision is anchored in either the existing codebase or official docs.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in pyproject.toml; no new packages.
- Architecture: HIGH — every pattern (router, auth, Jinja, HTMX poll) has a direct precedent in v0.1.
- Pitfalls: MEDIUM-HIGH — SQLite WAL behaviour well-documented; hook lifecycle edge cases anchored in Claude Code docs.
- PostToolUse schema: MEDIUM — sourced from official docs but not Context7-verified; Pydantic `extra="ignore"` makes it forgiving.
- Migration mechanism (Alembic vs create_all): explicit open question — needs user confirmation.

**Research date:** 2026-05-25
**Valid until:** 2026-06-25 (30 days — Claude Code hook protocol is moderately stable; verify before re-use after that)
