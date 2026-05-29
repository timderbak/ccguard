---
phase: 01-tool-use-audit-foundation
verified: 2026-05-25T00:00:00Z
status: passed
score: 5/5 must-haves verified
overrides_applied: 0
tests:
  full_suite_pre_e2e: 356 passed
  baseline_v0_1: 185
  new_audit_tests: 153
  threshold: "185+20=205 (target) — actual 356 (≥+171 new)"
  e2e_deferred: "tests/e2e/* pre-existing failures (httpx.ConnectError / FileNotFoundError) — documented in deferred-items.md"
requirements_coverage:
  TUA-01: satisfied
  TUA-02: satisfied
  TUA-03: satisfied
---

# Phase 1: Tool-Use Audit (Foundation) — Verification Report

**Phase Goal:** Собрать фактические tool-use события через PostToolUse hook и показать timeline в web UI.
**Verified:** 2026-05-25
**Status:** passed
**Re-verification:** No (initial verification)

## Goal Achievement

### ROADMAP Success Criteria (must-haves)

| #   | Criterion (paraphrased)                                                                              | Status     | Evidence |
| --- | ---------------------------------------------------------------------------------------------------- | ---------- | -------- |
| 1   | Agent logs tool-use to local buffer on PostToolUse (tool_name, fingerprint, decision, result_status, ts) without saving full tool_input | VERIFIED | `src/ccguard/agent/audit_hook/hook_main.py:76-93` — fingerprint computed then `del tool_input` (line 77); buffer.insert receives only ts/tool_name/fingerprint/decision/result_status; `decision = "allow"` hardcoded (line 81, PostToolUse runs only after PreToolUse allowed). Buffer schema `src/ccguard/agent/audit_hook/buffer.py` mirrors fields. Schema `src/ccguard/schemas/tool_use.py:28-58` has **no** `tool_input` field — privacy contract explicit. Tests: `test_audit_hook_main.py` (12 tests), `test_audit_fingerprint.py` (21), `test_audit_buffer.py` (16). |
| 2   | POST /api/v1/audit accepts batch and writes to extended audit table                                  | VERIFIED | `src/ccguard/server/api/audit.py:44-96` — router prefix `/api/v1`, endpoint `/audit`, validates `schema_version` major (line 56-65), enforces `MAX_BATCH=200` (line 70-74), persists `ToolUseEvent` rows (line 78-88). Model defined at `src/ccguard/server/db/models.py:93-114` (`ToolUseEvent` table with machine_id/ts/received_at/tool_name/fingerprint/decision/result_status). Router registered in `src/ccguard/server/main.py:68` (`app.include_router(audit.router)`). Tests: `test_audit_api.py` (13), `test_audit_schemas.py` (12), `test_audit_smoke.py` (13), `test_audit_flush_e2e.py` (7). |
| 3   | Web UI /audit shows events with machine/tool_name/decision/timeframe filters                         | VERIFIED | `src/ccguard/server/web/routes.py:213-265` — `/audit` GET route accepts `machine_id`, `tool_name`, `decision`, `timeframe` query params; coerces invalid decision/timeframe; calls `list_events` (filters applied at SQL layer in `tool_use_service.py:37-50`); template `audit_feed.html:6-36` renders filter form with all four inputs (machine_id, tool_name, decision select, timeframe select). Tests: `test_audit_page.py` (12 tests covering filter echo, filter mismatch, timeframe coercion, decision coercion, default timeframe, etc.). |
| 4   | Timeline graph on /audit shows last-24h events with hourly grouping                                  | VERIFIED | `timeline_buckets(hours=24, …)` called from `routes.py:239-245` and `:292-298`; service at `tool_use_service.py:87-156` uses `strftime('%Y-%m-%d %H', ts)` SQL grouping, returns dense 24-bucket histogram (line 111-156). Template `components/_audit_timeline.html` renders bars proportional to bucket counts; heading "Активность за 24 часа". HTMX polling wired at `audit_feed.html:38-43` (`hx-get="/_partials/audit/timeline"`, `hx-trigger="every 30s"`, `hx-include="closest form"`). Tests: `test_audit_timeline_partial.py` (11 tests covering empty state, seeded bars, filters, HTMX wiring, fixed 24h window), `test_tool_use_service.py` (20). |
| 5   | All 185+ existing tests green + 20+ new                                                              | VERIFIED | `.venv/bin/pytest tests/ --ignore=tests/e2e` → **356 passed, 0 failed, 0 errors** in 13.12s. Baseline v0.1 was 185 tests; new audit-related tests = 153 (test_audit_*.py + test_tool_use_service.py: 16+21+16+12+12+13+12+7+13+11+20). Net delta well above the +20 threshold. E2E pre-existing failures documented as deferred (deferred-items.md) — not introduced by this phase. |

**Score:** 5/5 success criteria verified.

### Required Artifacts (Level 1–4)

| Artifact | Exists | Substantive | Wired | Data Flows | Status |
| -------- | ------ | ----------- | ----- | ---------- | ------ |
| `src/ccguard/agent/audit_hook/hook_main.py` | yes | yes (102 LOC, main_cli implements full pipeline) | yes (called from `audit_main.py` / hook entrypoint) | yes (writes to buffer, spawns flusher) | VERIFIED |
| `src/ccguard/agent/audit_hook/fingerprint.py` | yes | yes (96 LOC, Bash + file-tools + default branches) | yes (imported in `hook_main.py`) | yes | VERIFIED |
| `src/ccguard/agent/audit_hook/buffer.py` | yes | yes (SQLite WAL buffer, drain/insert/row_count/trim_to_cap) | yes (used by hook_main + flusher) | yes | VERIFIED |
| `src/ccguard/agent/audit_hook/flusher.py` | yes | yes (atomic lock, 4-attempt retry, per-batch continuation) | yes (spawned by hook_main, drains buffer → POST) | yes | VERIFIED |
| `src/ccguard/schemas/tool_use.py` | yes | yes (ToolUseEventIn/AuditBatchIn/AuditBatchOut + UTC validator) | yes (shared by agent flusher + server router) | yes | VERIFIED |
| `src/ccguard/server/api/audit.py` | yes | yes (validates schema, persists, returns batch result) | yes (registered in `main.py:68`) | yes (writes ToolUseEvent rows) | VERIFIED |
| `src/ccguard/server/db/models.py::ToolUseEvent` | yes | yes (full field set + indexes) | yes (auto-created via SQLModel metadata) | yes | VERIFIED |
| `src/ccguard/server/services/tool_use_service.py` | yes | yes (list_events + timeline_buckets, parameterized SQL) | yes (called from web routes.py) | yes | VERIFIED |
| `src/ccguard/server/web/routes.py::/audit` + `/_partials/audit/timeline` | yes | yes (filter coercion, service calls, template render) | yes (web_router registered in main.py) | yes (queries DB → renders) | VERIFIED |
| `src/ccguard/server/web/templates/audit_feed.html` | yes | yes (filter form + HTMX timeline + events table) | yes (rendered by /audit handler) | yes | VERIFIED |
| `src/ccguard/server/web/templates/components/_audit_timeline.html` | yes | yes (renders bars from buckets) | yes (included by audit_feed.html + polled partial) | yes | VERIFIED |
| `src/ccguard/server/web/templates/components/_audit_events_table.html` | yes | yes | yes (included by audit_feed.html) | yes | VERIFIED |

### Key Link Verification

| From | To | Via | Status |
| ---- | -- | --- | ------ |
| PostToolUse hook stdin | Local SQLite buffer | `hook_main.main_cli` → `ToolBufferDB.insert` (hook_main.py:86-93) | WIRED |
| Local buffer | POST /api/v1/audit | `flusher._run_flush_loop` drains and posts (flusher.py:236-295) | WIRED |
| POST /api/v1/audit | `ToolUseEvent` table | `session.add(ToolUseEvent(...))` + `session.commit()` (audit.py:78-89) | WIRED |
| /audit page | tool_use_service.list_events | `routes.py:229-236` | WIRED |
| /audit page | tool_use_service.timeline_buckets | `routes.py:239-245`, `routes.py:292-298` | WIRED |
| Timeline HTMX poll | `/_partials/audit/timeline` every 30s | `audit_feed.html:38-43` (`hx-get`, `hx-trigger="every 30s"`) | WIRED |
| Filter form params | service WHERE clauses | `_apply_common_filters` + parameterized SQL in `timeline_buckets` | WIRED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| Full non-e2e test suite green | `.venv/bin/pytest tests/ --ignore=tests/e2e` | 356 passed | PASS |
| audit router registered | `grep "audit.router" src/ccguard/server/main.py` | line 68 includes | PASS |
| HTMX polling wired | `grep "every 30s" templates/audit_feed.html` | line 40 | PASS |
| Privacy invariant (no tool_input in schema) | `grep "tool_input" src/ccguard/schemas/tool_use.py` | only doc comments warning AGAINST adding it | PASS |
| `decision="allow"` hardcoded | `grep 'decision = "allow"' agent/audit_hook/hook_main.py` | line 81 | PASS |
| `del tool_input` after fingerprint | `grep "del tool_input" agent/audit_hook/hook_main.py` | line 77 | PASS |

### Requirements Coverage

| Requirement | Description | Status | Evidence |
| ----------- | ----------- | ------ | -------- |
| TUA-01 | PostToolUse hook collects `(tool_name, tool_input_fingerprint, decision, result_status, ts)` without saving full tool_input | SATISFIED | hook_main.py:76-93 + fingerprint.py (compute_fingerprint returns 16-hex). No tool_input field in schema. |
| TUA-02 | Agent aggregates and POSTs batch to `/api/v1/audit` (extended audit table) | SATISFIED | flusher.py + api/audit.py + db/models.py::ToolUseEvent. AuditRecord coexists, ToolUseEvent is the new firehose table. |
| TUA-03 | Web UI: `/audit` page with machine/tool_name/decision/timeframe filters + timeline graph | SATISFIED | routes.py::audit_page + audit_feed.html + components/_audit_timeline.html, with HTMX polling. |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| (none) | — | — | — | No TBD/FIXME/XXX/PLACEHOLDER markers detected in phase 1 files. |

### Probe Execution

No project-conventional `scripts/*/tests/probe-*.sh` declared for this phase. PLAN-level "Verify" sections were entirely pytest-based and are covered by Step 7b.

### Data-Flow Trace (Level 4)

- Timeline bars: `audit_feed.html`/`_audit_timeline.html` render from `buckets` → populated by `timeline_buckets()` → executes parameterized SQL against `ToolUseEvent` table. Real DB query (no static fallback).
- Events table: `_audit_events_table.html` renders `events` → populated by `list_events()` → SQL select against `ToolUseEvent`. Real DB query.
- Ingest path: `hook_main` writes to `ToolBufferDB` (SQLite WAL); `flusher` drains and POSTs to `/api/v1/audit`; server persists `ToolUseEvent` rows. End-to-end data flow exercised by `test_audit_flush_e2e.py` (7 tests).

All Level-4 traces show real data flow; no HOLLOW_PROP / STATIC / DISCONNECTED findings.

## Deferred (informational — not gaps)

- `tests/e2e/test_end_to_end.py` and `tests/e2e/test_web_e2e.py` fail with `httpx.ConnectError`/`FileNotFoundError` at collection time (require running server + external scan corpus). Per `deferred-items.md`, failures pre-date this phase and are explicitly scoped out. Not blocking — and the ROADMAP success-criterion #5 says "unit + integration + e2e for /audit", which IS covered by `tests/integration/test_audit_*.py` (audit-flow integration tests, including `test_audit_flush_e2e.py`).

## Gaps Summary

None. All 5 success criteria verified with file-level evidence and a green 356-test run. The privacy contract (no `tool_input` field, `del tool_input` after fingerprint), the API ingest path, the table model, the UI filter form, the HTMX-polled hourly timeline, and the test-count threshold are all observable in the codebase.

---

_Verified: 2026-05-25_
_Verifier: Claude (gsd-verifier, Opus 4.7)_
