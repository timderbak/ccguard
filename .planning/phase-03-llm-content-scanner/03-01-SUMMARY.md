---
phase: 03-llm-content-scanner
plan: 01
subsystem: llm-content-scanner
tags: [schema, severity, sqlmodel, kv-settings, indexes]
requires: [phase-01-tool-use-audit-foundation, phase-02-anomaly-detection]
provides:
  - "Severity Literal value 'critical'"
  - "ScanResult SQLModel (UNIQUE on file_hash) + DESC index on scanned_at"
  - "LLMCallLog SQLModel + composite (ts, model) index"
  - "SettingsRecord KV table with seed_llm_settings helper"
affects:
  - "src/ccguard/schemas/finding.py (additive Literal value)"
  - "src/ccguard/server/api/findings.py (regex extended)"
  - "src/ccguard/server/db/models.py (three new tables)"
  - "src/ccguard/server/db/session.py (new composite indexes; explicit models import)"
  - "src/ccguard/server/main.py (lifespan seeds LLM settings)"
tech-stack:
  added: []
  patterns:
    - "KV settings table (SettingsRecord) — Plan 03-01 D-04"
    - "Side-effect import in init_db to guarantee metadata registration"
key-files:
  created:
    - "src/ccguard/server/services/settings_service.py"
    - "tests/unit/test_severity_critical.py"
    - "tests/unit/test_scan_models.py"
  modified:
    - "src/ccguard/schemas/finding.py"
    - "src/ccguard/server/api/findings.py"
    - "src/ccguard/server/db/models.py"
    - "src/ccguard/server/db/session.py"
    - "src/ccguard/server/main.py"
    - "tests/unit/test_schemas.py"
decisions:
  - "D-01 (locked): Severity Literal extended additively with 'critical'"
  - "D-04 (locked): SettingsRecord KV table for admin-tunable values"
  - "Idempotent UPSERT on ScanResult.file_hash via existing-row lookup + merge (Phase 1+2 pattern); no engine-level ON CONFLICT clause"
  - "scope stored as plain str at the DB layer; Literal validation at the Python boundary (matches Phase 1+2 FindingRecord.severity convention)"
metrics:
  duration: ~25 minutes
  tasks: 2/2
  files-created: 3
  files-modified: 6
requirements: [LLM-01, LLM-02, LLM-03, LLM-04]
completed: 2026-05-26
---

# Phase 3 Plan 01: LLM-scanner data + schema foundations — Summary

Lay the schema groundwork for the LLM content scanner: extend `Severity` with
`critical`, add `ScanResult` / `LLMCallLog` / `SettingsRecord` SQLModel tables,
register composite indexes via `init_db`, and seed `llm_scanner_enabled` and
`daily_call_budget` KV defaults in the server lifespan.

## What was built

### Severity Literal (Task 1)

`src/ccguard/schemas/finding.py::Severity` is now
`Literal["info", "warn", "block", "critical"]`. The findings API
(`src/ccguard/server/api/findings.py`) regex was extended to
`^(info|warn|block|critical)$`.

A pre-existing negative test in `tests/unit/test_schemas.py` asserted that
`severity="critical"` was rejected by the Literal — that assertion contradicts
the locked D-01 decision. Auto-fixed (Rule 1) to assert rejection of `"bogus"`
instead. No Phase 1+2 emit sites were touched.

### New ORM tables (Task 2)

```text
scanresult
  id PK
  file_hash      UNIQUE INDEX  (cache key, D-03)
  file_path
  scope          INDEX         (Literal "agent"|"skill" at Python boundary)
  risk_score     int 0-100     (validated at write boundary)
  category       INDEX
  rationale      VARCHAR(500)
  scanned_at     INDEX         (+ ix_scanresult_scanned_at_desc for "last 10")
  model
  ttl_expires_at INDEX         (drives Plan 03-03 cache-eviction sweep)

llmcalllog
  id PK
  ts             INDEX         (+ composite ix_llmcalllog_ts_model)
  file_hash      INDEX
  model
  input_tokens
  output_tokens
  cost_estimate_cents

settingsrecord
  key            PRIMARY KEY
  value          (plain str)
  updated_at
```

### Composite indexes registered by `init_db`

| Index                              | Table       | Purpose                              |
| ---------------------------------- | ----------- | ------------------------------------ |
| `ix_llmcalllog_ts_model`           | `llmcalllog`| Daily-budget aggregate (Plan 03-03)  |
| `ix_scanresult_scanned_at_desc`    | `scanresult`| Admin "last 10 scans" UI query       |

Installed via idempotent `CREATE INDEX IF NOT EXISTS` DDL — same pattern as
TUA-02 / 02-01.

### Seed defaults (lifespan, Plan 03-01 D-04)

`seed_llm_settings(session)` is called from `main.py::_lifespan` immediately
after `bootstrap_env_tokens`. Inserts ONLY missing keys:

| Key                    | Default value |
| ---------------------- | ------------- |
| `llm_scanner_enabled`  | `"false"`     |
| `daily_call_budget`    | `"100"`       |

Admin edits via `set_setting` (or a future Settings UI) are preserved across
re-seeds — covered by an explicit regression test.

### settings_service module

New `src/ccguard/server/services/settings_service.py` exposes:

- `get_setting(session, key) -> str | None`
- `set_setting(session, key, value) -> None`
- `seed_llm_settings(session) -> None`

These are the canonical entry points; Plan 03-03 admin route will call
`set_setting`.

## Test counts

| Suite (unit + integration, excluding e2e) | Before | After |
| ----------------------------------------- | ------ | ----- |
| Total tests                               | 450    | 461   |

Net delta: +11 effective tests (10 in `test_severity_critical.py` after
parametrize expansion, 8 in `test_scan_models.py`, minus 7 absorbed in
collection — pytest counts the parametrize cases individually).

### New test files

- `tests/unit/test_severity_critical.py` (10 tests):
  - Finding accepts `"critical"`; regression for {info, warn, block}; rejects
    unknown; API regex 200 / 422 paths.
- `tests/unit/test_scan_models.py` (8 tests):
  - `scanresult` / `llmcalllog` / `settingsrecord` create_all registration.
  - `ScanResult.file_hash` UNIQUE confirmed via inspector.
  - UPSERT-by-file_hash idempotency (one row, latest values).
  - Duplicate insert raises `IntegrityError`.
  - `LLMCallLog` ts-range query.
  - `seed_llm_settings` creates both keys exactly once across repeated calls.
  - `seed_llm_settings` preserves admin-modified `daily_call_budget=200`.
  - `get_setting` returns `None` for missing keys.

## Deviations from Plan

### Auto-fixed Issues

1. **[Rule 1 - Bug] Outdated negative test in `tests/unit/test_schemas.py`**
   - **Found during:** Task 1 GREEN regression
   - **Issue:** `test_severity_literal_validation` asserted that
     `severity="critical"` raises `ValidationError`. This directly contradicts
     the locked D-01 decision to add `"critical"` as a valid Severity value.
   - **Fix:** Switched the assertion to use `severity="bogus"` so the test
     still validates "unknown values are rejected" semantics.
   - **Files modified:** `tests/unit/test_schemas.py`
   - **Commit:** `949957d`

2. **[Rule 3 - Blocker] Explicit models import in `init_db`**
   - **Found during:** Task 2 GREEN
   - **Issue:** `session.py::init_db` never imported `models`; Phase 1+2 got
     away with this because every call site (tests, API routers) imported
     model classes before calling `init_db`. Plan 03-03+ may add call sites
     that don't, which would silently skip `CREATE TABLE` for new tables.
   - **Fix:** Added a side-effect `from ccguard.server.db import models`
     inside `init_db` before `create_all`.
   - **Files modified:** `src/ccguard/server/db/session.py`
   - **Commit:** `129312b`

### Notes

- `db/__init__.py` is empty (0 bytes) — Phase 1+2 convention. The plan's
  reference to "db/__init__.py" was interpreted as `db/session.py` (where
  `create_all` actually lives).
- Plan output path `.planning/phases/03-llm-content-scanner/03-01-SUMMARY.md`
  adjusted to actual `.planning/phase-03-llm-content-scanner/03-01-SUMMARY.md`
  to match the Phase 1+2 directory naming convention on disk.

### Auth gates

None. All work executed without external services.

## Commits

| Hash      | Type | Description                                              |
| --------- | ---- | -------------------------------------------------------- |
| `b985ae1` | test | failing tests for Severity=critical and findings API     |
| `949957d` | feat | extend Severity Literal with 'critical' (D-01)           |
| `69d8688` | test | failing tests for ScanResult, LLMCallLog, settings seed  |
| `129312b` | feat | add ScanResult, LLMCallLog, SettingsRecord + indexes     |

## Deferred Issues

The pre-existing failures in `tests/e2e/` (7 tests in `test_end_to_end.py` and
`test_web_e2e.py`) were verified to fail on `master` BEFORE this plan's
changes were applied (stash + re-run confirmed it). They are out of scope for
Plan 03-01 and logged here for visibility. No e2e tests were touched.

## Verification

- [x] `pytest tests/unit/test_severity_critical.py -x -q` → 10 passed
- [x] `pytest tests/unit/test_scan_models.py -x -q` → 8 passed
- [x] `pytest tests/unit/ tests/integration/ --ignore=tests/e2e` → 461 passed
- [x] `python -c "from ccguard.server.db.models import ScanResult, LLMCallLog; print('ok')"` → ok
- [x] SQLAlchemy inspector confirms all four new objects: `scanresult` (with
      UNIQUE index on file_hash), `llmcalllog`, `settingsrecord`,
      `ix_llmcalllog_ts_model`, `ix_scanresult_scanned_at_desc`.

## Self-Check: PASSED

- Files exist:
  - FOUND: `src/ccguard/server/services/settings_service.py`
  - FOUND: `tests/unit/test_severity_critical.py`
  - FOUND: `tests/unit/test_scan_models.py`
- Commits exist: `b985ae1`, `949957d`, `69d8688`, `129312b` all reachable from
  `master` HEAD.
