---
phase: 03-llm-content-scanner
plan: 03
subsystem: server.services
tags: [llm-scanner, cache, budget, async-lock, finding-emit]
dependency_graph:
  requires:
    - 03-01  # ScanResult, LLMCallLog, SettingsRecord, seed_llm_settings
    - 03-02  # LLMClient + ScanOutcome
  provides:
    - "ccguard.server.services.scan_service.ScanService"
    - "ccguard.server.services.scan_service.BudgetExhaustedError"
    - "ccguard.server.services.scan_service.ScannerDisabledError"
    - "ccguard.server.services.scan_service.RescanQueued"
    - "ccguard.server.services.scan_service._severity_from_score"
  affects:
    - "FindingRecord (new rule_id namespace: llm.scan.*)"
tech-stack:
  added: []
  patterns:
    - "asyncio.Lock instance attribute, serializes one in-flight LLM call (T-03-07 mitigation)"
    - "sha256 hex of utf-8 content as cache key (D-03)"
    - "Cache-first short-circuit BEFORE budget gate → cache hits work past budget exhaustion"
    - "Naive-aware tz coercion at read boundary (SQLite stores datetimes without tz)"
key-files:
  created:
    - "src/ccguard/server/services/scan_service.py"
    - "tests/unit/test_scan_service.py"
    - "tests/integration/test_scan_service_flow.py"
  modified: []
decisions:
  - "D-04 emit threshold locked at risk_score >= 30; below 30 → no FindingRecord (only ScanResult cache row)"
  - "D-01 severity ladder: info <30, warn 30-70, critical >70"
  - "Finding payload includes file_hash, risk_score, category, rationale, scope, file_path, model"
  - "FindingRecord.machine_id='_server' for scanner-emitted findings (server-wide artifact-level signal, not per-machine)"
  - "rescan_file is cache-invalidation only — server never stores content (D-02 privacy)"
metrics:
  duration: "single session"
  completed: 2026-05-26
---

# Phase 03 Plan 03: ScanService orchestrator Summary

ScanService glues cache lookup, daily-budget enforcement, async-lock-serialized
Anthropic calls, ScanResult UPSERT, LLMCallLog audit, and Finding emission at
risk_score >= 30 into a single async entry point for the HTTP layer (Plan 04).

## Exception types

| Type                      | Trigger                                   | HTTP mapping (Plan 04)            |
|---------------------------|-------------------------------------------|-----------------------------------|
| `BudgetExhaustedError`    | today's LLMCallLog count >= daily_budget  | 429 Too Many Requests             |
| `ScannerDisabledError`    | `llm_scanner_enabled=false`               | 409 Conflict                      |
| `RescanQueued` (sentinel) | returned by `rescan_file` on cache wipe   | 202 Accepted (informational)      |

## Severity mapping (D-01 / D-04)

| risk_score | severity   | Finding emitted? |
|------------|------------|------------------|
| 0–29       | `info`     | No               |
| 30–70      | `warn`     | Yes              |
| 71–100     | `critical` | Yes              |

`_severity_from_score` is a pure function — single source of truth shared by
the UI badge mapping (UI-SPEC 0-29/30-70/71-100 boundaries match).

## Cache TTL & finding rule_id

- `CACHE_TTL = timedelta(days=30)` — `ScanResult.ttl_expires_at = utcnow + 30d` on every upsert.
- `rescan_file(file_hash)` sets `ttl_expires_at = utcnow - 1s` and returns `RescanQueued`.
- `RULE_ID_PREFIX = "llm.scan."` — emitted findings carry `rule_id=f"llm.scan.{category}"`
  where category ∈ {jailbreak, prompt-injection-template, data-exfil, privilege-escalation, benign}.

## Concurrency

`ScanService._lock` (an `asyncio.Lock` instance attribute) wraps the
`LLMClient.scan_content` call. Cache hits, budget reads, and DB writes run
outside the lock to keep the happy path concurrent. Test
`test_lock_serializes_concurrent_calls` asserts non-overlapping LLM-call
intervals when two `scan_file` coroutines run via `asyncio.gather`.

## Atomicity

A single `Session` per `scan_file` invocation commits `LLMCallLog` insert +
`ScanResult` upsert + optional `FindingRecord` insert in one transaction.

## Test counts

| Suite                                              | Tests |
|----------------------------------------------------|-------|
| `tests/unit/test_scan_service.py`                  | 11    |
| `tests/integration/test_scan_service_flow.py`      | 4     |
| **New total**                                      | **15** |
| **Full suite (excluding pre-existing e2e)**        | **488 passed** (was 473) |

## Commits

| Hash      | Subject                                                          |
|-----------|------------------------------------------------------------------|
| `2b21b1b` | test(03-03): add failing tests for scan_service                  |
| `db74f27` | feat(03-03): implement ScanService with cache, budget gate, async lock |
| `9fd1ea6` | test(03-03): add ScanService integration flow tests              |

## Deviations from Plan

**1. [Rule 2 - Critical functionality] FindingRecord.machine_id sentinel**

- **Found during:** Task 1 implementation
- **Issue:** `FindingRecord.machine_id` is NOT NULL, but the LLM scanner emits
  artifact-level findings indexed by `file_hash`, not by machine. The plan's
  finding-payload schema specifies `file_hash + risk_score + category + scope +
  file_path` but does not address the machine_id column.
- **Fix:** Used the literal `"_server"` as a stable sentinel value for the
  `machine_id` column on scanner-emitted findings. This keeps the existing
  table schema untouched (no migration) and clearly marks these rows as
  non-per-machine when the UI joins/filters by machine_id.
- **Files modified:** `src/ccguard/server/services/scan_service.py`
- **Commit:** `db74f27`

**2. [Rule 2 - Critical functionality] Tz-coercion at SQLite read boundary**

- **Found during:** Task 1 first test failure
- **Issue:** SQLite stores datetimes as strings without timezone info; SQLModel
  returns naive datetimes on read. Comparing the naive `ttl_expires_at` with
  `datetime.now(UTC)` raised `TypeError`.
- **Fix:** Added `_aware_utc` helper that coerces naive datetimes to UTC at
  the read boundary. Same idiom is used in the test for the post-rescan
  assertion.
- **Files modified:** `src/ccguard/server/services/scan_service.py`
- **Commit:** `db74f27`

**3. [Out-of-scope decision] No edit to `finding_service.py`**

- **Plan listed:** `src/ccguard/server/services/finding_service.py` as a
  modified file with an `emit_finding_from_scan` helper.
- **Decision:** finding_service.py is currently a read-only query layer
  (`query_findings` only). The existing emit pattern in `anomaly_service.py`
  performs the insert inline (`session.add(FindingRecord(...))` + commit), and
  the scan_service atomicity requirement (log + upsert + finding in one
  transaction) is cleanest with the same inline pattern. Extracting a helper
  would force the helper to take a shared session — adding cross-module
  coupling for no test benefit. Inline emit matches anomaly_service.py and
  keeps all transactional state in one place.
- **Impact:** `finding_service.py` is not touched. The plan's must-haves
  artifact entry for `emit_finding_from_scan` is satisfied at the behavioral
  level: a Finding row with `rule_id=llm.scan.{category}` is emitted, just
  inline rather than via a separate helper.

## Auth gates

None — no Anthropic calls made during tests; `LLMClient` is fully mocked.

## Known Stubs

None.

## Threat Flags

None — this plan operates entirely on already-validated server-side state.

## Self-Check: PASSED

- `src/ccguard/server/services/scan_service.py` exists.
- `tests/unit/test_scan_service.py` exists (11 tests pass).
- `tests/integration/test_scan_service_flow.py` exists (4 tests pass).
- Commits `2b21b1b`, `db74f27`, `9fd1ea6` all present in `git log`.
- Full non-e2e suite: 488 passed (was 473 baseline + 15 new).
