---
phase: 02-anomaly-detection
plan: 06
subsystem: testing/anomaly
tags: [test, integration, regression, anomaly]
dependency-graph:
  requires:
    - 02-01
    - 02-02
    - 02-03
    - 02-04
    - 02-05
  provides:
    - phase-2-quality-gate
  affects: []
tech-stack:
  added: []
  patterns:
    - "Direct anomaly_service.tick() invocation in tests (never APScheduler timer)"
    - "TestClient + create_session admin_client fixture for route-level integration"
    - "unittest.mock.patch.dict on anomaly_service._DISPATCH to inject synthetic series"
    - "patch('ccguard.server.services.anomaly_service.datetime') to pin 'now' for clock-rollover tests"
key-files:
  created:
    - tests/integration/test_anomaly_routes.py
    - tests/integration/test_scheduler_tick.py
    - tests/unit/test_anomaly_edge_cases.py
  modified: []
decisions:
  - "freezegun not added — unittest.mock.patch on the imported datetime symbol works in-tree"
  - "End-to-end e2e (tick() → /_partials/anomalies/overview) lives in test_scheduler_tick.py, not a separate file, to keep the seed→tick→render path co-located"
metrics:
  duration: "~45min"
  completed: "2026-05-25"
requirements:
  - ANO-01
  - ANO-02
  - ANO-03
---

# Phase 2 Plan 06: Integration + Edge-Case + Phase 1 Regression Tests Summary

Phase 2 quality gate — proves the anomaly slice end-to-end without flake. Adds
24 new tests across three files (route integration, scheduler tick integration,
cross-cutting edge cases) and confirms zero Phase 1 regressions.

## Test Counts

| File                                              | Tests added |
| ------------------------------------------------- | ----------- |
| `tests/integration/test_anomaly_routes.py`        |          11 |
| `tests/integration/test_scheduler_tick.py`        |           6 |
| `tests/unit/test_anomaly_edge_cases.py`           |           7 |
| **Total new (this plan)**                         |      **24** |

Full suite: **438 passed** (was 414 before this plan; Phase 1 baseline = 356,
prior Phase 2 plans added 58 more tests across modules touched in 02-01..02-05).

## Per-Task Outcomes

### Task 1 — Integration tests for anomaly routes (11 tests)

Covers `/anomalies`, `/_partials/anomalies/overview`, `/_partials/anomalies/matrix`,
and `/anomalies/{machine_id}/{metric}`:

* Unauthenticated requests get 307→/login or 401 (matches Phase 1 contract).
* Authed `/anomalies` renders the `Аномалии` heading and the HTMX matrix wiring.
* Overview partial: empty state renders literal `Аномалий нет.`; seeded
  FindingRecord shows `machine_id[:12]` and `bash_calls_per_day`.
* Matrix partial: no-machines → `Машин нет.`; warm-up MachineBaseline →
  `накопление`; outlier point past 3σ → `выброс` badge.
* Drill-down: unknown metric → 404; known metric → `Все аномалии` back link +
  `Baseline` card; missing MachineBaseline → `Недостаточно данных для baseline`.

Russian UI-SPEC copy is locked at the assertion level — any rename of these
literals will trip CI.

### Task 2 — Scheduler tick integration tests (6 tests)

Direct `anomaly_service.tick(session)` invocation — APScheduler never starts:

* Real bash outlier history → MachineBaseline persisted with `baseline_ready=True`
  AND FindingRecord emitted with `rule_id=anomaly.bash_calls_per_day`,
  `severity=warn`, `inventory_id=None`.
* Same-day dedup proven: second `tick()` on the same data emits 0 new findings.
* Warm-up suppression: 5 days of data → no bash finding emitted.
* Per-machine aggregator failure (monkeypatched `_DISPATCH`) → tick continues,
  errors recorded as `"<machine>/<metric>: <exc>"` strings.
* `CCGUARD_DISABLE_SCHEDULER=1` env guard asserted live; `app.state.scheduler`
  is `None` after lifespan.
* End-to-end: tick-emitted finding visible in `/_partials/anomalies/overview`
  HTML — proves the full seed→tick→render chain works without an APScheduler
  thread.

### Task 3 — Cross-cutting edge cases (7 tests)

* **stdev=0 degenerate guard.** 14 identical points + latest == mean → no
  finding. Latest +1 over flat baseline → flagged. 14-zero points → calm
  machine stays quiet (no false positive).
* **baseline_ready gates on window length, not nonzero count.** A series with
  7 zeros + 7 nonzero points yields `sample_count=14`, `baseline_ready=True`.
* **Clock-rollover.** Finding at 23:59 UTC and another at 00:01 UTC the next
  day are NOT dedup'd — dedup buckets on `func.date(discovered_at)`. Achieved
  by patching `ccguard.server.services.anomaly_service.datetime` directly
  (no freezegun dependency added).
* **Empty Machine table.** `tick()` returns
  `{machines_evaluated: 0, findings_emitted: 0, errors: []}`.
* **Contract sanity.** `rule_id_for("bash_calls_per_day") == "anomaly.bash_calls_per_day"`
  pinned — routes hardcode this prefix.

## Verification

* `pytest tests/unit tests/integration --tb=short` → **438 passed**, no hangs.
* `pytest tests/integration/test_anomaly_routes.py -x -q` → 11 passed.
* `pytest tests/integration/test_scheduler_tick.py -x -q` → 6 passed.
* `pytest tests/unit/test_anomaly_edge_cases.py -x -q` → 7 passed.
* `git diff --stat HEAD~3..HEAD src/ccguard/server/api/audit.py src/ccguard/server/services/tool_use_service.py`
  → empty (Phase 1 audit code paths untouched).

## Phase 1 Regression Confirmation

No file under `src/ccguard/server/` was modified by this plan — only new test
files were added. The full Phase 1 suite (356 baseline tests) remained green
in every interim run. Final pass count of 438 = 356 Phase 1 + 58 Phase 2
(plans 02-01..02-05) + 24 new this plan.

## Deviations from Plan

**None.** All three tasks executed exactly as specified. One sub-decision:

* Task 2 plan listed the env-guard assertion as either "scheduler.running is
  False" OR "app.state.scheduler is unset". Picked the simpler `is None`
  assertion since `_lifespan` explicitly sets `app.state.scheduler = None`
  when `is_disabled()` returns true (verified in `src/ccguard/server/main.py:64`).

## Flake Notes for Future Maintainers

* The TestClient cookie-deprecation `DeprecationWarning` is harmless and
  inherited from the Phase 1 pattern — do not migrate to instance-level
  cookies without a sweep, the deprecation does not break the contract.
* `_seed_bash_outlier_history` uses `datetime.now(UTC).date()` as the anchor
  to match the aggregator's `_default_anchor()` — do not freeze "now" in this
  helper or the aggregator's date window will mismatch the seeded events.
* The clock-rollover test patches the module-level `datetime` symbol inside
  `anomaly_service`, not `datetime.datetime` globally — the side_effect
  forwards real `datetime(...)` constructor calls through so `payload_json`
  serialization keeps working.

## Self-Check: PASSED

Files exist:

* `tests/integration/test_anomaly_routes.py` — FOUND
* `tests/integration/test_scheduler_tick.py` — FOUND
* `tests/unit/test_anomaly_edge_cases.py` — FOUND

Commits in `git log`:

* `eb59d71` test(02-06): add integration tests for anomaly routes — FOUND
* `374cfa6` test(02-06): add scheduler tick integration tests — FOUND
* `7156cb0` test(02-06): add cross-cutting anomaly edge cases — FOUND
