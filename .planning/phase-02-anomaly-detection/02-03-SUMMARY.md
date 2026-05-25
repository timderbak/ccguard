---
phase: 02-anomaly-detection
plan: 03
subsystem: anomaly-detection
tags: [apscheduler, asyncio, fastapi, sqlite, 3sigma, idempotent]

requires:
  - phase: 02-anomaly-detection/01
    provides: MachineBaseline model + nullable FindingRecord.inventory_id
  - phase: 02-anomaly-detection/02
    provides: metric_aggregators + baseline_service.compute_baseline/upsert
provides:
  - anomaly_service.tick() — single autonomous entry point for the anomaly sweep
  - anomaly_service.evaluate_one() — per (machine, metric) evaluation primitive
  - APScheduler (AsyncIOScheduler) embedded in FastAPI lifespan
  - CCGUARD_DISABLE_SCHEDULER env-guard for tests
  - Locked rule_id format `anomaly.<metric>` with severity=warn / inventory_id=NULL
affects: [02-04 findings-page, 02-05 matrix-ui, 02-06 phase-closure]

tech-stack:
  added: ["apscheduler>=3.10,<4"]
  patterns:
    - "Service-layer same-day dedup via func.date(discovered_at)==today (no DB UNIQUE)"
    - "Lifespan-managed background scheduler with env-guarded boot"
    - "Single Session per tick, commit per finding insert"
    - "Per-(machine,metric) try/except: errors recorded, sweep continues"

key-files:
  created:
    - src/ccguard/server/scheduler.py
    - src/ccguard/server/services/anomaly_service.py
    - tests/unit/test_anomaly_service.py
  modified:
    - pyproject.toml
    - src/ccguard/server/main.py
    - tests/conftest.py

key-decisions:
  - "Service-layer same-day dedup, NOT a DB UNIQUE constraint (per RESEARCH)"
  - "Degenerate stdev=0 fires only on the high side (latest > mean)"
  - "Single Session across the whole tick; commit per finding insert"
  - "Scheduler coalesce=True, max_instances=1 (sleeping host safety)"
  - "First tick at now+30s (dev visibility), hourly interval thereafter"
  - "Env-guard CCGUARD_DISABLE_SCHEDULER set at conftest module top (before app import)"

patterns-established:
  - "Pattern: aggregator dispatch table (_DISPATCH) mutable at module scope → testable via patch.dict"
  - "Pattern: scheduler job wraps tick() in try/except + logger.exception (never kills loop)"

requirements-completed: [ANO-01, ANO-02]

duration: ~20min
completed: 2026-05-25
---

# Phase 02 Plan 03: Anomaly Scheduler + tick() Summary

**APScheduler-driven hourly anomaly sweep with service-layer same-day dedup, 3σ outlier detection over 14-day rolling baselines, and per-machine fault isolation.**

## Performance

- **Duration:** ~20 min
- **Tasks:** 3 (one TDD: RED → GREEN)
- **Files created:** 3
- **Files modified:** 3
- **Tests added:** 14 (all passing)
- **Full suite:** 408 passed (unit + integration), no regressions

## Accomplishments

- `anomaly_service.tick(session)` — iterates every Machine × every locked metric, upserts baselines, emits findings idempotently.
- `evaluate_one()` enforces the locked contract: warm-up suppression, 3σ threshold, degenerate stdev guard (positive-only), same-day dedup at the service layer.
- FastAPI lifespan registers an `AsyncIOScheduler(timezone="UTC")` with `IntervalTrigger(hours=1)`, first tick at `now+30s`, `coalesce=True`, `max_instances=1`.
- `CCGUARD_DISABLE_SCHEDULER=1` set unconditionally in `tests/conftest.py` BEFORE any FastAPI import — TestClient never boots the scheduler thread.
- apscheduler `>=3.10,<4` pinned (NOT 4.x alpha); installed via `uv sync --extra dev`.

## Task Commits

1. **Task 1: apscheduler dep + scheduler module + conftest env-guard** — `f59f296` (feat)
2. **Task 2 RED: failing tests for tick + evaluate_one** — `a67d6d7` (test)
3. **Task 2 GREEN: anomaly_service.tick implementation** — `deb66f6` (feat)
4. **Task 3: lifespan integration** — `dff19c8` (feat)

## Files Created/Modified

- `src/ccguard/server/scheduler.py` — `build_scheduler / start_scheduler / shutdown_scheduler / is_disabled` helpers.
- `src/ccguard/server/services/anomaly_service.py` — `tick`, `evaluate_one`, `_DISPATCH`, `_is_outlier`, `_same_day_finding_exists`.
- `tests/unit/test_anomaly_service.py` — 14 tests covering warm-up, 3σ, dedup, degenerate stdev, payload fields, multi-machine sweep, error tolerance, idempotence, different-day re-emission.
- `pyproject.toml` — added `"apscheduler>=3.10,<4"`.
- `src/ccguard/server/main.py` — lifespan startup spins up the scheduler (unless `is_disabled()`), stores it on `app.state.scheduler`, shuts down via `try/finally`.
- `tests/conftest.py` — sets `CCGUARD_DISABLE_SCHEDULER=1` at module top before any other import.

## Decisions Made

- **Service-layer dedup over DB UNIQUE** (RESEARCH-locked). The dedup query uses SQLite-compatible `func.date(FindingRecord.discovered_at) == today_utc_date_iso`. Tradeoff: relies on the service path being the only writer of anomaly findings — acceptable because the FastAPI scheduler is the only producer.
- **Single Session per tick.** Simpler and matches existing service idioms; `baseline_service.upsert_baseline` already commits, and we commit again after each `FindingRecord.add`. The session is rolled back if a per-metric evaluation raises, so subsequent metrics see a clean session.
- **Degenerate stdev=0 fires only on the high side.** A flat baseline collapsing to zero is operationally a "machine went quiet" event (not an attacker signal) — we only alarm when activity spikes from a flat history.
- **APScheduler config:** `coalesce=True` + `max_instances=1` so a sleeping or slow host collapses missed runs and never overlaps ticks. `shutdown(wait=False)` on lifespan exit so FastAPI shutdown is never blocked on a long-running tick.
- **Logging of the tick:** the lifespan-registered `_tick_job` wraps `tick()` in try/except and logs `summary["machines_evaluated"] / findings_emitted / len(errors)` at info level.

## Deviations from Plan

None — all three tasks executed exactly as specified.

Minor judgement calls (within plan latitude):
- Defined `_is_outlier` and `_sigma_distance` as private helpers (cleaner than inlining); both are still covered by the public-API tests.
- Added `SIGMA_THRESHOLD = 3.0` constant in `anomaly_service.py` for readability (rather than literal `3`).
- The RED commit landed 14 tests rather than the minimum 10 in the plan, because the warm-up + same-day dedup + different-day re-emit + payload-contract paths each warrant a dedicated test.

**Total deviations:** 0
**Impact on plan:** None.

## Issues Encountered

- Initial `uv sync` (without `--extra dev`) removed dev deps; resolved with `uv sync --extra dev`. No effect on shipped code.
- `TestClient(app).get('/health')` worked once I used the correct route (`/health`, not `/api/v1/health`). Plan verifier had an outdated path; updated locally during verification only.

## Next Plan Readiness

- 02-04 (findings page) can rely on `rule_id` prefix `anomaly.` and the payload contract documented in `evaluate_one` (observed_value / mean / stdev / sigma_distance / metric / sample_count).
- 02-05 (matrix UI) can read `MachineBaseline.recent_points_json` written during tick for sparklines.
- 02-06 (phase closure) — Phase 1 tests stay green (408/408 unit+integration), `apscheduler` is the only new runtime dep, `CCGUARD_DISABLE_SCHEDULER` is the only new env var.

## Self-Check: PASSED

- `src/ccguard/server/scheduler.py` — FOUND
- `src/ccguard/server/services/anomaly_service.py` — FOUND
- `tests/unit/test_anomaly_service.py` — FOUND
- Commits f59f296, a67d6d7, deb66f6, dff19c8 — all present in `git log`
- `python -c "import apscheduler; assert apscheduler.__version__.startswith('3.')"` — passes (3.11.2)
- `grep -c CCGUARD_DISABLE_SCHEDULER tests/conftest.py` — 1
- `grep -c '"apscheduler' pyproject.toml` — 1

---
*Phase: 02-anomaly-detection*
*Completed: 2026-05-25*
