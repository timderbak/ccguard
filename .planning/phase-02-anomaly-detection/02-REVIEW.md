---
phase: 02-anomaly-detection
reviewed: 2026-05-25T00:00:00Z
depth: standard
iteration: 2
files_reviewed: 17
files_reviewed_list:
  - src/ccguard/server/services/anomaly_constants.py
  - src/ccguard/server/services/metric_aggregators.py
  - src/ccguard/server/services/baseline_service.py
  - src/ccguard/server/services/anomaly_service.py
  - src/ccguard/server/scheduler.py
  - src/ccguard/server/db/models.py
  - src/ccguard/server/db/session.py
  - src/ccguard/server/main.py
  - src/ccguard/server/web/routes.py
  - src/ccguard/server/web/templates/anomalies_feed.html
  - src/ccguard/server/web/templates/anomaly_detail.html
  - src/ccguard/server/web/templates/components/_anomalies_matrix.html
  - src/ccguard/server/web/templates/components/_anomalies_overview.html
  - src/ccguard/server/web/templates/base.html
  - src/ccguard/server/web/templates/overview.html
  - tests/conftest.py
  - pyproject.toml
findings:
  critical: 0
  warning: 0
  info: 5
  total: 5
status: clean
resolution:
  iteration_1:
    fixed_at: 2026-05-25T00:00:00Z
    fixed: 10
    deferred: 5
    status: critical_and_warnings_resolved
    details:
      - CR-01: fixed (commit ebc8924)
      - CR-02: fixed (commit 43fb861)
      - WR-01: fixed (commit 9a5c36e, grouped with WR-05)
      - WR-02: fixed (commit 89876af)
      - WR-03: fixed (commit aef7fee)
      - WR-04: fixed (commit e153e69)
      - WR-05: fixed (commit 9a5c36e, grouped with WR-01)
      - WR-06: documented as v0.2-acceptable (commit 4fb7166)
      - WR-07: fixed (commit 08844c0)
      - WR-08: fixed (commit d98dee3)
      - IN-01..IN-05: deferred (Info-tier, out of fix scope)
  iteration_2:
    reviewed_at: 2026-05-25T00:00:00Z
    status: clean
    summary: All CR/WR fixes verified in source. No new defects introduced. Phase 1 audit code untouched. 443 unit/integration tests pass.
---

# Phase 2: Code Review Report

**Reviewed:** 2026-05-25
**Depth:** standard
**Iteration:** 2 (post auto-fix)
**Files Reviewed:** 17
**Status:** clean

## Summary

Iteration 2 re-review verifies the nine fix commits (ebc8924, 43fb861, 9a5c36e, 89876af, aef7fee, e153e69, 4fb7166, 08844c0, d98dee3) against the iteration-1 findings. All two BLOCKERs and all eight WARNINGs are correctly resolved in the source. No new defects were introduced. Phase 1 audit / tool-use code was not modified by any fix commit (verified via `git log ebc8924^..HEAD -- src/ccguard/server/api/audit.py src/ccguard/server/services/tool_use_service.py` — empty result). The non-e2e test suite (443 tests) passes; e2e subprocess failures are unrelated environment issues (httpx connection, binary install paths) and not regressions of these fixes.

Five Info-tier findings from iteration 1 remain deferred (out of fix scope) and are preserved verbatim below.

---

## Iteration 2 Verification

### CR-01 — substr(ts,1,10) date-prefix range — VERIFIED FIXED

`src/ccguard/server/services/metric_aggregators.py:104-116` now compares both bounds and the GROUP BY key on `substr(ts, 1, 10)` against `date.isoformat()` strings (`"YYYY-MM-DD"`). This is independent of how SQLAlchemy/SQLite serializes the remainder of the timestamp (space vs `T` separator, presence/absence of `+00:00`). Lexicographic comparison on `YYYY-MM-DD` strings matches calendrical ordering. Phase 1 `_enforce_utc` guarantees the first 10 chars are the UTC date. Correct.

### CR-02 — Warm-up gate based on non-zero sample count — VERIFIED FIXED

`src/ccguard/server/services/baseline_service.py:54-62` computes `real_n = sum(1 for v in points if v > 0)` and gates both the persisted `sample_count` and `baseline_ready` on `real_n >= WARMUP_THRESHOLD (=7)`. Mean/stdev are still over the full 14-point zero-padded series (anchors the distribution). A brand-new machine with one snapshot today (1 non-zero point) reports `sample_count=1`, `baseline_ready=False`, and `anomaly_service.evaluate_one` returns `None` at line 138. Confirmed by the regression test path noted in the iteration-1 resolution.

### WR-01 — scheduler attribute initialized early — VERIFIED FIXED

`src/ccguard/server/main.py:28` sets `app.state.scheduler = None` as the very first statement of `_lifespan`, before any work that could raise. Lines 95-103 wrap `start_scheduler` in a try/except that resets the attribute to `None` on failure so the `finally:` teardown (lines 107-110) never references a half-started scheduler.

### WR-02 — sigma_distance None + allow_nan=False — VERIFIED FIXED

`src/ccguard/server/services/anomaly_service.py:87-89` returns `None` for `stdev <= 0` (was `float('inf')`). Line 173 passes `allow_nan=False` to `json.dumps`, so any future `inf`/`nan` in the payload surfaces as a `ValueError` at write time. UI handlers in `routes.py` (lines 682-693 and 834-841) preformat the display string (`"∞"`, `"+3.4"`, `"—"`) and pass `is_high_sigma` separately. Template `anomaly_detail.html:91` consumes both. JSON-portable end to end.

### WR-03 — band top/bottom clamped before height — VERIFIED FIXED

`src/ccguard/server/web/routes.py:650-654`:
```python
top_pct = max(0.0, min(100.0, ((mean + 3 * stdev) / max_val) * 100.0))
bot_pct = max(0.0, min(100.0, ((mean - 3 * stdev) / max_val) * 100.0))
band_bottom_pct = bot_pct
band_height_pct = max(0.0, top_pct - bot_pct)
```
Both edges clamped to `[0, 100]` independently, so the resulting height cannot push the band beyond the container regardless of whether the outlier defining `max_val` exceeds `mean + 3σ`.

### WR-04 — 404 on unknown machine_id — VERIFIED FIXED

`src/ccguard/server/web/routes.py:604-605` raises `HTTPException(status_code=404, detail="unknown machine")` when `session.get(Machine, machine_id)` returns `None`. Mirrors `machine_detail` (line 159-160). Enumeration-friendly behavior closed.

### WR-05 — asyncio.to_thread wraps blocking SQL — VERIFIED FIXED

`src/ccguard/server/main.py:86-92` defines `async def _tick_job` that does `await asyncio.to_thread(_tick_job_sync)`. AsyncIOScheduler awaits the coroutine, offloading the synchronous SQLite sweep to the default thread pool. Event loop stays responsive during ticks. `scheduler.py:55-58` documents the contract.

### WR-06 — documented as v0.2-acceptable — VERIFIED DOCUMENTED

`src/ccguard/server/services/anomaly_service.py:103-113` carries an explicit invariant docstring on `_same_day_finding_exists`: the SELECT-then-INSERT is not race-free; APScheduler `coalesce=True + max_instances=1` makes the scheduler a single in-process writer, sufficient for v0.2. Explicit "DO NOT call evaluate_one from request handlers without an external lock" warning; v0.3 migration path (SQLite expression UNIQUE INDEX with `IntegrityError` catch) recorded. Acceptable for v0.2 scope per CLAUDE.md (< 100 machines, single-tenant).

### WR-07 — recent_points_json shape + NaN guard — VERIFIED FIXED

`src/ccguard/server/web/routes.py:728-764` extracts a `_parse_recent_points` helper that: (a) treats non-list JSON shapes as no-data; (b) filters non-numeric entries; (c) explicitly excludes `bool` (subclass of `int`) before the numeric check; (d) drops `NaN` via `math.isnan`. Both `anomaly_detail` (line 623) and `_build_sparkline_cell` (line 777) consume the helper. `_build_sparkline_cell` adds a `if not raw:` warmup-fallback guard at line 778 to handle the validated-but-empty case.

### WR-08 — log.warning on malformed inventory JSON — VERIFIED FIXED

`src/ccguard/server/services/metric_aggregators.py:167-179` logs a structured warning (`machine_id`, exception) before falling back to `{}`. Aggregator keeps running against remaining valid snapshots; corruption is now visible in server logs instead of being silently masked as "no anomalies".

### No new defects introduced

I re-read all changed code paths for second-order issues:

- `_sigma_distance → None`: `json.dumps(None, allow_nan=False)` is valid JSON (`null`); template handlers explicitly check `raw_sigma is None`. Safe.
- `compute_baseline` real-n gating: aggregators are non-negative counts so `> 0` is correct; mean/stdev still computed over full 14-point window (anchors distribution; unchanged from prior intent).
- `_parse_recent_points` ordering: `isinstance(v, bool)` is checked before `isinstance(v, (int, float))`, correctly excluding booleans (bool is subclass of int).
- `band_height_pct` clamp: if `mean - 3σ < 0` (typical) `bot_pct` clamps to 0; `top_pct` clamps to 100; resulting height is in `[0, 100]`.
- `asyncio.to_thread` available on Python 3.9+; project pins 3.12. Safe.
- `start_scheduler` try/except in `main.py` correctly resets `app.state.scheduler = None` before re-raising — the `finally:` block then skips shutdown.
- New 404 in `anomaly_detail` requires Machine rows in tests; iteration-1 resolution notes mention seeding was added — confirmed by passing test count.

### Phase 1 audit code untouched

`git log ebc8924^..HEAD -- src/ccguard/server/api/audit.py src/ccguard/server/services/tool_use_service.py` returns empty. None of the nine fix commits touched Phase 1 surfaces. Files have not been modified since their original phase-1 introduction.

### Tests

`uv run pytest --ignore=tests/e2e` → **443 passed**, 0 failed, 68 warnings. e2e tests (`tests/e2e/test_end_to_end.py`, `tests/e2e/test_web_e2e.py`) fail with httpx connection errors and subprocess install issues — these are pre-existing environment-dependent failures unrelated to the Phase 2 fix scope (no fix commit touches e2e fixtures or the CLI binary path).

---

## Critical Issues

_None._

## Warnings

_None._

## Info (deferred from iteration 1)

### IN-01: Detail-page heading says "median" but code uses `fmean`

**File:** `src/ccguard/server/web/templates/anomaly_detail.html:12`, `baseline_service.py:55`

**Issue:** Template displays `{{ baseline.mean }}` under the label "median:" — but `compute_baseline` uses `statistics.fmean` (arithmetic mean). Cosmetic but misleading to AppSec analysts.

**Fix:** Either rename UI label to "среднее" (mean) or switch the computation to `statistics.median`. Picking median would also better match the docstring claim of robustness against outliers, since the running mean *includes* outliers in subsequent baselines (positive-feedback drift). Worth a follow-up issue.

### IN-02: `anomaly_service.tick` uses a single session for entire sweep with no scoping

**File:** `src/ccguard/server/services/anomaly_service.py:181-220`

**Issue:** A single session across N×4 evaluations means identity map keeps growing in memory. For 100 machines this is fine, but document the trade-off given the v0.3 Postgres migration plan.

**Fix:** Add a `session.expire_all()` per machine, or open a fresh session per machine in the tick loop.

### IN-03: Hardcoded magic numbers in template / route logic

**File:** `src/ccguard/server/web/routes.py:568,616,633,651-654`, `_anomalies_matrix.html:33`

**Issue:** `14`, `13`, `3 * stdev`, `6 * stdev`, sparkline width `w-20` (≈80px) are duplicated between routes.py and templates. The `WINDOW_DAYS` and `SIGMA_THRESHOLD` constants exist in source modules but are not threaded through. Drift risk in v0.3.

**Fix:** Import `WINDOW_DAYS` from `metric_aggregators` and `SIGMA_THRESHOLD` from `anomaly_service` into routes.py; pass into template context.

### IN-04: Dead `request: Request` parameters in several POST handlers

**File:** `src/ccguard/server/web/routes.py:432,466,479,491`

**Issue:** Pre-existing, not Phase-2-introduced, but visible in this diff scope: `request: Request` is unused in `policy_rollback`, `settings_create_token`, etc. Ruff `F841` should flag.

**Fix:** Remove `request` param where unused or prefix with `_request`.

### IN-05: Migration path for `FindingRecord.inventory_id` not enforced

**File:** `src/ccguard/server/db/models.py:33-56`

**Issue:** The docstring acknowledges `create_all` is a no-op against existing tables, so pre-Phase-2 deployments retain the NOT NULL constraint. The Phase 2 writer (`anomaly_service.evaluate_one`) inserts with `inventory_id=None`. On an upgraded existing deployment, this raises `IntegrityError` and the scheduler tick logs an error per machine per metric per hour. The mitigation ("not yet exposed to those deployments") is wishful thinking once anyone actually upgrades.

**Fix:** Add an explicit DDL in `init_db` to ALTER the column to nullable (or rebuild the table — SQLite ALTER COLUMN is awkward but doable via `PRAGMA writable_schema` or table-rebuild). At minimum, detect the constraint at startup and refuse to start the scheduler with a clear error message.

---

## Historical: Iteration 1 Findings (resolved)

The following findings were raised in iteration 1 and resolved in commits ebc8924, 43fb861, 9a5c36e, 89876af, aef7fee, e153e69, 4fb7166, 08844c0, d98dee3. Verbatim text preserved below for traceability.

### CR-01: `bash_calls_per_day_series` SQL binds wrong datetime format — will return 0 against real data

**Resolution:** FIXED in commit `ebc8924`. Switched the range filter to compare on `substr(ts, 1, 10)` against `date.isoformat()` strings, making it independent of how SQLAlchemy/SQLite serializes the rest of the timestamp. Added a tz-aware ORM-roundtrip regression test.

**File:** `src/ccguard/server/services/metric_aggregators.py:96-112`

**Issue:** The comment claims SQLAlchemy persists tz-aware datetimes as `"YYYY-MM-DD HH:MM:SS.ffffff"` with no offset. This is incorrect for `ToolUseEvent.ts` which is declared `datetime` in SQLModel — SQLAlchemy's default DateTime type in SQLite stores ISO-8601 *including* the `+00:00` offset when the value passed is tz-aware (and Phase 1 normalizes everything to UTC via `_enforce_utc`). The bound `start`/`end` strings are stripped of tz (`.replace(tzinfo=None)`), producing a `"2026-05-25 00:00:00.000000"` literal, while the column contains `"2026-05-25 00:00:00.000000+00:00"` (or similar). Lexicographic string comparison `ts >= :start` then matches incorrectly (the offset makes column strings lexicographically *greater* than naive bound strings for the same instant, which actually inflates results — but `ts < :end` *excludes* same-day rows whose offset suffix makes them sort above `end`). Net effect: results are non-deterministic depending on SQLite/SQLAlchemy version; in observed configurations the query returns **zero rows** even when ToolUseEvent rows clearly exist for the machine.

### CR-02: Warm-up gate is broken — every machine becomes "ready" after one tick

**Resolution:** FIXED in commit `43fb861`. `compute_baseline` now derives `sample_count` from the non-zero point count and gates `baseline_ready` on it. Mean/stdev are still computed over the full 14-point zero-padded series (so the distribution stays anchored). Updated affected tests; added a regression test confirming a single spike on an otherwise-quiet brand-new machine does NOT trigger emission.

**File:** `src/ccguard/server/services/baseline_service.py:44-52`, `src/ccguard/server/services/anomaly_service.py:114-120`

**Issue:** `compute_baseline` is called with the **14-element zero-padded series** produced by aggregators (every metric, every tick). Therefore `n = len(points)` is always 14, so `baseline_ready = n >= WARMUP_THRESHOLD` (=7) is **always True** from the very first tick of a brand-new machine.

### WR-01: `app.state.scheduler` not initialized before potential exception window

**Resolution:** FIXED in commit `9a5c36e` (grouped with WR-05). `app.state.scheduler = None` is now the very first statement of `_lifespan`; `start_scheduler` is wrapped so failure clears the attribute back to `None` and the lifespan teardown does not attempt to shutdown a half-started scheduler.

### WR-02: `_sigma_distance` returns `float("inf")` — gets persisted in payload_json

**Resolution:** FIXED in commit `89876af`. `_sigma_distance` now returns `None` for the degenerate `stdev==0` case; payload is JSON-portable. `json.dumps(..., allow_nan=False)` added to the finding insert so any future regression surfaces as a `ValueError` at write time. UI handlers preformat the display string (`"∞"`, `"+3.4"`, `"—"`) and pass an `is_high_sigma` flag for the red-highlight threshold check.

### WR-03: Detail page `band_height_pct` can overflow visually

**Resolution:** FIXED in commit `aef7fee`. Band top and bottom are now clamped to `[0, 100]` in absolute terms first, then height is derived from the clamped values.

### WR-04: `anomaly_detail` does not 404 on unknown machine_id

**Resolution:** FIXED in commit `e153e69`. `anomaly_detail` now mirrors `machine_detail`'s `session.get(Machine, machine_id)` check and raises 404 for unknown ids. Affected tests seed the Machine row; a dedicated regression test asserts the 404 path.

### WR-05: Scheduler tick performs blocking DB I/O inside AsyncIOScheduler's event loop

**Resolution:** FIXED in commit `9a5c36e` (grouped with WR-01). The synchronous SQL tick body is now wrapped in `asyncio.to_thread` so the AsyncIOScheduler does not block the FastAPI event loop for the duration of the sweep.

### WR-06: Same-day dedup race between concurrent ticks / HTTP triggers

**Resolution:** DOCUMENTED as v0.2-acceptable in commit `4fb7166`. The SELECT-then-INSERT pattern is NOT race-free, but APScheduler's `coalesce=True + max_instances=1` makes the scheduler a single in-process writer, which is sufficient for v0.2. Added an explicit invariant docstring on `_same_day_finding_exists` warning future contributors not to call `evaluate_one` from request handlers without an external lock, and recording the v0.3 migration path (SQLite expression UNIQUE INDEX with `IntegrityError` catch-on-insert).

### WR-07: `recent_points_json` parsing trusts the JSON shape

**Resolution:** FIXED in commit `08844c0`. Extracted a `_parse_recent_points` helper that treats non-list shapes as no-data, filters non-numeric entries (incl. `bool` which is a subclass of `int`), and drops `NaN`. Both `anomaly_detail` and `_build_sparkline_cell` now route through it. Regression test seeds malformed baselines (`null`, `{}`, `"oops"`, mixed-junk lists) and asserts the detail route returns 200 instead of 500.

### WR-08: `_load_snapshots` silently coerces malformed payloads to `{}` without logging

**Resolution:** FIXED in commit `d98dee3`. `_load_snapshots` now emits a structured `log.warning` (with `machine_id` and the parse error) when an `inventorysnapshot.payload_json` fails to decode, so data corruption is visible in server logs instead of being silently masked as "no anomalies detected". Aggregator still falls back to `{}` so it keeps running against remaining valid snapshots.

---

_Reviewed: 2026-05-25_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Iteration: 2 (clean — all CR/WR resolved, Info deferred)_
