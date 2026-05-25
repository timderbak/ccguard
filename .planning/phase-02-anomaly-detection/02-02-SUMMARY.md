---
phase: 02-anomaly-detection
plan: 02
subsystem: server.services
tags: [anomaly, aggregators, baseline, statistics]
requires:
  - 02-01 (MachineBaseline table, ux_machinebaseline_machine_metric, anomaly_constants)
provides:
  - "4 metric aggregators (1 SQL-backed + 3 inventory-diff, all O(snapshots))"
  - "baseline_service.compute_baseline (pure)"
  - "baseline_service.upsert_baseline (race-free ON CONFLICT)"
  - "WARMUP_THRESHOLD = 7 (locked)"
affects:
  - src/ccguard/server/services/metric_aggregators.py (new)
  - src/ccguard/server/services/baseline_service.py (new)
tech_added: []
patterns:
  - "Inventory-diff rolling-week: load snapshots once, evaluate 14 anchors in Python"
  - "Empty baseline → count=0 (no signal from initial population)"
  - "SQLite ON CONFLICT (composite UNIQUE) for idempotent UPSERT via raw SQL"
  - "substr(ts,1,10) for date bucketing (avoids date()/+00:00 quirks)"
key_files_created:
  - src/ccguard/server/services/metric_aggregators.py
  - src/ccguard/server/services/baseline_service.py
  - tests/unit/test_metric_aggregators.py
  - tests/unit/test_baseline_service.py
key_files_modified: []
decisions:
  - "Empty baseline (no snapshots strictly older than anchor-7d) → count=0 — prevents false anomalies from first-ever inventory upload (reconciled from plan-stated example by treating initial population as 'no baseline')"
  - "SQLite stores tz-aware datetimes as 'YYYY-MM-DD HH:MM:SS.ffffff' (space separator, no offset). Bind parameters for ts range comparisons use the same format via strftime('%Y-%m-%d %H:%M:%S.%f') — NOT datetime.isoformat() (which uses 'T' and would lexicographically mis-compare on hour boundaries)"
  - "Skill change detection reuses the generic new-tuple diff helper: a skill whose dir_hash changes shows up as a new (name, dir_hash) tuple not present in the baseline window"
  - "compute_baseline returns dict {mean, stdev, sample_count, baseline_ready} — keeps caller agnostic of MachineBaseline schema until upsert time"
metrics:
  duration: "~12 min"
  completed: "2026-05-25"
  tasks_completed: 2
  new_tests: 32
  phase1_test_baseline: 362
  phase1_test_count_after: 394
---

# Phase 2 Plan 02: Metric Aggregators + baseline_service Summary

One-liner: Four pure-function 14-day daily-granular metric aggregators (1 SQL-backed Bash counter + 3 inventory-diff aggregators using rolling-week semantics) plus a `baseline_service` with `statistics.stdev` warm-up gating and race-free SQLite `ON CONFLICT` upsert into `MachineBaseline`.

## What Was Built

### `src/ccguard/server/services/metric_aggregators.py` (new)

Four pure functions, all sharing the signature:

```python
fn(session: Session, machine_id: str, anchor_date: date | None = None) -> list[tuple[date, int]]
```

| Function | Source | Identity tuple |
|----------|--------|---------------|
| `bash_calls_per_day_series` | `tooluseevent` SQL `GROUP BY substr(ts,1,10)` | n/a (count of Bash events) |
| `new_mcp_per_week_series` | `inventorysnapshot.payload_json` | `item["name"]` (MCP_NAME_FIELD) |
| `new_agents_per_week_series` | `inventorysnapshot.payload_json` | `(item["name"], item["file_hash"])` |
| `skill_dir_hash_changes_per_week_series` | `inventorysnapshot.payload_json` | `(item["name"], item["dir_hash"])` |

**Rolling-window semantics** (for the three inventory-diff aggregators), for each of 14 daily anchor dates `d`:

- `window` = snapshots in `(d - 7, d]`
- `baseline` = snapshots in `(d - 14, d - 7]`
- `new = items_at(latest_in_window) - items_in_any(baseline)`
- **If `baseline` is empty → count = 0** (no comparison frame, no signal)

This last rule is a small deviation from the literal plan example at `anchor=d-5` (see Deviations below) but matches the plan's locked intent: "new in last 7d" requires a prior week to compare against.

**Cost:** O(snapshots) per call — snapshots loaded and parsed once, then 14 anchors evaluated in pure Python via `_rolling_window_diff_series`.

### `src/ccguard/server/services/baseline_service.py` (new)

```python
WARMUP_THRESHOLD: int = 7

def compute_baseline(points: list[float]) -> dict:
    # returns {"mean", "stdev", "sample_count", "baseline_ready"}
    # mean: statistics.fmean (0.0 for empty input)
    # stdev: statistics.stdev (0.0 for n<2 — avoids StatisticsError)
    # baseline_ready: n >= WARMUP_THRESHOLD

def upsert_baseline(session, machine_id, metric, points) -> MachineBaseline:
    # INSERT ... ON CONFLICT(machine_id, metric) DO UPDATE SET ...
    # Returns the freshly persisted row.
```

The UPSERT relies on `ux_machinebaseline_machine_metric` (UNIQUE composite index installed by plan 02-01 via DDL). `recent_points_json` is `json.dumps(points)`; `updated_at` is `datetime.now(UTC)` per call.

### `tests/unit/test_metric_aggregators.py` (16 tests)

| Block | Tests |
|-------|-------|
| `bash_calls_per_day` | 6 — counts, tool-name exclusion, machine isolation, anchor=last/oldest=anchor-13, empty, out-of-window |
| `new_mcp_per_week` | 4 — basic rolling diff, empty, 14-length ascending, machine isolation |
| `new_agents_per_week` | 3 — hash-aware identity, unchanged-hash no-signal, empty |
| `skill_dir_hash_changes_per_week` | 3 — change detection, no-change, empty |

### `tests/unit/test_baseline_service.py` (16 tests)

| Block | Tests |
|-------|-------|
| `compute_baseline` | 7 — identical points, full window w/ zeros, warm-up <7, exactly-7 boundary, sample stdev correctness, single point, empty |
| `upsert_baseline` | 8 — insert→update no duplicate, JSON store, updated_at advances, different metric, repeated calls, warmup flag persistence, ready flag persistence, return-type |
| Constants | 1 — `WARMUP_THRESHOLD == 7` |

## Public API (for plan 02-03)

```python
from ccguard.server.services.metric_aggregators import (
    bash_calls_per_day_series,
    new_mcp_per_week_series,
    new_agents_per_week_series,
    skill_dir_hash_changes_per_week_series,
)
from ccguard.server.services.baseline_service import (
    WARMUP_THRESHOLD,
    compute_baseline,
    upsert_baseline,
)
```

All aggregators accept `(session, machine_id, anchor_date=None)` and return `list[tuple[date, int]]` of length 14. `upsert_baseline(session, machine_id, metric, points)` accepts the count series (cast to floats) and persists the row.

## Quirks Downstream Plans Must Know

1. **Date bucketing uses `substr(ts, 1, 10)`** — SQLite stores tz-aware datetimes from SQLAlchemy as `"YYYY-MM-DD HH:MM:SS.ffffff"` (space separator, no offset suffix). Using `date(ts)` would produce subtle errors with the offset-bearing strings agents send. The first 10 chars are always the UTC date because Phase 1 `ToolUseEventIn._enforce_utc` normalizes everything to UTC at ingest.

2. **Time bound parameters bind in the SQLite format**, not `datetime.isoformat()`. The aggregator uses `dt.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")` — if plan 02-03 passes datetime objects through SQLAlchemy params directly that's fine (SA renders them the same way), but raw bind-string callers must match.

3. **Initial-population edge case** — a machine that just uploaded its first-ever inventory has `baseline=∅` for every anchor → all-zero series, no signal. The scheduler can rely on this rather than special-casing "first inventory ever".

4. **`compute_baseline({})` is safe** — returns `{mean: 0.0, stdev: 0.0, sample_count: 0, baseline_ready: False}`. No `ZeroDivisionError`, no `StatisticsError`.

5. **`upsert_baseline` commits the session**. Callers using a larger transaction must not wrap this — the commit is internal so the UPSERT is durable before the SELECT round-trip that returns the row.

## Commits

| Task | Phase | Hash | Message |
|------|-------|------|---------|
| 1 | RED | `d075442` | test(02-02): add failing tests for metric_aggregators |
| 1 | GREEN | `72ee442` | feat(02-02): implement 4 metric aggregators with 14-day rolling-week semantics |
| 2 | RED | `39bbbcd` | test(02-02): add failing tests for baseline_service |
| 2 | GREEN | `eb8756e` | feat(02-02): baseline_service — compute_baseline + race-free UPSERT |

## TDD Gate Compliance

Both tasks followed RED → GREEN. No REFACTOR commits were necessary; both implementations passed first-shot of GREEN.

## Phase 1 + 02-01 Regression

- **Pre-change baseline:** 362 tests (356 Phase 1 + 6 from 02-01).
- **Post-change:** 394 tests = 362 + 32 new (16 aggregator + 16 baseline_service).
- All 394 pass; pre-existing e2e suite (requires live server) excluded as in 02-01.

## Verification

```
$ pytest tests/unit/test_metric_aggregators.py tests/unit/test_baseline_service.py -v
... 32 passed in 0.17s

$ pytest tests/ -q --ignore=tests/e2e
... 394 passed, 48 warnings in 13.51s

$ grep -r "from.*router\|FastAPI\|APScheduler" src/ccguard/server/services/metric_aggregators.py src/ccguard/server/services/baseline_service.py | wc -l
0
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] Initial bind-parameter format mismatch in `bash_calls_per_day_series`**

- **Found during:** Task 1 GREEN first test run (`test_bash_calls_per_day_returns_14_length_with_correct_counts` failed on the `anchor - 13` day assertion).
- **Issue:** First implementation bound `start`/`end` with `datetime.isoformat()` ("T" separator). SQLite stores those columns as `"YYYY-MM-DD HH:MM:SS.ffffff"` (space). The lexicographic `>=` comparison silently mis-bound the anchor-13 edge — events at that boundary were dropped.
- **Fix:** Bind with `strftime("%Y-%m-%d %H:%M:%S.%f")` to match storage format. Documented in code with a SQLite-storage comment.
- **Files modified:** `src/ccguard/server/services/metric_aggregators.py` (same GREEN commit `72ee442`).

### Plan-text reconciliations (documented, not auto-fixed)

**2. [Reconciliation] `new_mcp_per_week` semantics at `anchor=d-5`**

- **Plan example asserts:** "at anchor=d-5, count=0" (with snapshots at d-10 `[A,B]` and d-2 `[A,B,C]`).
- **Strict reading would yield:** 2 (both A and B "new" because there's nothing strictly older than d-12).
- **Resolution adopted:** "new requires a baseline" — if no snapshot exists strictly older than `(anchor − 7d)`, the count is 0. This is what the plan's locked example says and matches the intent (an anomaly signal that flags *changes*, not *initial population*).
- **Implementation:** `_rolling_window_diff_series` early-returns 0 when `baseline_seen` is False or no in-window snapshot exists.

## Known Stubs

None. Both modules are fully wired; downstream consumers (scheduler, finding-emitter, UI) will be added in plans 02-03 → 02-05.

## Threat Flags

None — no new network endpoints, no new auth paths, no new file-access patterns, no new trust-boundary schema changes. Both modules are pure read-side aggregation + a write to an existing table whose access control is already governed by the server's session layer.

## Self-Check: PASSED

- `src/ccguard/server/services/metric_aggregators.py` — FOUND
- `src/ccguard/server/services/baseline_service.py` — FOUND
- `tests/unit/test_metric_aggregators.py` — FOUND
- `tests/unit/test_baseline_service.py` — FOUND
- Commits `d075442`, `72ee442`, `39bbbcd`, `eb8756e` — all resolved in `git log`
