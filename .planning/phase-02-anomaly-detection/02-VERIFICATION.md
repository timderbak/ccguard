---
phase: 02-anomaly-detection
verified: 2026-05-25T20:40:14Z
status: human_needed
score: 5/5 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Open /anomalies in browser with seeded baseline + outlier data; confirm sparkline matrix renders, last-bar outlier cell is red, and clicking a cell navigates to /anomalies/{machine_id}/{metric} drill-down."
    expected: "Matrix card lists machines × 4 metrics; cells with baseline_ready=false show a warm-up placeholder; outlier cells visually highlighted in red; navigation works."
    why_human: "Visual rendering correctness (Tailwind classes, sparkline bar geometry, colour contrast) cannot be verified by grep — only by actual browser render."
  - test: "Open /anomalies/{machine_id}/{metric} drill-down for a machine with >3σ outlier; confirm baseline band overlay visible, outlier bar marker dot above the bar, recent findings table populated."
    expected: "Timeseries shows 14 daily bars with grey baseline band (mean±σ region) overlaying the chart; outlier bars red with circular marker above; findings table lists same-day anomaly finding with rule_id=anomaly.*."
    why_human: "SC #4 is a visual chart with baseline band — CSS positioning (band_bottom_pct/band_height_pct), opacity, and outlier dot placement must be inspected visually to confirm SC met as a user-facing chart, not just a data structure."
  - test: "Open /overview and confirm the «Аномалии» block renders with top-N recent anomalies and links navigate correctly."
    expected: "Overview page shows Anomalies card with up to N items each linking to /anomalies/{machine_id}/{metric}; empty state shows «Аномалий нет.»"
    why_human: "SC #3 is UI-rendering on Overview — visual layout and HTMX partial swap behavior cannot be verified without an actual page load."
---

# Phase 2: Anomaly Detection Verification Report

**Phase Goal:** Per-machine baseline + 3σ-алерты на отклонения в tool-use поведении
**Verified:** 2026-05-25T20:40:14Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (mapped to ROADMAP Success Criteria)

| # | Truth (SC) | Status | Evidence |
|---|------------|--------|----------|
| 1 | Server computes rolling 14-day baseline (median+σ) for 4 metrics per-machine | VERIFIED | `services/baseline_service.py` (118 LOC) computes mean/stdev over 14-point series, warm-up gate ≥7 non-zero points; `services/metric_aggregators.py:79,239,258,277` defines all 4 aggregators (`bash_calls_per_day_series`, `new_mcp_per_week_series`, `new_agents_per_week_series`, `skill_dir_hash_changes_per_week_series`); `db/models.py:130` defines `MachineBaseline(machine_id, metric, mean, stdev, sample_count, baseline_ready, recent_points_json)` |
| 2 | At >3σ creates finding severity=warn rule_id=anomaly.* | VERIFIED | `services/anomaly_service.py:67-75` `_is_outlier` uses `SIGMA_THRESHOLD * stdev`; `:164-175` creates `FindingRecord(severity="warn", rule_id=...)`; `services/anomaly_constants.py:43,46` `RULE_ID_PREFIX = "anomaly."` and `rule_id_for("bash_calls_per_day") -> "anomaly.bash_calls_per_day"`. Scheduler wired in `main.py:58-110` (lifespan starts APScheduler, runs `anomaly_tick` via `asyncio.to_thread`, shuts down gracefully) |
| 3 | Web UI Overview contains «Anomalies» block with top-N | VERIFIED | `templates/overview.html:11-14` includes HTMX-hydrated `components/_anomalies_overview.html`; component renders «Аномалии» heading + list of recent anomalies with sigma_distance and links to `/anomalies/{machine_id}/{metric}`; backed by `routes.py:807` partial endpoint |
| 4 | Drill-down /anomalies timeseries with baseline band + outliers | VERIFIED | `routes.py:529 /anomalies`, `:542 /_partials/anomalies/matrix`, `:585 /anomalies/{machine_id}/{metric}` all wired. `templates/anomaly_detail.html:36-69` renders timeseries chart with baseline band overlay (`band_visible`, `band_bottom_pct`, `band_height_pct`) and red outlier bars with marker dots (`is_outlier`). Sparkline cell in `components/_anomalies_matrix.html` shows last-value outlier highlighting |
| 5 | Tests cover baseline empty data, <3σ edge-case, finding generation, UI rendering | VERIFIED | 70 anomaly-related test functions across 6 files: `tests/unit/test_baseline_service.py` (16), `test_anomaly_service.py` (15), `test_anomaly_edge_cases.py` (8), `test_machine_baseline_model.py` (6), `tests/integration/test_anomaly_routes.py` (13), `test_scheduler_tick.py` (6), `test_anomalies_overview_partial.py` (6). Full suite: 443/443 pass (`.venv/bin/pytest tests/ --ignore=tests/e2e` — 100% pass) |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/ccguard/server/db/models.py` :: `MachineBaseline` | SQLModel table for per-machine baselines | VERIFIED | Fields: machine_id, metric, mean, stdev, sample_count, baseline_ready, recent_points_json (JSON list), updated_at |
| `src/ccguard/server/services/baseline_service.py` | Compute + upsert baseline | VERIFIED | 118 LOC; `upsert_baseline()` with warm-up gate on non-zero count ≥7 (CR-02 fix verified in 02-REVIEW) |
| `src/ccguard/server/services/metric_aggregators.py` | 4 metric aggregator series | VERIFIED | 297 LOC; all 4 series functions present; `substr(ts,1,10)` date-prefix bucketing (CR-01 fix verified) |
| `src/ccguard/server/services/anomaly_service.py` | `evaluate_one` + `tick` orchestration | VERIFIED | 220 LOC; `_is_outlier`, `_sigma_distance` (returns None on stdev=0 — WR-02), `_same_day_finding_exists` dedup, `evaluate_one` creates FindingRecord, `tick` sweeps all machines × metrics |
| `src/ccguard/server/services/anomaly_constants.py` | METRICS list + rule_id_for | VERIFIED | 52 LOC; `ALL_METRICS`, `VALID_METRICS`, `SIGMA_THRESHOLD=3`, `RULE_ID_PREFIX="anomaly."`, `rule_id_for()` |
| `src/ccguard/server/scheduler.py` | APScheduler build/start/shutdown | VERIFIED | 90 LOC; `build_scheduler`, `start_scheduler`, `shutdown_scheduler` |
| `src/ccguard/server/main.py` lifespan | Scheduler wired into FastAPI lifespan | VERIFIED | Lines 58-110: imports anomaly_tick, wraps in `asyncio.to_thread`, env-gated by `CCGUARD_DISABLE_SCHEDULER`, defensive `app.state.scheduler = None` init (WR-01 fix), proper shutdown |
| `templates/anomalies_feed.html` | Matrix list page | VERIFIED | HTMX-hydrated matrix card |
| `templates/anomaly_detail.html` | Drill-down chart page | VERIFIED | Baseline stats panel + 14-day timeseries chart with band overlay + outlier markers + findings table |
| `templates/components/_anomalies_overview.html` | Overview block | VERIFIED | «Аномалии» heading + top-N list with sigma_distance |
| `templates/components/_anomalies_matrix.html` | Sparkline matrix | VERIFIED | 14 vertical bars per cell + outlier highlighting on last point |
| Web routes (3) | `/anomalies`, partials, `/anomalies/{machine}/{metric}` | VERIFIED | `routes.py:529, 542, 585, 807` — all 4 endpoints wired |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| FastAPI lifespan | anomaly_service.tick | `_tick_job_sync` in `asyncio.to_thread` | WIRED | `main.py:65-92` imports and invokes |
| anomaly_service.evaluate_one | baseline_service.upsert_baseline | direct call | WIRED | `anomaly_service.py:136` |
| anomaly_service.evaluate_one | FindingRecord | `session.add(finding); session.commit()` | WIRED | `:175-176` — creates persisted finding |
| Web overview page | partial `/_partials/anomalies/overview` | HTMX `hx-get` | WIRED | `overview.html:11`, route at `routes.py:807` |
| `/anomalies` matrix cell click | `/anomalies/{machine_id}/{metric}` | HTML `<a href>` link in `_anomalies_matrix.html` | WIRED | route at `routes.py:585` |
| Drill-down handler | MachineBaseline | `session.exec(select(MachineBaseline)...)` | WIRED | `routes.py:607` |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `anomaly_detail.html` `points` | timeseries point list | `routes.py:623` parses `baseline.recent_points_json` populated by `baseline_service.upsert_baseline` from `metric_aggregators.bash_calls_per_day_series` (real SQL `SELECT … FROM tool_use_event GROUP BY substr(ts,1,10)`) | Yes | FLOWING |
| `_anomalies_overview.html` `items` | top-N anomalies | `/_partials/anomalies/overview` queries FindingRecord (real DB select on rule_id LIKE 'anomaly.%') | Yes | FLOWING |
| `_anomalies_matrix.html` `cells` | sparkline cells | `routes.py:557-579` bulk-loads `MachineBaseline` rows + parses `recent_points_json` per cell | Yes | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full non-e2e test suite passes | `.venv/bin/pytest tests/ --ignore=tests/e2e -q` | 443 passed, 0 failed | PASS |
| Test collection counts match SUMMARY claim (443) | `.venv/bin/pytest tests/ --ignore=tests/e2e --co` | "443 tests collected" | PASS |
| MachineBaseline model importable | implicit via SQLModel create_all in tests | tests using `MachineBaseline` pass | PASS |
| Scheduler imports succeed from main.py lifespan | covered by `test_scheduler_tick.py` (6 tests) | PASS | PASS |
| Anomaly routes return 200 | covered by `test_anomaly_routes.py` (13 tests) + `test_anomalies_overview_partial.py` (6 tests) | PASS | PASS |

### Probe Execution

| Probe | Command | Result | Status |
|-------|---------|--------|--------|
| (no `scripts/*/tests/probe-*.sh` declared) | n/a | n/a | SKIPPED |

Phase 2 PLAN/SUMMARY does not declare any shell probes. Test suite serves as the verification gate, and it passes 443/443.

### Requirements Coverage

| Requirement | Source | Description | Status | Evidence |
|-------------|--------|-------------|--------|----------|
| ANO-01 | Phase 2 | Per-machine baseline (rolling 14-day window) for 4 metrics | SATISFIED | `MachineBaseline` model + `baseline_service` + 4 aggregators implemented; warm-up gate ≥7 |
| ANO-02 | Phase 2 | Alert severity=warn at >3σ; findings with rule_id=anomaly.* | SATISFIED | `anomaly_service.evaluate_one` creates `FindingRecord(severity="warn", rule_id=rule_id_for(metric))`; same-day dedup |
| ANO-03 | Phase 2 | Web UI: «Anomalies» block on Overview + drill-down with timeseries | SATISFIED | Overview component + `/anomalies` matrix + `/anomalies/{machine}/{metric}` drill-down with baseline band; **NEEDS HUMAN visual confirmation** |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none) | — | — | — | No TBD/FIXME/XXX markers, no `return []` stubs, no empty handlers in Phase 2 source files |

A scan of the 17 files reviewed in 02-REVIEW.md confirms no debt markers. The two BLOCKERs and eight WARNINGs identified in review iteration 1 were all resolved (commits ebc8924, 43fb861, 9a5c36e, 89876af, aef7fee, e153e69, 4fb7166, 08844c0, d98dee3) and verified by iteration 2 (`status: clean`).

### Human Verification Required

Three items need human visual verification — Phase 2 has a substantial UI surface (overview block, matrix sparklines, drill-down chart with baseline band overlay) whose correctness cannot be asserted by grep or integration tests beyond "HTML renders without 500 errors". The integration tests confirm routes return 200 with expected substrings; they do NOT confirm that the baseline band is visually positioned correctly or that outlier markers are perceptually distinguishable.

See `human_verification:` block in frontmatter for the three checks.

### Gaps Summary

No code-level gaps. All five ROADMAP success criteria have concrete artifacts and data-flow paths verified in the codebase. All 443 unit/integration tests pass. The phase code review (02-REVIEW.md iteration 2) confirms clean status with all CR/WR findings resolved.

Status set to `human_needed` rather than `passed` because three UI rendering claims (SC #3 overview block visual, SC #4 timeseries chart with baseline band, sparkline matrix outlier coloring) require browser inspection — automated tests confirm route correctness and data shape but cannot certify visual fidelity.

---

*Verified: 2026-05-25T20:40:14Z*
*Verifier: Claude (gsd-verifier)*
