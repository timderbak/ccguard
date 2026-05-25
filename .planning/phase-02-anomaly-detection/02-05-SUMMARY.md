---
phase: 02-anomaly-detection
plan: 05
subsystem: server/web
tags: [ui, htmx, jinja, anomalies, drill-down]
requires: [02-01, 02-02, 02-03, 02-04]
provides:
  - "GET /anomalies (anomalies_feed.html)"
  - "GET /_partials/anomalies/matrix (components/_anomalies_matrix.html)"
  - "GET /anomalies/{machine_id}/{metric} (anomaly_detail.html)"
affects: [overview UX, sidebar nav target]
tech_added: []
tech_patterns:
  - "Bulk MachineBaseline pre-load + in-process bucketing for matrix view-model"
  - "Per-cell sparkline VM with deterministic 4-metric column order pinned in template"
  - "Detail page band geometry computed server-side (band_bottom_pct, band_height_pct) — no JS"
key_files:
  created:
    - src/ccguard/server/web/templates/anomalies_feed.html
    - src/ccguard/server/web/templates/components/_anomalies_matrix.html
    - src/ccguard/server/web/templates/anomaly_detail.html
  modified:
    - src/ccguard/server/web/routes.py
decisions:
  - "Right-pad detail-page raw_points to length 14 with leading zeros so the most-recent point always pins to the right of the chart."
  - "Detail-page outlier classification is per-point (each bar is independently red if |value-mean|>3σ); matrix sparkline outlier classification stays last-bar-only per UI-SPEC."
  - "Findings query uses payload_json.observed_value and payload_json.sigma_distance — gracefully degrades to em-dash / 0.0 on malformed payloads."
metrics:
  duration_minutes: 5
  tasks_completed: 3
  files_created: 3
  files_modified: 1
  completed: 2026-05-25
requirements: [ANO-03]
---

# Phase 2 Plan 05: Drill-down (matrix + detail) Summary

CSS-only matrix and 14-day timeseries drill-down for anomaly investigation: three new routes wired into the existing FastAPI router, three new Jinja templates extending the Phase-1 base layout, RU copy verbatim per UI-SPEC lockdown.

## Tasks Completed

| Task | Name                                                       | Commit  |
|------|------------------------------------------------------------|---------|
| 1    | Routes — /anomalies, drill-down, /_partials/anomalies/matrix | bf3ba94 |
| 2    | anomalies_feed.html + _anomalies_matrix.html               | f099fad |
| 3    | anomaly_detail.html                                        | 62aaa15 |

## View-Model Field Names (for 02-06 integration tests)

### `components/_anomalies_matrix.html`

Top-level template context:

| Key       | Type                                | Notes |
|-----------|-------------------------------------|-------|
| `machines` | `list[dict]`                       | Empty list when fleet is empty (renders 'Машин нет.' row, colspan=5) |
| `metrics` | `list[str]`                         | Echo of `ALL_METRICS` — currently unused by template but exposed for 02-06 assertions / future debugging |

Each `machines[i]` shape:

| Key     | Type                | Notes |
|---------|---------------------|-------|
| `id`    | `str`               | Full `machine_id`; template uses `m.id[:12]` for display, full id for `/machines/{id}` and `/anomalies/{id}/{metric}` href |
| `cells` | `dict[str, cell]`   | Keyed by metric name (one of `ALL_METRICS`) |

Each `cells[metric]` shape:

| Key          | Type                  | Notes |
|--------------|-----------------------|-------|
| `warmup`     | `bool`                | True when baseline is None OR `baseline_ready=False` OR `recent_points_json` decodes to empty list |
| `points`     | `list[point]`         | Empty when `warmup=True`; otherwise length up to 14 (right-aligned with left zero-pad if fewer) |
| `last_value` | `float \| None`       | `None` when `warmup=True` |
| `is_outlier` | `bool`                | True when `stdev>0 AND abs(last_value - mean) > 3*stdev` |

Each `points[i]` shape (matrix-cell only — has no `is_outlier` per point; last-bar coloring is driven by `cell.is_outlier`):

| Key          | Type    |
|--------------|---------|
| `value`      | `float` |
| `height_pct` | `float` (2-decimal rounded, 0..100) |
| `label`      | `str` (ISO date) |

### `anomaly_detail.html`

Top-level template context:

| Key                | Type                          | Notes |
|--------------------|-------------------------------|-------|
| `machine_id`       | `str`                         | From URL path; rendered as `machine_id[:12]` in heading/title |
| `metric`           | `str`                         | One of `VALID_METRICS` (route raises 404 otherwise) |
| `baseline`         | `MachineBaseline \| None`     | None when no baseline row exists yet; template guards every dereference |
| `baseline_ready`   | `bool`                        | `baseline.baseline_ready` if baseline else False |
| `points`           | `list[detail_point]`          | Always length 14 (left zero-padded) |
| `band_visible`     | `bool`                        | True iff baseline_ready AND stdev>0 AND max>0 |
| `band_bottom_pct`  | `float` (0..100, 2-dec)       | `max(0, ((mean - 3σ)/max)*100)`; 0.0 when not visible |
| `band_height_pct`  | `float` (0..100, 2-dec)       | `min(100-bottom, (6σ/max)*100)`; 0.0 when not visible |
| `findings`         | `list[finding_vm]`            | Up to 50; empty list → 'Находок для этой метрики ещё нет.' |

Each `points[i]` shape (detail page — per-point outlier flag, distinct from matrix-cell points):

| Key          | Type    |
|--------------|---------|
| `value`      | `float` |
| `height_pct` | `float` (2-decimal rounded) |
| `label`      | `str` (ISO date — 14 anchors `today - timedelta(days=13-i)`) |
| `is_outlier` | `bool` (`baseline_ready AND stdev>0 AND abs(value-mean) > 3σ`) |

Each `findings[i]` shape:

| Key              | Type        | Notes |
|------------------|-------------|-------|
| `discovered_at`  | `datetime`  | Template renders via `.isoformat(timespec="seconds")` |
| `observed_value` | `str \| float` | Comes from `payload_json.observed_value`; em-dash `'—'` fallback on missing/invalid payload |
| `sigma_distance` | `float`     | From `payload_json.sigma_distance`; 0.0 fallback; template renders `"{:+.1f}σ"` and adds `text-red-600` when `abs() > 3` |
| `rule_id`        | `str`       | E.g. `anomaly.bash_calls_per_day` |

## Verification Results

- `pytest tests/ --ignore=tests/e2e` → **414 passed**, 53 warnings (no new failures vs baseline at 7306fa8).
- `tests/e2e/test_end_to_end.py::test_health_endpoint` requires a live network listener and is unrelated to plan scope — pre-existing skip in CI mode, deferred.
- Route registration smoke check (`app.routes`): all 4 expected paths present — `/anomalies`, `/anomalies/{machine_id}/{metric}`, `/_partials/anomalies/matrix`, plus the prior `/_partials/anomalies/overview`.
- Plan-mandated grep checks (matrix RU strings, detail RU strings) — all pass.

## Deviations from Plan

**None.** All RU strings match UI-SPEC verbatim; matrix sparkline structure, detail timeseries band overlay, and per-point outlier dots all match the spec markup exactly. The only forward-compatible additions are the two graceful-degradation fallbacks (em-dash for malformed `observed_value`, zero-pad to length 14 for partial windows) — both are necessary so the template never raises on real-world partial data and neither changes the visible contract.

## Self-Check: PASSED

- src/ccguard/server/web/routes.py — FOUND (modified)
- src/ccguard/server/web/templates/anomalies_feed.html — FOUND
- src/ccguard/server/web/templates/components/_anomalies_matrix.html — FOUND
- src/ccguard/server/web/templates/anomaly_detail.html — FOUND
- commit bf3ba94 — FOUND
- commit f099fad — FOUND
- commit 62aaa15 — FOUND
