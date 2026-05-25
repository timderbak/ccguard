---
phase: 01-tool-use-audit-foundation
plan: 05
subsystem: server-web
tags: [htmx, jinja2, timeline, audit, partial]
requires: [01-03, 01-04]
provides: [tua-03-timeline-chart, _partials/audit/timeline endpoint]
affects: [/audit page initial render]
tech-stack:
  added: []
  patterns: [HTMX hx-include polling, CSS-only bar chart, server-rendered fragment partial]
key-files:
  created:
    - src/ccguard/server/web/templates/components/_audit_timeline.html
    - tests/integration/test_audit_timeline_partial.py
  modified:
    - src/ccguard/server/web/templates/audit_feed.html
    - src/ccguard/server/web/routes.py
decisions:
  - "Timeline chart window is fixed at 24h regardless of user-selected timeframe filter (UI-SPEC: card heading 'Активность за 24 часа')"
  - "Empty-state branch lives inside the polled partial so polled refreshes can swap to/from empty atomically"
  - "max_count computed in route handler (not template) to keep Jinja branch-free arithmetic minimal"
metrics:
  duration: ~12min
  completed: 2026-05-25
  tests_baseline: 325
  tests_after: 336
  new_tests: 11
---

# Phase 01 Plan 05: Timeline Chart Partial + Polling Endpoint Summary

CSS-only 24h hourly bar chart partial wired to a new HTMX-polled GET /_partials/audit/timeline endpoint that honors active filter-form values via hx-include.

## What Was Built

- **`components/_audit_timeline.html`** — server-rendered partial. Two branches: `max_count == 0` → empty-state copy "Нет данных за выбранный период."; otherwise heading + 24 vertical bars (`flex-1 bg-slate-700 rounded-sm`, `h-32` container, `gap-1`) with per-bar inline `height: {pct}%; min-height: 2px|0;` + `title="{hour_label} — {count} событий"`, followed by an x-axis row showing only first and last `hour_label`. `role="img"` + `aria-label` per UI-SPEC accessibility contract.
- **`GET /_partials/audit/timeline`** — cookie-authenticated HTMX endpoint. Whitelists `decision` ∈ {allow, deny, error, ""}, accepts but ignores `timeframe` (chart window fixed at 24h), calls `timeline_buckets(hours=24, …)`, computes `max_count`, returns the partial as a pure HTML fragment (no `<html>`/`<body>`).
- **`/audit` page handler upgrade** — now precomputes `buckets` + `max_count` so the initial server render already shows real bars (eliminates flash-of-empty before first HTMX poll). The obsolete `timeline_partial_available` placeholder from PLAN 04 is removed.
- **`audit_feed.html`** — timeline card unconditionally includes the partial; outer card keeps `hx-get`/`hx-trigger="every 30s"`/`hx-include="closest form"` so polling replaces only the inner partial markup.

## Test Coverage

11 new integration tests in `tests/integration/test_audit_timeline_partial.py`:

| Scenario | Test |
|----------|------|
| Auth gate | `test_timeline_partial_anonymous_redirects_or_401` |
| Empty DB → empty-state copy | `test_timeline_partial_empty_db_shows_empty_state` |
| Response is fragment (no `<html>`/`<body>`) | `test_timeline_partial_is_fragment_not_full_page` |
| Seeded events → exactly 1 `min-height: 2px` + 23 zero bars | `test_timeline_partial_seeded_events_render_bar` |
| `tool_name` filter excludes other tools | `test_timeline_partial_filter_tool_name_excludes_others` |
| `machine_id` LIKE substring match | `test_timeline_partial_filter_machine_id_substring` |
| `decision` exact match | `test_timeline_partial_filter_decision_exact` |
| Invalid decision coerced to all | `test_timeline_partial_invalid_decision_coerced_to_all` |
| `timeframe` ignored at chart layer | `test_timeline_partial_timeframe_param_accepted_but_window_fixed_24h` |
| `/audit` initial render contains real bars | `test_audit_page_initial_render_has_real_bars` |
| HTMX polling attributes present | `test_audit_page_htmx_polling_wiring` |

Full suite: **336 passed** (baseline 325 → +11).

## Deviations from Plan

None — plan executed exactly as written.

## TDD Gate Compliance

- RED commit: `77566af test(01-05): add failing tests …`
- GREEN commit: `d35eb43 feat(01-05): implement GET /_partials/audit/timeline …`
- Task 1 (template-only, no behavior test) committed as `2b553de feat(01-05): add timeline partial template + flip audit_feed include` — its `<verify>` block is a Jinja render assertion executed inline before commit.
- No REFACTOR needed.

## Commits

| Hash | Message |
|------|---------|
| `2b553de` | feat(01-05): add timeline partial template + flip audit_feed include |
| `77566af` | test(01-05): add failing tests for /_partials/audit/timeline (RED) |
| `d35eb43` | feat(01-05): implement GET /_partials/audit/timeline endpoint (GREEN) |

## Threat Surface Notes

All STRIDE entries from the plan's `<threat_model>` are mitigated as designed:
- T-01-21 (Spoofing): endpoint uses `require_session` cookie dep (parity with `/audit`).
- T-01-22 (Tampering — SQL): filter params flow through bind-parametrized `timeline_buckets` (PLAN 03); `decision` whitelisted in handler.
- T-01-23 (XSS): Jinja2 autoescape on `.html`; `hour_label` is server-formatted via `strftime`, never user input.
- T-01-24 (Info Disclosure via tooltips): accepted — counts only, no per-event detail.

No new threat surface introduced (no new packages, no new auth surface, no new schema).

## Self-Check: PASSED

- File `src/ccguard/server/web/templates/components/_audit_timeline.html`: FOUND
- File `src/ccguard/server/web/templates/audit_feed.html`: FOUND (modified)
- File `src/ccguard/server/web/routes.py`: FOUND (modified)
- File `tests/integration/test_audit_timeline_partial.py`: FOUND
- Commit `2b553de`: FOUND
- Commit `77566af`: FOUND
- Commit `d35eb43`: FOUND
