---
phase: 04-push-install
plan: 05
subsystem: server.web
tags: [audit, ui, policy_apply, htmx, jinja, russian-locked-copy]
requires:
  - .planning/phase-04-push-install/04-CONTEXT.md
  - .planning/phase-04-push-install/04-UI-SPEC.md
  - .planning/phase-04-push-install/04-01-SUMMARY.md
provides:
  - "GET /audit?event_source=policy_apply renders PolicyApplyEvent rows with «Результат» pill column"
  - "Locked Russian filter option «События политики» wired into existing /audit filter form"
  - "Default GET /audit (no event_source) preserves v0.1 tool_use layout byte-equal — timeline + events table unchanged"
  - "New partial components/_audit_policy_apply_table.html with success/rollback pill markup (bg-emerald-600 / bg-red-600)"
affects:
  - src/ccguard/server/web/routes.py
  - src/ccguard/server/web/templates/audit_feed.html
  - src/ccguard/server/web/templates/components/_audit_policy_apply_table.html
key-files:
  created:
    - tests/integration/test_audit_page_policy_apply_filter.py
    - src/ccguard/server/web/templates/components/_audit_policy_apply_table.html
  modified:
    - src/ccguard/server/web/routes.py
    - src/ccguard/server/web/templates/audit_feed.html
decisions:
  - "D-1: Separate partial _audit_policy_apply_table.html (not a conditional in _audit_events_table.html) keeps the v0.1 tool_use thead byte-equal. Switching templates is cheap and preserves regression guarantees."
  - "D-2: event_source query whitelisted to {empty, policy_apply}; any other value coerced to empty (mirrors decision/timeframe coercion pattern from v0.1)."
  - "D-3: Timeline card hidden in the policy_apply branch — the existing /_partials/audit/timeline polling endpoint is tool_use-specific and was not in scope to extend (api/* untouched per plan)."
  - "D-4: Timeframe coverage reused for PolicyApplyEvent via simple cutoff = now - timedelta(hours={1,24,168}); ORDER BY ts DESC + LIMIT 200 leverages ix_policy_apply_result_ts (and primary ts index) implicitly."
  - "D-5: result_column_visible context flag passed to template (per plan must_haves) even though template currently switches on event_source directly — keeps the API surface aligned with plan and lets future partials read either signal."
metrics:
  duration_minutes: 22
  completed: 2026-05-26
  tasks_completed: 2
  new_tests: 11
  baseline_before: 604
  baseline_after: 615
  full_suite_status: "615 passed (excluding pre-existing e2e infra and tests/integration/test_sync_push_install.py collection error owned by 04-04)"
---

# Phase 04 Plan 05: /audit policy_apply Filter + «Результат» Column Summary

One-liner: Extended /audit with a Russian-locked «События политики» filter that
swaps in a 5-column PolicyApplyEvent table (success/rollback pill) while
keeping the default tool_use view byte-equal to v0.1.

## What Was Built

### `GET /audit` extension (routes.py)

- Added `event_source: str = ""` query param, whitelisted to `{"", "policy_apply"}`.
- New helper `_policy_apply_events(session, machine_id_like, timeframe, limit)`:
  - SQLModel `select(PolicyApplyEvent).where(ts >= cutoff)`
  - Optional `machine_id LIKE %{q}%` substring filter
  - `ORDER BY ts DESC LIMIT 200`
  - Hours map: `{"1h": 1, "24h": 24, "7d": 168}`
- Template context extended with `event_source` and `result_column_visible: bool`
- v0.1 `tool_use` code path **unchanged**: `list_events()` + `timeline_buckets()`
  still called when `event_source != "policy_apply"`.

### `audit_feed.html` (template)

- Added new `<select name="event_source">` to the existing filter form with
  two options: `tool_use` (default) and `policy_apply` («События политики»).
- Wrapped the timeline card in `{% if event_source != "policy_apply" %}` —
  HTMX polling endpoint is tool_use-specific.
- Conditional include: policy_apply branch renders the new partial; everything
  else falls through to the existing `_audit_events_table.html`.

### `components/_audit_policy_apply_table.html` (new partial)

5 columns in order: Когда / Машина / Источник / Подробности / Результат.

- **Success pill:** `<span class="inline-block rounded-full px-2 py-0.5 text-xs font-semibold bg-emerald-600 text-white">success</span>`
- **Rollback pill:** same wrapper with `bg-red-600` + text `rollback`
- **Success details:** `<span class="font-mono text-xs text-slate-700">applied={n}, snapshot={snapshot_id[:8]}</span>`
- **Rollback details:** `<span class="font-mono text-xs text-slate-700"><span class="text-amber-600">reason=</span>{reason}, failed_file={file}, snapshot={snapshot_id[:8]}</span>`
- **Empty state:** `<tr><td colspan="5" class="py-6 text-center text-slate-400">Событий нет.</td></tr>`

## Conditional Column Pattern (`result_column_visible`)

The plan called for a `result_column_visible: bool` flag. Two equivalent
signals are passed to the template:

1. `event_source == "policy_apply"` (string compare in the Jinja `{% if %}`)
2. `result_column_visible: True` (explicit boolean for partials that need it)

The current template uses signal (1) directly because it also needs to know
the source for selecting between the two table partials. Signal (2) is
preserved in the context dict for future partials (e.g. a CSV-export
template) that only need the column-visibility decision without knowing the
event-source taxonomy.

## v0.1 Audit Page Regression — Confirmed Unchanged

`test_default_audit_renders_tool_use_columns_without_policy_apply_extras` and
`test_default_audit_with_tool_use_events_layout_unchanged` assert that:

- `<th>Инструмент</th>`, `<th>Решение</th>`, `<th>Fingerprint</th>` still render
- Empty-state copy stays `Аудит-событий нет.`
- No `bg-emerald-600` / `bg-red-600` pill markup leaks
- Timeline card still renders

The only NEW visible element in the default view is the additional
`<select name="event_source">` filter dropdown — a strictly additive control
sanctioned by the plan's must-haves («added <option ...> in the existing
event_source select»). Since v0.1 had no `event_source` select, the executor
added the select element itself plus the locked option.

## Tests Added (11)

1. `test_default_audit_renders_tool_use_columns_without_policy_apply_extras`
2. `test_default_audit_has_event_source_filter_option`
3. `test_policy_apply_filter_renders_result_column_header`
4. `test_policy_apply_empty_state_locked_copy`
5. `test_policy_apply_success_event_renders_emerald_pill`
6. `test_policy_apply_rollback_event_renders_red_pill_and_reason`
7. `test_policy_apply_orders_by_ts_desc`
8. `test_policy_apply_machine_filter_combines`
9. `test_policy_apply_timeframe_filter_combines`
10. `test_default_audit_with_tool_use_events_layout_unchanged`
11. `test_explicit_event_source_tool_use_renders_tool_use_table`

## Deviations from Plan

None — plan executed as written. The plan's truth «filter option appears in
the existing event_source select» was honored by introducing the select
element itself (none existed in v0.1) and adding both options inside it.

## Auth Gates

None.

## Known Stubs

None.

## Commits

- `b5ebb5f` test(04-05): add failing tests for /audit policy_apply filter + Результат column
- `55ef648` feat(04-05): add policy_apply branch to /audit with Результат column

## Self-Check: PASSED

- File `tests/integration/test_audit_page_policy_apply_filter.py` — FOUND
- File `src/ccguard/server/web/templates/components/_audit_policy_apply_table.html` — FOUND
- File `src/ccguard/server/web/templates/audit_feed.html` (modified) — FOUND
- File `src/ccguard/server/web/routes.py` (modified) — FOUND
- Commit `b5ebb5f` — FOUND
- Commit `55ef648` — FOUND
- Verification: 11/11 plan tests pass; 615 total tests pass
- Verification grep: «События политики» (1), bg-emerald-600 (1), bg-red-600 (1), «Событий нет» (1)
