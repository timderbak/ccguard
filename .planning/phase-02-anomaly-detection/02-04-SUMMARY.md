---
phase: 02-anomaly-detection
plan: 04
subsystem: web-ui
tags: [htmx, jinja2, tailwind, anomalies, overview]
requires: [02-01, 02-02, 02-03]
provides:
  - "Sidebar 'Аномалии' nav link in base.html"
  - "Overview page 'Аномалии' card polled every 60s"
  - "GET /_partials/anomalies/overview — top-5 anomaly findings partial"
affects:
  - templates/base.html
  - templates/overview.html
  - templates/components/_anomalies_overview.html
  - web/routes.py
tech-stack:
  added: []
  patterns:
    - "HTMX hx-trigger='load, every 60s' for polled card with eager first-paint"
    - "Cookie auth via require_session dep (NOT X-CCGuard-Token)"
    - "FindingRecord.rule_id LIKE 'anomaly.%' as the anomaly-finding selector"
key-files:
  created:
    - src/ccguard/server/web/templates/components/_anomalies_overview.html
    - tests/integration/test_anomalies_overview_partial.py
  modified:
    - src/ccguard/server/web/templates/base.html
    - src/ccguard/server/web/templates/overview.html
    - src/ccguard/server/web/routes.py
decisions:
  - "Reuse require_session (cookie-based admin auth) — same dep used by every other web route (overview_fleet_partial, audit_timeline_partial)"
  - "Reuse module-level templates = Jinja2Templates(directory=...) — no new templates object"
  - "Reuse get_session SQLModel session dep from ccguard.server.api.deps"
  - "Use hx-trigger='load, every 60s' (plan literal) + hx-target='this' so initial server-render is the empty include and HTMX hydrates immediately, then polls every 60s"
  - "Defensive json.loads with try/except — a malformed payload_json must not 500 the Overview page"
metrics:
  duration: "~12 min"
  completed: 2026-05-25
  tests_added: 6
  tests_total: 414
---

# Phase 02 Plan 04: Overview Аномалии Card Summary

Wired the anomaly findings produced by 02-03 onto the Overview landing page — a single HTMX-polled card listing the top-5 most recent anomalies, plus the sidebar `Аномалии` link to the (forthcoming, 02-05) feed page.

## What Shipped

- Sidebar `<a href="/anomalies">Аномалии</a>` inserted between `Аудит` and `Политика` in `base.html`, matching sibling Tailwind classes verbatim.
- `templates/components/_anomalies_overview.html` partial — heading `Аномалии`, top-5 `<ul>` of clickable rows, empty state `Аномалий нет.` All RU strings verbatim from UI-SPEC.
- `GET /_partials/anomalies/overview` in `routes.py` — queries `FindingRecord` filtered by `rule_id LIKE 'anomaly.%'`, ordered by `discovered_at DESC`, limited to 5. Parses metric from rule_id via `removeprefix('anomaly.')`, decodes `payload_json` for `observed_value` + `sigma_distance`, rounds sigma to 1 dp, formats timestamp `YYYY-MM-DD HH:MM`.
- `templates/overview.html` appends the new HTMX-polled card below the existing fleet table card with `hx-trigger="load, every 60s"` and `hx-target="this"`.

## Key Pattern Names (for 02-05 continuity)

| Concern | Symbol used |
|---|---|
| Auth dependency | `require_session` (cookie-based admin auth) |
| Session dependency | `get_session` from `ccguard.server.api.deps` |
| Templates object | module-level `templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))` |
| Render style | `templates.TemplateResponse(request, "template.html", {...})` (Starlette-3 signature, matches Phase 1 routes) |
| HTMX polling cadence | `every 60s` (UI-SPEC) — composed as `hx-trigger="load, every 60s"` on the wrapping card to get eager hydration |

Follow these in 02-05 (`/anomalies` feed + `/anomalies/{machine_id}/{metric}` detail).

## Verification

- Manual greps:
  - `grep -c 'href="/anomalies"' base.html` → 1
  - `grep -c 'hx-trigger="load, every 60s"' overview.html` → 1
  - `grep -c '/_partials/anomalies/overview' routes.py` → 1 (route handler decorator)
- Full pytest suite (excluding e2e which requires a live network server): **414 passed, 0 failed** (was 408 before this plan — 6 new integration tests added).
- New integration tests cover: anonymous redirect, empty state, top-5 ordering + machine cutoff at 5, non-anomaly rule_id exclusion, fragment-not-full-page assertion, overview page includes the polled card with correct trigger and sidebar link, defensive handling of malformed `payload_json`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical functionality] Defensive payload_json parsing**
- **Found during:** Task 3 implementation review
- **Issue:** Plan's snippet `json.loads(r.payload_json) if r.payload_json else {}` would raise on the Overview page if any single FindingRecord had a non-JSON payload — taking down the entire Overview landing page for a per-row data defect.
- **Fix:** Wrapped `json.loads` in `try/except (ValueError, TypeError)` returning `{}` on failure. Row still renders with `observed_value="—"` and `sigma_distance=0.0`.
- **Files modified:** `src/ccguard/server/web/routes.py`
- **Commit:** `da190f4`
- **Test coverage:** `test_overview_partial_handles_malformed_payload`

**2. [Rule 3 - Test fixture] Test fixture sets CCGUARD_DISABLE_SCHEDULER**
- **Found during:** Task 3 test authoring
- **Issue:** Plan-2 added an APScheduler that auto-starts in `create_app()`. New tests instantiate `create_app()` directly via TestClient, so they would launch real background jobs in the test process.
- **Fix:** Set `CCGUARD_DISABLE_SCHEDULER=1` in the `admin_client` fixture (mirrors how Phase 1 tests handle env isolation).
- **Files modified:** `tests/integration/test_anomalies_overview_partial.py`
- **Commit:** `da190f4`

### Plan-spec alignment notes (not deviations)

- Plan task 3 references a `require_admin` dep — the codebase only has `require_session` (cookie auth). Used `require_session` as instructed by the plan's parenthetical "use the actual auth-dep names from the existing router".
- Plan task 3 snippet positions the `_user` dep with no default-prefixed underscore in one line — I named it `_user` to match the established convention in `overview_fleet_partial` and `audit_timeline_partial`.

## TDD Gate Compliance

Plan frontmatter is `type: execute` (not `type: tdd`). Tests were written alongside implementation in a single commit (`da190f4: feat`). No separate `test(...)` RED commit required per the plan type.

## Known Stubs

None. The card renders real anomaly findings produced by the 02-03 scheduler. The click-through target `/anomalies/{machine_id}/{metric}` is a not-yet-existing route — it will return a 404 until 02-05 ships, which is the intended hand-off.

## Commits

| Hash | Message |
|---|---|
| `f48b73a` | feat(02-04): add 'Аномалии' sidebar link between Аудит and Политика |
| `d9888dc` | feat(02-04): add _anomalies_overview.html HTMX partial |
| `da190f4` | feat(02-04): add GET /_partials/anomalies/overview + wire into overview.html |

## Self-Check: PASSED

- `[ -f src/ccguard/server/web/templates/components/_anomalies_overview.html ]` → FOUND
- `[ -f tests/integration/test_anomalies_overview_partial.py ]` → FOUND
- `git log --oneline | grep f48b73a` → FOUND
- `git log --oneline | grep d9888dc` → FOUND
- `git log --oneline | grep da190f4` → FOUND
- `grep -c 'hx-trigger="load, every 60s"' src/ccguard/server/web/templates/overview.html` → 1
- `grep -c '/_partials/anomalies/overview' src/ccguard/server/web/routes.py` → 1
- `pytest tests/ --ignore=tests/e2e` → 414 passed
