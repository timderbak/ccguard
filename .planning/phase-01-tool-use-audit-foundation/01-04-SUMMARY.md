---
phase: 01-tool-use-audit-foundation
plan: 04
subsystem: server/web
tags: [audit, ui, jinja2, htmx]
requires: ["01-03"]  # tool_use_service.list_events
provides:
  - "GET /audit page (admin cookie-auth)"
  - "Sidebar nav link 'Аудит' between 'Находки' and 'Политика'"
  - "audit_feed.html + _audit_events_table.html templates"
  - "timeline_partial_available context flag (False; PLAN 05 flips to True)"
affects:
  - src/ccguard/server/web/templates/base.html
  - src/ccguard/server/web/routes.py
tech_stack:
  added: []  # no new deps
  patterns: ["GET-form filter echo", "Jinja partial include", "decision color tri-state"]
key_files:
  created:
    - src/ccguard/server/web/templates/audit_feed.html
    - src/ccguard/server/web/templates/components/_audit_events_table.html
    - tests/integration/test_audit_page.py
  modified:
    - src/ccguard/server/web/templates/base.html
    - src/ccguard/server/web/routes.py
decisions:
  - "Reused `findings_page` route shape (Depends order, cookie auth, template render)"
  - "Decision color tri-state computed inline in Jinja (no new filter)"
  - "Defensive query coercion: unknown decision → '' (all), unknown timeframe → '24h' (no 422)"
  - "Anonymous redirect test uses admin_client fixture (no cookie) because app.state.engine must be initialized before require_session dependency reaches HTML-accept branch"
metrics:
  duration_seconds: 220
  tasks_complete: 2
  tests_added: 12
  total_tests_passing: 325
  commits: 3
  completed: 2026-05-25
requirements: [TUA-03]
---

# Phase 1 Plan 04: /audit Page Scaffold Summary

GET /audit page with filter form + paginated events table; HTMX-polled timeline card placeholder awaiting PLAN 05 partial.

## What Was Built

- **Sidebar nav** — new `<a href="/audit">Аудит</a>` between Находки and Политика (single-line insertion in `base.html`)
- **`audit_feed.html`** — page heading, filter form (machine_id/tool_name/decision/timeframe with sr-only labels and focus rings per UI-SPEC § Accessibility), HTMX-polled timeline card (`hx-get=/_partials/audit/timeline every 30s`, `hx-include=closest form`) with empty-placeholder until PLAN 05 ships the partial, and events table card
- **`components/_audit_events_table.html`** — `<thead>` with 6 columns Когда / Машина / Инструмент / Решение / Результат / Fingerprint; each row uses `border-b last:border-0`; decision cell tri-state color (`text-emerald-600` / `text-red-600` / `text-amber-600`); `event.fingerprint[:10]` in mono; empty-state row `Аудит-событий нет.`; overflow `<tfoot>` row when `total > limit`
- **`GET /audit` route** — query params with FastAPI string coercion + defensive whitelist (`decision` → `""` if invalid; `timeframe` → `24h` if invalid); calls `tool_use_service.list_events(..., limit=200)`; renders `audit_feed.html` with `filters` dict, `events`, `total`, `limit`, `timeline_partial_available=False`

## How It Was Tested

`tests/integration/test_audit_page.py` — 12 tests using a new `admin_client` fixture that boots the full FastAPI app with env-configured admin hash + DB + session secret, mints a session cookie, and yields the `(client, engine, sid)` triple:

| # | Test | Asserts |
|---|------|---------|
| 1 | anonymous redirect | unauth GET → 307 Location:/login |
| 2 | empty DB | 200, page title, h2, empty-state row, sidebar link, Russian copy |
| 3 | default timeframe | `value="24h" selected` present |
| 4 | filter echo | machine_id/tool_name input values + decision/timeframe selected |
| 5 | 5 seeded events | 5 `/machines/{id}` links, no empty-state row |
| 6 | tool_name mismatch | empty-state row reappears |
| 7 | 250 events | overflow footer `Показано 200 из 250 событий за период.` |
| 8 | decision colors | all three color classes present in HTML |
| 9 | 7d timeframe expansion | 3-day-old event invisible at 24h, visible at 7d |
| 10 | invalid decision | coerced silently, event still rendered |
| 11 | invalid timeframe | coerced to 24h |
| 12 | machine_id[:12] | link href has full id, link body has first 12 chars |

**Full suite:** 325 / 325 non-e2e tests pass (pre-existing e2e failures verified unchanged via `git stash` regression check; they require a running `ccguard` binary that is unrelated to this plan).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] Anonymous-test fixture mismatch**
- **Found during:** Task 2 (first GREEN test run)
- **Issue:** Plan's `test_audit_anonymous_redirects_to_login` instantiated a bare `TestClient(create_app())` without going through the lifespan/env setup, so `get_session` (which is resolved by FastAPI before `require_session` in the dependency graph) raised `AttributeError: 'State' object has no attribute 'engine'` instead of producing the 307 redirect.
- **Fix:** Reuse the `admin_client` fixture (which env-configures admin hash + DB + session secret) but issue the request WITHOUT a `ccg_session` cookie. The route then traverses `get_session` (returns valid session) → `require_session` (no cookie + HTML accept → 307 to /login), matching the assertion.
- **Files modified:** `tests/integration/test_audit_page.py`
- **Commit:** 4c5810d

**2. [Rule 2 — Critical] CSRF token passed to template**
- **Found during:** Task 2 (defensive parity with sibling page handlers)
- **Issue:** Plan handler snippet omitted `csrf_token`. The base template's logout form needs `csrf_token` to render correctly under an authenticated session. Without it Jinja autoescape would emit `csrf_token=""`, producing a 403 on /logout from the audit page.
- **Fix:** Pass `_csrf_for(request)` into the template context (matches `findings_page`).
- **Files modified:** `src/ccguard/server/web/routes.py`
- **Commit:** 4c5810d

### Style alignment

Sticking with the existing `findings_page` precedent, I used `templates.TemplateResponse(request, "audit_feed.html", {...})` (positional `request`) rather than the plan's `templates.TemplateResponse("audit_feed.html", {"request": request, ...})` form. Both are valid; the positional form is what the rest of the file uses and is the modern Starlette signature.

## Known Stubs

| Stub | File | Line | Reason |
|------|------|------|--------|
| `timeline_partial_available=False` placeholder paragraph | `audit_feed.html` | timeline card body | **Intentional** per plan objective — PLAN 05 ships `components/_audit_timeline.html` and the partial endpoint `/_partials/audit/timeline`. Then PLAN 05 will flip the flag to `True`. Documented in plan's `<objective>`. |

## Threat Flags

None new. All surface introduced (`GET /audit` and template inputs) is already covered by the plan's `<threat_model>` T-01-17 / T-01-18 / T-01-19 entries. Jinja2 autoescape verified active for `.html` (default `Jinja2Templates` behavior); query params land in `LIKE %?%` via service-layer bind parameters (audited in PLAN 03).

## Self-Check: PASSED

- FOUND: src/ccguard/server/web/templates/audit_feed.html
- FOUND: src/ccguard/server/web/templates/components/_audit_events_table.html
- FOUND: tests/integration/test_audit_page.py
- FOUND: src/ccguard/server/web/templates/base.html (modified — new nav link)
- FOUND: src/ccguard/server/web/routes.py (modified — audit_page handler)
- FOUND commit: 3723d88 (templates)
- FOUND commit: 6aaef4c (RED tests)
- FOUND commit: 4c5810d (GREEN route + test adjust)
