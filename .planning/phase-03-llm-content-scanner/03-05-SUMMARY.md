---
phase: 03-llm-content-scanner
plan: 05
subsystem: server-web
tags: [ui, htmx, admin, llm-scanner]
provides:
  - LLM-scanner admin UI on /settings (toggle + budget + usage + last-10 + rescan-all)
  - /findings risk badge column + per-row HTMX re-scan + scope filter
  - APScheduler one-shot rescan-all hook (D-03)
requires:
  - 03-01 (SettingsRecord KV + ScanResult / LLMCallLog tables)
  - 03-02 (LLMClient / ScanOutcome contract)
  - 03-03 (ScanService — get_daily_usage shape mirrored synchronously)
  - 03-04 (FindingRecord.payload_json shape with file_hash/risk_score/category)
affects:
  - findings_feed.html (existing 4 cols preserved verbatim; +Риск +Действия)
  - settings.html (new LLM-сканер section appended below "О сервере")
  - routes.py /findings (new scope param; FindingRecord → VM with parsed details)
tech-stack:
  added: []
  patterns:
    - HTMX outerHTML row swap (first use in project)
    - APScheduler DateTrigger one-shot with inline fallback when scheduler disabled
key-files:
  created:
    - src/ccguard/server/web/templates/components/_risk_badge.html
    - src/ccguard/server/web/templates/components/_finding_row.html
    - src/ccguard/server/web/templates/components/_llm_usage_counter.html
    - tests/integration/test_llm_admin_routes.py
    - tests/integration/test_findings_ui_extension.py
  modified:
    - src/ccguard/server/web/templates/findings_feed.html
    - src/ccguard/server/web/templates/settings.html
    - src/ccguard/server/web/routes.py
    - src/ccguard/server/scheduler.py
decisions:
  - "Jinja attribute access on dicts (`finding.details.risk_score`) raises UndefinedError on missing keys → switched to `.get()` for safe access"
  - "rescan-all uses APScheduler one-shot when scheduler running; inline fallback when CCGUARD_DISABLE_SCHEDULER=1 (test path) keeps 303-redirect-then-GET semantics testable without spinning up the scheduler"
  - "Per-row /admin/scan/{file_hash}/rescan does NOT call the LLM — D-02 means server stores no content, so the route just invalidates the TTL and returns the existing finding row; budget/disabled surfaced as inline notice on the same <tr>"
  - "/findings rule_id and machine_id filters kept exact-match (==) to preserve existing test_web_smoke expectations rather than switching to fragment LIKE that UI-SPEC mentions as a target"
metrics:
  duration_minutes: 25
  completed: 2026-05-26
---

# Phase 3 Plan 5: LLM-Scanner Admin UI Summary

LLM-сканер admin surface wired end-to-end on /findings and /settings with the Russian-language copy locked verbatim per UI-SPEC, plus the APScheduler hook for the global "Пересканировать всё" button (D-03).

## Route Table

| Method | Path | Auth | Returns |
|--------|------|------|---------|
| GET    | /findings (extended) | cookie | findings_feed.html — now honors `?scope=all\|llm\|non_llm` |
| POST   | /admin/llm-settings | cookie + CSRF | 303 to /settings; or 200 with locked validation message on out-of-range budget |
| POST   | /admin/scan/{file_hash}/rescan | cookie + CSRF | 200 single `<tr>` partial; 404 if invalid/unknown hash |
| POST   | /admin/scan/rescan-all | cookie + CSRF | 303 to /settings (job enqueued or executed inline) |
| GET    | /_partials/settings/llm-usage | cookie | 200 usage counter partial |

## Template Inventory

| File | Action | Purpose |
|------|--------|---------|
| `components/_risk_badge.html` | create | Reusable pill (emerald/amber/red by 0-29/30-70/71-100) |
| `components/_finding_row.html` | create | Single `<tr>` partial; HTMX outerHTML swap target |
| `components/_llm_usage_counter.html` | create | Polled usage strip |
| `findings_feed.html` | edit | scope `<select>` + 2 new columns (Риск, Действия) |
| `settings.html` | edit | LLM-сканер section appended |

## Scheduler Hook

```python
def rescan_all_files(engine: Engine) -> None:
    """Expire every ScanResult.ttl_expires_at so the next agent inventory cycle repopulates."""

def enqueue_rescan_all(scheduler: AsyncIOScheduler | None, engine: Engine) -> None:
    """Enqueue one-shot job via DateTrigger(run_date=now); inline fallback if scheduler disabled."""
```

`RESCAN_ALL_JOB_ID = "llm-rescan-all"` with `replace_existing=True` so repeated admin clicks coalesce.

## Test Counts

| File | New tests |
|------|-----------|
| tests/integration/test_llm_admin_routes.py | 10 |
| tests/integration/test_findings_ui_extension.py | 7 |
| **Total new** | **17** |

Full-suite result (`pytest --ignore=tests/e2e`): **531 passed**, 1 deselected.

- The deselected test is `tests/integration/test_audit_smoke.py::test_audit_1000_events_render_table_and_timeline`, which was already failing on master before this plan (verified by `git stash` + re-run). It is unrelated to /findings, /settings, or the LLM scanner.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] Jinja `finding.details.risk_score` raised UndefinedError on missing keys**
- Found during: Task 2 first test run (after wiring routes).
- Issue: Jinja attribute access on a plain `dict` returns Undefined for missing keys; subsequent comparisons (`is not none`) and `< 30` raised `jinja2.exceptions.UndefinedError`.
- Fix: switched both `_risk_badge.html` and `_finding_row.html` to `.get('key')` style.
- Files modified: `_risk_badge.html`, `_finding_row.html`.
- Commit: 20edb4d.

**2. [Rule 2 — Critical functionality] scheduler.enqueue_rescan_all needed an inline fallback**
- Found during: writing test_rescan_all_expires_every_scan_result.
- Issue: in tests `CCGUARD_DISABLE_SCHEDULER=1` so `app.state.scheduler is None`; if the route enqueued a job it would silently no-op and the post-303 assertion would never see ttl_expires_at < now.
- Fix: `enqueue_rescan_all` falls back to synchronous `rescan_all_files(engine)` when scheduler is None or not running. Production still uses the async path.
- Files modified: `src/ccguard/server/scheduler.py`.
- Commit: 20edb4d.

**3. [Rule 2 — Critical functionality] CSRF token field added to per-row re-scan form**
- Found during: Task 1 review of UI-SPEC's HTMX snippet (which omits CSRF).
- Issue: All POST routes guard via `require_csrf` Form dep. UI-SPEC's snippet would have HTMX submit forms with no `csrf_token`, yielding 403.
- Fix: added `<input type="hidden" name="csrf_token" value="{{ csrf_token }}">` to the per-row form and the global `rescan-all` form. HTMX serializes hidden fields by default.
- Files modified: `_finding_row.html`, `settings.html`.
- Commit: cbdaafe (Task 1) + 20edb4d (Task 2).

## Russian Copy Spot-Check

```
$ grep -F "Пересканировать этот файл? Списание из дневного бюджета." \
       src/ccguard/server/web/templates/components/_finding_row.html
1
```

Plus tested verbatim by `test_per_row_form_carries_locked_hx_confirm_copy` and `test_llm_settings_post_invalid_budget_renders_validation_message`.

## Known Stubs

None — every UI surface is wired to live data:
- usage counter reads `LLMCallLog` + `SettingsRecord`
- last-10 scans reads `ScanResult ORDER BY scanned_at DESC LIMIT 10`
- per-row re-scan invalidates `ScanResult.ttl_expires_at` for real
- rescan-all expires every row (test-asserted)

## Self-Check: PASSED

Created files:
- `src/ccguard/server/web/templates/components/_risk_badge.html` — FOUND
- `src/ccguard/server/web/templates/components/_finding_row.html` — FOUND
- `src/ccguard/server/web/templates/components/_llm_usage_counter.html` — FOUND
- `tests/integration/test_llm_admin_routes.py` — FOUND
- `tests/integration/test_findings_ui_extension.py` — FOUND

Commits:
- `cbdaafe` (feat(03-05): add LLM-scanner UI templates per UI-SPEC) — FOUND
- `a094d72` (test(03-05): add failing tests for LLM admin routes + findings UI extension) — FOUND
- `20edb4d` (feat(03-05): wire LLM admin routes + scheduler rescan-all hook) — FOUND
