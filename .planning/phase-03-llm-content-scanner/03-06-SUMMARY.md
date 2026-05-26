---
phase: 03-llm-content-scanner
plan: 06
subsystem: testing
tags: [pytest, anthropic-mock, regression, fastapi-testclient, jinja-templates, asgi-transport]

requires:
  - phase: 03-llm-content-scanner
    provides: full Phase 3 stack (plans 01-05) — schemas, llm_client, scan_service, HTTP endpoints, agent pipeline, admin UI
provides:
  - end-to-end vertical-slice coverage from agent payload to rendered UI
  - locked-constant tripwires for D-01 (critical severity) and D-06 (Haiku 4.5 pricing)
  - byte-for-byte v0.1 masking regression assertion
  - phase-wide test-count floor (≥468) as T-03-17 mitigation
affects: [phase-04, future-llm-scanner-refactors, future-pricing-changes, future-masking-changes]

tech-stack:
  added: [unittest.mock.AsyncMock for SDK boundary mocking, httpx.MockTransport bridge for agent→TestClient flow]
  patterns:
    - "SDK boundary mock: patch anthropic.AsyncAnthropic at llm_client import site, return SimpleNamespace mimicking Message/content/usage shape"
    - "Agent→ASGI bridge: route httpx.MockTransport handler through FastAPI TestClient for sync send_scan_batch coverage"
    - "Tripwire tests: subprocess pytest --collect-only + locked-constant import asserts catch silent suite/decision drift"

key-files:
  created:
    - tests/integration/test_llm_phase_e2e.py
    - tests/integration/test_severity_critical_badge.py
    - tests/integration/test_agent_masking_regression.py
    - tests/unit/test_llm_phase_regression.py
  modified: []

key-decisions:
  - "Used httpx.MockTransport(handler) bridging into TestClient for the scanner_disabled e2e test rather than ASGITransport — ASGITransport is async-only and send_scan_batch uses sync httpx.Client"
  - "Test-count tripwire runs `pytest --collect-only` (no -q) because -q output omits the 'N tests collected' summary line; floor 468 kept conservative (current actual 553)"
  - "Mocked Anthropic at the SDK class boundary (anthropic.AsyncAnthropic) not at the wrapper level, so the test exercises the real _extract_tool_use + _parse_tool_use parsing path"

patterns-established:
  - "Phase-wide test-count floor as a tripwire — refactors that silently drop tests trip in CI before merge"
  - "Locked-constant import-and-assert pattern — D-06 pricing literals + D-01 severity round-trip prevent decision drift"

requirements-completed: [LLM-01, LLM-02, LLM-03, LLM-04]

duration: 18min
completed: 2026-05-26
---

# Phase 3 Plan 06: Regression & End-to-End Test Coverage Summary

**14 new tests stitching agent → API → DB → UI across the Phase 3 scanner stack, plus locked-constant tripwires for Haiku 4.5 pricing and critical severity, lifting total suite to 553 tests with full vertical-slice coverage of all D-01..D-06 decisions.**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-05-26
- **Completed:** 2026-05-26
- **Tasks:** 2
- **Files modified:** 4 (all new test modules)

## Accomplishments
- 4 e2e tests proving the full vertical slice (collect → mask → POST → scan_service → DB → UI badge) with Anthropic SDK mocked
- 4 badge-rendering tests asserting exact Tailwind class strings per severity band (`bg-red-600`, `bg-amber-600`, `bg-emerald-600`) plus em-dash branch for non-LLM rows
- 3 masking regression tests including byte-for-byte v0.1 inventory output lock and pre-send secret-leak coverage across all 6 pattern families
- 3 tripwire tests: D-06 Haiku 4.5 pricing literal, D-01 critical severity round-trip, ≥468 collected-test floor
- Full suite green (545 passed, 1 pre-existing failure deferred, no new failures)

## Task Commits

1. **Task 1: e2e vertical slice + severity badge UI tests** — `0cdc59b` (test)
2. **Task 2: masking regression + phase-wide tripwires** — `c46ef0e` (test)

**Plan metadata commit:** _(this commit)_

## Files Created/Modified
- `tests/integration/test_llm_phase_e2e.py` — 4 e2e tests: happy_path, cache_hit_avoids_second_call, budget_exhausted_mid_batch, scanner_disabled_path
- `tests/integration/test_severity_critical_badge.py` — 4 UI tests for the D-01 severity ladder rendered in /findings
- `tests/integration/test_agent_masking_regression.py` — 3 tests: v0.1 byte-for-byte lock, idempotency, pre-send 6-family leak check
- `tests/unit/test_llm_phase_regression.py` — 3 tripwires: Haiku pricing constants, critical round-trip, test-count floor

## Test Inventory by Plan

| Plan | New tests added (approx) | Focus |
|------|--------------------------|-------|
| 03-01 | ~16 | severity Literal, scan models, settings_service |
| 03-02 | ~14 | llm_client wrapper, parsing, fail-safe |
| 03-03 | ~18 | scan_service: cache, budget, lock, finding emit |
| 03-04 | ~24 | scan_endpoint, scanner-config, agent pipeline |
| 03-05 | ~24 | admin routes, findings UI extension, scheduler |
| 03-06 | 14 | e2e + badge + masking regression + tripwires |
| **Phase 3 total** | **~110** | (over the ≥25 floor) |

**Pre-Phase-3 baseline:** 443 tests
**Post-Phase-3 (current):** 553 tests
**Net Phase 3 contribution:** +110 tests

## Locked-Decision → Test-Name Mapping

| Decision | Lock | Test |
|----------|------|------|
| D-01 critical severity | bg-red-600 rendered for score>70 | `test_critical_score_renders_red` |
| D-01 critical severity | Pydantic Finding accepts critical AND preserves info/warn/block | `test_severity_critical_round_trip`, `test_finding_accepts_critical_severity` (03-01) |
| D-02 one-pass | Agent sends content+hash in single POST, no re-prompt | `test_scanner_e2e_happy_path` |
| D-03 scheduler/cache | Identical content second POST returns cached=true, mock.call_count stays 1 | `test_cache_hit_avoids_second_call` |
| D-04 threshold=30 + rule_id format | Finding emitted with `llm.scan.jailbreak` at score 85 | `test_scanner_e2e_happy_path` |
| D-04 budget gate | budget=2, item 3 returns error=budget_exhausted, 2 LLMCallLog rows | `test_budget_exhausted_mid_batch` |
| D-05 strict tool | Mock returns tool_use block; real _extract_tool_use path parses it | `test_scanner_e2e_happy_path` |
| D-06 Haiku 4.5 pricing | INPUT_CENTS_PER_MTOK==100, OUTPUT_CENTS_PER_MTOK==500, MODEL literal | `test_haiku_pricing_constant_locked` |
| T-03-10 mask-before-send | base64-decoded items contain none of 6 secret families | `test_content_scan_masks_before_send` |
| T-03-17 silent scope drop | pytest --collect-only ≥468 | `test_phase_3_test_count_baseline` |
| Masking refactor invariant | v0.1 mask_secrets output byte-for-byte unchanged | `test_v01_inventory_masking_unchanged` |
| Scanner-disabled UI | "Сканер выключен." rendered on /_partials/settings/llm-usage | `test_scanner_disabled_path` |

## Decisions Made
- **httpx.MockTransport over ASGITransport for agent-driver coverage** — ASGITransport is async-only and `send_scan_batch` uses sync `httpx.Client`. A small handler that re-routes requests through the in-process FastAPI TestClient gives identical wire semantics without crossing the sync/async boundary.
- **Test-count floor 468, not 553** — Conservative floor catches silent suite shrinkage (deleted modules, collapsed parametrize) without churning every time we add tests in future phases.
- **Mock at the SDK class import boundary** — patching `anthropic.AsyncAnthropic` (not the higher-level `LLMClient`) exercises the production parsing path (`_extract_tool_use`, `_parse_tool_use`) so refactors there are caught by the e2e tests.

## Deviations from Plan
None — plan executed exactly as written. The single adaptive choice (MockTransport bridge for the disabled-path test) was an action-step refinement, not a behavioral deviation: the test still asserts what the plan specified (agent calls /scanner-config → enabled=false → no POST → zero LLMCallLog).

## Issues Encountered
- **Pre-existing failure outside scope** — `tests/integration/test_audit_smoke.py::test_audit_1000_events_render_table_and_timeline` was already failing on `1a35762` (the Plan 03-05 metadata commit) before any Plan 06 work. Confirmed by checkout-and-rerun against the prior commit. Out-of-scope per executor deviation rules; logging here for the verifier. The full `tests/e2e/` directory also fails (subprocess-driven CLI tests requiring real network) — unchanged from baseline.

## Threat Flags
None — Plan 06 adds tests only, no new code surface.

## Next Phase Readiness
- Phase 3 is functionally complete: every locked decision now has an executable assertion test.
- Phase 4 can rely on `tests/integration/test_llm_phase_e2e.py` as the source-of-truth contract for the agent↔server scanner protocol; future changes to that wire format will trip these tests first.

## Self-Check: PASSED

- `tests/integration/test_llm_phase_e2e.py` — FOUND
- `tests/integration/test_severity_critical_badge.py` — FOUND
- `tests/integration/test_agent_masking_regression.py` — FOUND
- `tests/unit/test_llm_phase_regression.py` — FOUND
- commit `0cdc59b` (Task 1) — FOUND
- commit `c46ef0e` (Task 2) — FOUND
- Total collected tests: 553 ≥ 468 floor — PASS
- Plan-06 net new: 14 (8 + 3 + 3) — meets the 12+ target in plan objective

---
*Phase: 03-llm-content-scanner*
*Completed: 2026-05-26*
