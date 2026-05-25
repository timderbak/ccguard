---
phase: 01-tool-use-audit-foundation
plan: 06
subsystem: tests / phase-closure
tags: [tests, integration, e2e, smoke, regression, backward-compat, privacy]
requires: ["01-01", "01-02", "01-03", "01-04", "01-05"]
provides:
  - "Operational e2e validation of the full agent -> server audit stack"
  - "Regression guards for v0.1 endpoints (/health, /api/v1/inventory, /api/v1/policy)"
  - "Privacy invariant test (no raw tool_input on the wire) — T-01-07"
  - "Russian UI copy lockdown"
affects:
  - tests/conftest.py
  - tests/integration/test_audit_flush_e2e.py
  - tests/integration/test_audit_smoke.py
tech-stack:
  added: []
  patterns:
    - "httpx.MockTransport handler routing flusher POSTs into in-process TestClient"
    - "monkeypatch _buffer_path / _lock_path / load_or_create / derive_machine_id to isolate flusher in tmp_path"
key-files:
  created:
    - tests/integration/test_audit_flush_e2e.py
    - tests/integration/test_audit_smoke.py
    - .planning/phase-01-tool-use-audit-foundation/deferred-items.md
  modified:
    - tests/conftest.py
decisions:
  - "Privacy regression scans recursively for any of {tool_input, command, file_path, content, prompt} on the POST body — adding any such key in the future fails this test"
  - "5xx retry test patches httpx separately (not via the shared helper) to avoid layered MonkeyPatch transport replacement"
  - "trim_to_cap assertion uses a weaker invariant (<=10_000) because the flusher's 3-attempt cap will not drain 10_100 rows in one invocation"
  - "pre-existing tests/e2e/* failures deferred (require external services); they fail on master independent of this plan"
metrics:
  duration_minutes: ~25
  completed: 2026-05-25
---

# Phase 1 Plan 06: Phase-1 Closure Tests Summary

Validated the full Phase 1 stack — agent buffer (01-01) -> hook + flusher (01-02) -> server endpoint (01-03) -> /audit page (01-04) -> timeline partial (01-05) — with two new integration test files. No production code changes; only tests + a small `tests/conftest.py` helper extension.

## Tasks

| # | Task                                                                            | Tests added | Commit  |
| - | ------------------------------------------------------------------------------- | ----------- | ------- |
| 1 | Conftest seed helper + 7-case agent flusher -> POST /api/v1/audit end-to-end    | 7           | b7b629b |
| 2 | 13-case /audit page + timeline smoke + v0.1 backward-compat regression          | 13          | b125ce8 |

**Total new tests in 01-06: 20**

## Key Files

**Created:**
- `tests/integration/test_audit_flush_e2e.py` — 7 cases covering happy-path drain, schema-major mismatch, 200-event chunking, 5xx retry/backoff, missing-token 401, trim_to_cap invariant, and the **privacy boundary regression** (recursive key scan on every POST body).
- `tests/integration/test_audit_smoke.py` — 13 cases: 1000-event render with overflow footer + timeline bars, filter narrowing (tool_name + machine_id LIKE), decision color codepath, HTMX wiring, Russian UI copy lockdown, timeline partial empty + populated standalone, sidebar nav regression, v0.1 endpoint backward-compat.
- `.planning/phase-01-tool-use-audit-foundation/deferred-items.md` — pre-existing `tests/e2e/*` failures (need external services).

**Modified:**
- `tests/conftest.py` — added `seed_tool_use_events` bulk-insert helper and `random_fingerprint`. Both are imported directly by the smoke tests.

## Deviations from Plan

None of Rule 4 magnitude. Two minor inline fixes (Rule 3):

1. **Health endpoint path** — plan listed `/api/v1/health`; the actual mount is `/health` (unauthenticated by design, no `/api/v1` prefix). Fixed the backward-compat assertion to match the real mount. No production code change.
2. **5xx retry test transport wiring** — `monkeypatch.setattr(httpx.Client, "__init__", ...)` called twice through the shared helper resulted in the second patch wrapping the first and dropping our counting transport. Inlined the agent-side patches for that one test and installed the counting transport directly. Pure test-only refactor.

Neither deviation affects production code.

## Test Counts

Plan success criterion (per ROADMAP item 5): **>=20 new tests across Phase 1.**

```
$ grep -rc "^def test_" tests/unit/test_audit_*.py tests/unit/test_tool_use_service.py tests/integration/test_audit_*.py
tests/unit/test_audit_fingerprint.py:21
tests/unit/test_audit_buffer.py:16
tests/unit/test_audit_schemas.py:12
tests/unit/test_audit_hook_main.py:12
tests/unit/test_audit_flusher.py:16
tests/unit/test_tool_use_service.py:20
tests/integration/test_audit_api.py:13
tests/integration/test_audit_page.py:12
tests/integration/test_audit_timeline_partial.py:11
tests/integration/test_audit_flush_e2e.py:7  ← new in 01-06
tests/integration/test_audit_smoke.py:13      ← new in 01-06
TOTAL: 153
```

**153 audit tests** in the Phase 1 surface — more than 7× the success threshold.

## Verification

- `.venv/bin/pytest tests/ --ignore=tests/e2e` → **356 passed, 48 warnings in 13.13s**
- `tests/e2e/*` excluded (pre-existing failures requiring external services — documented in `deferred-items.md`).

## Threat-model coverage

| Threat | Disposition | Where validated |
| ------ | ----------- | --------------- |
| T-01-07 (privacy: raw tool_input on the wire) | mitigate | `test_flush_payload_contains_no_raw_tool_input_keys` recursively scans every POST body |
| T-01-02/03 (buffer concurrency + DoS) | mitigate (validated previously in 01-01) | `test_flush_trims_buffer_to_cap_after_success` confirms `trim_to_cap` invariant under real load |

## Self-Check: PASSED

- File exists: `tests/integration/test_audit_flush_e2e.py` — FOUND
- File exists: `tests/integration/test_audit_smoke.py` — FOUND
- File exists: `tests/conftest.py` — FOUND (modified)
- File exists: `.planning/phase-01-tool-use-audit-foundation/deferred-items.md` — FOUND
- Commit b7b629b — FOUND
- Commit b125ce8 — FOUND

---

# Phase 1 Closure Note

All 6 plans (01-01 .. 01-06) complete. ROADMAP success criteria evidence:

| # | Criterion | Plan | Evidence |
| - | --------- | ---- | -------- |
| 1 | Agent logs tool-use to local SQLite buffer | 01-01, 01-02 | `tests/unit/test_audit_buffer.py` (16 cases), `tests/unit/test_audit_hook_main.py` (12 cases), `tests/integration/test_audit_flush_e2e.py::test_flush_happy_path_drains_buffer_and_persists_server_rows` |
| 2 | `POST /api/v1/audit` accepts batches up to 200 events | 01-03 | `tests/integration/test_audit_api.py` (13 cases), `tests/unit/test_tool_use_service.py` (20 cases) |
| 3 | `/audit` page with filters (machine_id, tool_name, decision, timeframe) | 01-04 | `tests/integration/test_audit_page.py` (12 cases) + `tests/integration/test_audit_smoke.py::test_audit_filter_*` |
| 4 | Timeline at 24h with hourly bucket grouping | 01-05 | `tests/integration/test_audit_timeline_partial.py` (11 cases) + `tests/integration/test_audit_smoke.py::test_audit_1000_events_render_table_and_timeline` |
| 5 | 185+ existing tests green + >=20 new | 01-06 | 356 passed (unit + integration); 153 audit tests cumulative; 20 new in 01-06 |

**TUA-01, TUA-02, TUA-03 all green.** No production code regressions. PreToolUse enforce-shim untouched (existing 9 install tests + behavior unchanged — verified by full-suite green).
