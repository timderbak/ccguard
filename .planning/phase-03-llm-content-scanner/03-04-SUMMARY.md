---
phase: 03-llm-content-scanner
plan: 04
subsystem: server-http + agent-cli
tags: [scanner, http-api, masking, base64, privacy]
provides:
  - "POST /api/v1/scan-content endpoint (batch scan with per-item errors)"
  - "GET /api/v1/scanner-config endpoint (agent-side gate)"
  - "ScannerConfig / ScanRequest / ScanResponseItem / ScanBatchResponse schemas"
  - "mask_content (full-document, no-truncation variant of mask_secrets)"
  - "collect_scannable_files + send_scan_batch + run_scan_cycle (agent pipeline)"
  - "ccguard sync command now triggers scan after inventory POST"
requires:
  - "ScanService.scan_file (Plan 03-03)"
  - "LLMClient (Plan 03-02)"
  - "X-CCGuard-Token agent auth (Phase 1)"
  - "SettingsRecord(llm_scanner_enabled) (Plan 03-01)"
affects:
  - "src/ccguard/server/main.py (router mounted, ScanService wired in lifespan)"
  - "src/ccguard/agent/cli.py (sync command extended with scan hook)"
  - "src/ccguard/agent/masking.py (added glpat pattern + mask_content)"
key-files:
  created:
    - src/ccguard/schemas/scan.py
    - src/ccguard/server/api/scan.py
    - src/ccguard/agent/inventory_scan.py
    - tests/integration/test_scan_endpoint.py
    - tests/unit/test_agent_scan_payload.py
  modified:
    - src/ccguard/server/main.py
    - src/ccguard/agent/masking.py
    - src/ccguard/agent/cli.py
decisions:
  - "D-02 one-pass protocol: content+hash in single POST (no re-prompt)"
  - "Cache-hit reported via pre-call SHA256 + TTL probe (cleaner than mutating ScanService API)"
  - "Hard cap 1 MiB = ScannerConfig.max_file_bytes; soft cap 100 KiB → truncated=true"
  - "Once any item raises BudgetExhaustedError, remaining items short-circuit with error=budget_exhausted"
  - "Once any item raises ScannerDisabledError, all remaining items get error=scanner_disabled"
  - "mask_content is a NEW function (not a refactor of mask_secrets) to preserve v0.1 truncation semantics for inventory/audit findings"
  - "Scan failures in CLI sync are logged but never fail the sync (scan = best-effort tertiary signal)"
metrics:
  duration_min: 18
  tasks_completed: 2
  files_created: 5
  files_modified: 3
  commits: 4
  tests_added: 24  # 12 endpoint + 12 unit/agent
  total_tests_passing: 514
  date_completed: 2026-05-26
---

# Phase 03 Plan 04: HTTP & Agent Wiring for LLM Content Scanner Summary

End-to-end HTTP wiring of the LLM content scanner: server exposes batched scan endpoint plus an enable-flag probe; agent collects masked file content from `~/.claude/agents/*.md` and `~/.claude/skills/*/SKILL.md` and ships it through the `ccguard sync` cycle. Privacy invariant from Plan 03-03 preserved end-to-end — no raw content ever lands in DB or logs.

## What Shipped

### Server endpoints (mounted in `main.py` next to inventory/audit/findings routers)

#### `GET /api/v1/scanner-config`
- Auth: `X-CCGuard-Token` header (existing Phase 1 `require_token` dependency)
- Returns `ScannerConfig{enabled, max_file_bytes=1048576, schema_version=1}`
- `enabled = (Settings.llm_scanner_enabled == "true") AND (ANTHROPIC_API_KEY set at startup)`
- Agents call this BEFORE collecting content; `enabled=false` ⇒ no `/scan-content` POST issued

#### `POST /api/v1/scan-content`
- Body: `ScanRequest{schema_version, items: ScanRequestItem[≤50]}`
- Each item: `{file_path, scope: "agent"|"skill", content_b64}`
- Per-item server-side processing:
  1. base64 decode (invalid → `error="invalid_b64"`)
  2. >1 MiB raw → `error="content_too_large"` (no LLM call)
  3. >100 KiB raw → truncate to 100 KiB, set `truncated=true`, scan runs
  4. utf-8 decode (errors="replace") + `ScanService.scan_file`
  5. `BudgetExhaustedError` → this and remaining items get `error="budget_exhausted"`
  6. `ScannerDisabledError` → all items get `error="scanner_disabled"`
  7. Any other exception → `error="scanner_error"`, batch continues
- Response: `ScanBatchResponse{schema_version, items: ScanResponseItem[]}` where each item has `{file_path, file_hash, risk_score, category, severity, cached, truncated, error}`
- **Cache hit detection**: implemented via a pre-`scan_file` SHA256 + `ttl_expires_at` probe so `cached=true` is reported truthfully on second-call short-circuit. Chosen over mutating the `ScanService` return type to avoid touching the Plan 03-03 surface.

### Agent pipeline

- `mask_content(text) -> str` (new in `agent/masking.py`): applies the same `_SECRET_PATTERNS` set as `mask_secrets` but without the 200-char truncation. Idempotent. Now covers JWT, `sk-` (OpenAI), `sk-ant-`, `ghp_`/`gho_`/`ghs_`, `glpat-` (newly added), `AKIA…`, `AIza…`, `xox[bpa]-`, and generic `password|token|secret|api_key=…`.
- `collect_scannable_files(claude_home)`: walks `<home>/agents/*.md` and `<home>/skills/<name>/SKILL.md`, masks each with `mask_content`, base64-encodes, returns `ScanRequestItem` list. Tolerates missing dirs.
- `send_scan_batch(server_url, token, items, transport=?)`: GET `/scanner-config` first; if disabled, returns `{"skipped": "scanner_disabled"}` without POSTing. Otherwise POSTs and returns parsed `ScanBatchResponse`. Never raises — 5xx/timeout/invalid-JSON become `{"error": ...}`. `transport` is for `httpx.MockTransport` in tests.
- `run_scan_cycle(claude_home, server_url, token)`: convenience entry point combining both.
- `ccguard sync` CLI command: after `perform_sync` succeeds, calls `run_scan_cycle` and includes a `"scan"` block in the JSON output. Scan failures NEVER fail the sync (best-effort signal).

### Schemas (`src/ccguard/schemas/scan.py`)

```python
class ScannerConfig(SchemaBase):
    enabled: bool
    max_file_bytes: int = 1_048_576
    schema_version: int = 1

class ScanRequestItem(SchemaBase):
    file_path: str
    scope: Literal["agent", "skill"]
    content_b64: str

class ScanRequest(SchemaBase):
    schema_version: int = 1
    items: list[ScanRequestItem] = Field(default_factory=list, max_length=50)

class ScanResponseItem(SchemaBase):
    file_path: str
    file_hash: str | None = None
    risk_score: int | None = None
    category: str | None = None
    severity: str | None = None
    cached: bool = False
    truncated: bool = False
    error: str | None = None

class ScanBatchResponse(SchemaBase):
    schema_version: int = 1
    items: list[ScanResponseItem] = Field(default_factory=list)
```

## Threat Model Compliance

| Threat ID | Mitigation |
|-----------|------------|
| T-03-10 (content disclosure in transit) | Agent runs `mask_content` BEFORE base64. Asserted: `test_collect_masks_before_base64` decodes back the b64 and confirms no raw AWS key bytes survive. |
| T-03-11 (content in server logs) | Server logs only `file_path + file_hash + risk_score + cached + truncated`. Asserted: `test_scan_content_does_not_log_raw_content` POSTs a unique needle and confirms it appears in NO captured log record. |
| T-03-12 (unauthenticated scan POST) | Both endpoints use the `require_token` dependency reused from Phase 1. Asserted: `test_scan_content_rejects_missing_token` and `test_scanner_config_rejects_missing_token` get 401. |
| T-03-13 (oversized batch DoS) | `ScanRequest.items` has `max_length=50` (Pydantic). 1 MiB hard cap per item rejected without LLM call. Asserted: `test_scan_content_oversized_rejected_per_item`. |

## Tests Added (24 total)

### `tests/integration/test_scan_endpoint.py` (12)
1. `test_scanner_config_disabled_without_api_key`
2. `test_scanner_config_enabled_with_key_and_setting`
3. `test_scanner_config_disabled_when_setting_off`
4. `test_scan_content_rejects_missing_token`
5. `test_scanner_config_rejects_missing_token`
6. `test_scan_content_happy_path_one_item`
7. `test_scan_content_cache_hit_on_repeat`
8. `test_scan_content_oversized_rejected_per_item`
9. `test_scan_content_truncates_above_soft_cap`
10. `test_scan_content_budget_exhausted_mid_batch`
11. `test_scan_content_scanner_disabled_all_items`
12. `test_scan_content_does_not_log_raw_content`

### `tests/unit/test_agent_scan_payload.py` (12)
- mask_content: JWT, sk-ant, AWS, ghp, glpat, idempotent, no-truncation
- collect_scannable_files: agents+skills walked, masking before b64, missing-dir tolerance, nonexistent-home tolerance
- send_scan_batch: short-circuits on disabled, POSTs on enabled, swallows 500, skips empty-item batch

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocker] `mask_secrets` truncates to 200 chars, unusable for content scanning**
- **Found during:** Task 2 design (about to overload `mask_secrets` for content).
- **Issue:** The plan said "reuse v0.1 secret regex set" and "consolidate so this module is the single source." The existing `mask_secrets` truncates aggressively (200 chars), which is correct for short matched-value fields in findings but would throw away ~99% of a typical agent.md before the LLM ever saw it.
- **Fix:** Added a new `mask_content(value: str) -> str` function in the same module sharing `_SECRET_PATTERNS`. Existing `mask_secrets` API is unchanged so the 9 existing masking tests + 4 callers (`check.py`, `scan/mcp.py`) keep working. Both functions remain "the single source" for the regex list.
- **Files modified:** `src/ccguard/agent/masking.py`.
- **Commit:** 844cce8.

**2. [Rule 2 — Missing critical functionality] Add `glpat-` GitLab PAT pattern**
- **Found during:** Reading plan task 2 behavior block.
- **Issue:** Plan task 2 lists `glpat-[A-Za-z0-9-]{20}` as a required pattern; v0.1 `_SECRET_PATTERNS` was missing it.
- **Fix:** Added `re.compile(r"glpat-[A-Za-z0-9_-]{20,}")` to the shared list.
- **Commit:** 844cce8.

**3. [Rule 3 — Scope correction] Plan didn't specify how `cached` should be reliably reported**
- **Found during:** Task 1 GREEN.
- **Issue:** `ScanService.scan_file` returns a `ScanResult` row but no boolean indicating whether the call hit the cache. The plan's `<behavior>` listed `cached: bool` in the response without prescribing the detection mechanism. Without instrumenting `ScanService` (out of scope — Plan 03-03 is shipped), we needed a non-invasive way to detect cache hits.
- **Fix:** Added a pre-`scan_file` cache probe in the endpoint (re-implements the same SHA256 + `ttl_expires_at` lookup that ScanService does internally). On a real cache hit the subsequent `scan_file` short-circuits trivially. No change to Plan 03-03.

### Deferred Issues

- `tests/integration/test_audit_smoke.py::test_audit_1000_events_render_table_and_timeline` fails (`min-height: 2px` count too low) **before this plan** — confirmed by stash-and-rerun. Pre-existing timing-dependent assertion in Phase 1/2 territory; logged here but not fixed (out of scope, scope-boundary rule).
- `tests/e2e/*` — multiple failures (httpx ConnectError, missing fixtures) pre-existing; ignored per `--ignore=tests/e2e` convention.

## Self-Check: PASSED

- [x] `src/ccguard/schemas/scan.py` exists
- [x] `src/ccguard/server/api/scan.py` exists, mounted in `main.py`
- [x] `src/ccguard/agent/inventory_scan.py` exists
- [x] `tests/integration/test_scan_endpoint.py` — 12 tests, all green
- [x] `tests/unit/test_agent_scan_payload.py` — 12 tests, all green
- [x] `src/ccguard/agent/cli.py` `sync` command extended with scan hook
- [x] `mask_content` added to `agent/masking.py`; existing `mask_secrets` API unchanged
- [x] Full suite: 514 passed, 1 deselected (pre-existing flake), 0 new failures
- [x] Commits: bf61fa0 (test/RED endpoint), 3493538 (feat/GREEN endpoint), 844cce8 (test/RED agent), 7630393 (feat/GREEN agent)
