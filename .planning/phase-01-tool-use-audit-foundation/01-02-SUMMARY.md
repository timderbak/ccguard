---
phase: 01-tool-use-audit-foundation
plan: 02
subsystem: agent.audit_hook
tags: [tool-use-audit, post-tool-use, schemas, install, agent]
requires: ["01-01"]
provides:
  - "ccguard-audit-bin console_script"
  - "PostToolUse hook registration in settings.json"
  - "Detached subprocess flusher → /api/v1/audit"
  - "ccguard.schemas.tool_use module (SCHEMA_VERSION_AUDIT='0.2')"
affects: ["agent.install", "schemas (new shared module for plan 01-03)"]
key-files:
  created:
    - src/ccguard/schemas/tool_use.py
    - src/ccguard/agent/audit_hook/hook_main.py
    - src/ccguard/agent/audit_hook/flusher.py
    - src/ccguard/agent/audit_hook/flusher_main.py
    - src/ccguard/agent/audit_main.py
    - tests/unit/test_audit_schemas.py
    - tests/unit/test_audit_hook_main.py
    - tests/unit/test_audit_flusher.py
  modified:
    - src/ccguard/agent/install.py
    - tests/unit/test_install.py
    - pyproject.toml
decisions:
  - "Flusher uses Unix double-fork (with Popen+start_new_session fallback) per RESEARCH Pitfall #1 — daemon-thread would be killed when the 20ms hook process exits"
  - "decision field hardcoded to 'allow' for all PostToolUse events (PreToolUse already gated the call); deny/error reserved for future hook events"
  - "result_status derived from tool_response: explicit error trumps interrupted flag → 'error' / 'blocked' / 'success'"
  - "install_hook returns hooks_added=PreToolUse-only to preserve v0.1 test contract; new audit_hooks_added surfaced separately"
  - "Audit shim is fail-silent (exit 0 if no python/binary found) — audit failure must never block tool use"
metrics:
  duration: "single session"
  tasks_completed: 2
  files_created: 8
  files_modified: 3
  tests_added: 50  # 12 schemas + 13 hook_main + 15 flusher + 10 install
  unit_tests_total_after: 240
---

# Phase 01 Plan 02: PostToolUse Hook + Detached Flusher Summary

Working PostToolUse audit pipeline: ccguard-audit-bin entrypoint, stdin parser with privacy-preserving fingerprinting, Unix double-fork flusher posting AuditBatchIn batches to `/api/v1/audit`, and `ccguard install` extension that wires the hook with matcher `["*"]` into settings.json — all backwards-compatible with the existing PreToolUse enforce shim.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Schemas + hook_main + flusher | `ec2286c` | schemas/tool_use.py, agent/audit_hook/{hook_main,flusher,flusher_main}.py + 3 test files |
| 2 | audit_main + install PostToolUse | `d3676a5` | agent/audit_main.py, agent/install.py, pyproject.toml, tests/unit/test_install.py |

## Architecture

### Privacy invariant (T-01-07)

`hook_main.main_cli` is the *only* place raw `tool_input` exists in agent memory. After `compute_fingerprint(tool_name, tool_input)` returns the 16-hex digest, the local is dropped via explicit `del tool_input`. The buffer schema (from plan 01-01) has no column for raw input; the wire schema (`ToolUseEventIn` in `ccguard.schemas.tool_use`) deliberately defines no `tool_input` field. Test `test_raw_tool_input_never_in_buffer` SQL-inspects every cell of every row and asserts the original command string is absent.

### Hot-path latency (T-01-09)

Hook body: parse stdin → fingerprint → `BEGIN IMMEDIATE` INSERT → maybe-fork → return. The httpx import, pydantic batch construction, and POST happen exclusively in the grandchild process after a double-fork. Test `test_execution_under_100ms` asserts second-invocation wall-clock < 100ms (real budget is <20ms, padded for CI noise).

### Detached subprocess (RESEARCH Pitfall #1)

`flusher.maybe_spawn_flusher`:

1. Threshold check `_should_spawn`: True if `row_count >= 50` OR pidfile absent/stale (>30s old).
2. Lock acquire `_acquire_lock`: write PID to `~/.ccguard/audit_flush.lock` atomically (tmp + rename); refuse if existing lock is <5s fresh.
3. If `os.fork` available → double-fork (parent reaps intermediate child, grandchild calls `_run_flush_loop` with stdio redirected to /dev/null).
4. Else → `subprocess.Popen([sys.executable, "-m", "ccguard.agent.audit_hook.flusher_main"], start_new_session=True, close_fds=True, std{in,out,err}=DEVNULL)`.

### Flush loop

`_run_flush_loop` (in the grandchild, never on the hot path):

- Lazy-import httpx + load_or_create + derive_machine_id (no cost to the hook).
- Loop: `drain(200)` → build `AuditBatchIn(schema_version="0.2", machine_id, events)` → POST `f"{url}/api/v1/audit"` with `X-CCGuard-Token` header → on 2xx `delete_ids` + reset attempts; on failure `attempts += 1`, sleep `(1, 2, 4)s`, retry up to `_MAX_ATTEMPTS=3`.
- Repeats while `row_count() > 0`, so a 250-row buffer is drained in two batches of 200 + 50.
- Malformed rows in the buffer are deleted (don't wedge the flusher).
- After loop: `trim_to_cap(10_000)` (T-01-03 DoS guard).

### Install layout

`install.install_hook` now writes:

```json
{
  "hooks": {
    "PreToolUse":  [<entries for HOOK_MATCHERS=["Bash","mcp__.*","WebFetch","WebSearch"]>],
    "PostToolUse": [{"matcher": "*", "hooks": [{"type":"command","command":"~/.ccguard/bin/ccguard-audit","timeout":3}]}]
  }
}
```

PreToolUse path is byte-identical to v0.1; the refactor extracted a shared `_install_event(hook_event, matchers, shim, timeout)` helper. Idempotency is checked by `(hook_type, command_path)` pair. `verify_installation` returns `audit_hook_registered: bool` and flags missing audit-shim or PostToolUse matcher.

### Schemas as single source of truth

`ccguard.schemas.tool_use` is imported by:

- agent flusher (`flusher._run_flush_loop` builds `AuditBatchIn`)
- server router (plan 01-03 will import the same `SCHEMA_VERSION_AUDIT`, `AuditBatchIn`, `AuditBatchOut`)

This prevents the agent and server from drifting on event-list bounds, fingerprint regex, or schema version.

## Verification Results

- **Unit tests**: `240/240 passing` (190 pre-existing + 50 new).
  - 12 `test_audit_schemas.py` — pydantic validation matrix (literals, patterns, min/max event count, no `tool_input` field).
  - 13 `test_audit_hook_main.py` — happy path, decision always `allow`, all three `result_status` branches, malformed JSON / empty stdin / non-dict / missing `tool_name` → fail-open, raw command string absent from SQL, <100ms budget, internal exception swallowed.
  - 15 `test_audit_flusher.py` — `_should_spawn` matrix, `_acquire_lock` freshness, no-fork → subprocess.Popen with `start_new_session=True`, fork → double-fork, drain → POST → delete on 200, backoff `[1, 2]` on failure with rows preserved, chunking when `row_count > _MAX_BATCH`, `trim_to_cap(10_000)` called after success.
  - 10 new install tests — PostToolUse entry shape (matcher `*`, timeout 3, command path), idempotency, Pre+Post coexistence, foreign post-hook preservation, hooks-section-from-scratch, verify reports `audit_hook_registered`, verify detects missing audit shim, uninstall removes audit hook + shim, uninstall keeps foreign post hooks.
- **Lint**: `ruff check src/ccguard/agent/audit_hook/ src/ccguard/agent/audit_main.py src/ccguard/agent/install.py src/ccguard/schemas/tool_use.py` clean.
- **Regression**: all 9 pre-existing install tests pass unmodified (PreToolUse contract preserved).

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 1 - Bug] `install_hook` return contract drift**
- **Found during:** Task 2, running existing install tests.
- **Issue:** Initial implementation summed PreToolUse + PostToolUse into `hooks_added`. Existing test `test_install_creates_shim_and_writes_hooks` asserts `result["hooks_added"] == len(install.HOOK_MATCHERS)` (4) — would have failed with 5.
- **Fix:** Split `hooks_added` (PreToolUse count, preserves v0.1 contract) from new `audit_hooks_added` field. Plan explicitly required "PreToolUse handling MUST be untouched" — this preserves the return-dict shape.
- **Files modified:** src/ccguard/agent/install.py
- **Commit:** d3676a5

**2. [Rule 2 - Missing Critical] Audit shim writer + tamper check**
- **Found during:** Task 2, planning install extension.
- **Issue:** Plan said "resolve the audit binary path the same way enforce binary path is resolved." The existing PreToolUse pattern writes a bash shim at `~/.ccguard/bin/ccguard-enforce` (not a direct path to the entry point) carrying `SHIM_MARKER` for tamper detection. Mirroring this is required for `verify_installation` to detect a tampered audit hook.
- **Fix:** Added `audit_shim_path()`, `write_audit_shim()`, `AUDIT_SHIM_MARKER` plus the marker check in `verify_installation`. Audit shim is fail-silent (vs. enforce's fail-open) since an audit miss is data loss, not a security regression.
- **Files modified:** src/ccguard/agent/install.py
- **Commit:** d3676a5

**3. [Rule 1 - Bug] ruff SIM105 in refactored install.uninstall**
- **Found during:** Task 2, final lint.
- **Issue:** Refactor moved a pre-existing `try/except OSError: pass` block into a loop iterating both shims; ruff flagged it.
- **Fix:** Replaced with `contextlib.suppress(OSError)`.
- **Files modified:** src/ccguard/agent/install.py
- **Commit:** d3676a5

## Threat Model Mitigations Applied

| Threat ID | Mitigation | Evidence |
|-----------|------------|----------|
| T-01-05 | Top-level `try/except Exception: return 0` in `main_cli` | `test_malformed_json_fails_open`, `test_internal_exception_swallowed` |
| T-01-06 | Reuses `X-CCGuard-Token` header pattern from sync.py | `test_run_flush_loop_drains_on_success` asserts header sent |
| T-01-07 | `del tool_input` after fingerprint; no schema field; SQL inspection in test | `test_raw_tool_input_never_in_buffer`, `test_no_tool_input_field_exists` |
| T-01-08 | Idempotency by (matcher_set, command_path) for both Pre and Post | `test_install_is_idempotent_for_audit_hook` |
| T-01-09 | Detached flusher; no httpx/pydantic import on hot path | `test_execution_under_100ms` |
| T-01-SC | No new third-party packages (httpx already pinned) | pyproject.toml diff |

## Coordination with Plan 01-03

The server router that plan 01-03 will implement should import:

```python
from ccguard.schemas.tool_use import (
    SCHEMA_VERSION_AUDIT,
    AuditBatchIn,
    AuditBatchOut,
)
```

The agent stamps `schema_version=SCHEMA_VERSION_AUDIT` into every batch. The server should validate `AuditBatchIn` via FastAPI dependency-injection and respond with `AuditBatchOut(server_schema_version=SCHEMA_VERSION_AUDIT, ...)` so clients can detect drift.

URL contract: `POST /api/v1/audit` with body `AuditBatchIn.model_dump_json()` and headers `{"Content-Type": "application/json", "X-CCGuard-Token": <token>}`.

## Self-Check: PASSED

Files referenced as created:
- `src/ccguard/schemas/tool_use.py` — FOUND
- `src/ccguard/agent/audit_hook/hook_main.py` — FOUND
- `src/ccguard/agent/audit_hook/flusher.py` — FOUND
- `src/ccguard/agent/audit_hook/flusher_main.py` — FOUND
- `src/ccguard/agent/audit_main.py` — FOUND
- `tests/unit/test_audit_schemas.py` — FOUND
- `tests/unit/test_audit_hook_main.py` — FOUND
- `tests/unit/test_audit_flusher.py` — FOUND

Commits referenced:
- `ec2286c` — FOUND (Task 1)
- `d3676a5` — FOUND (Task 2)

Tests: `pytest tests/unit/ -q` reports 240/240 pass.
