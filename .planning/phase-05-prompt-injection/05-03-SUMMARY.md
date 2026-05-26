---
phase: 05-prompt-injection
plan: 03
subsystem: agent/enforce
tags: [prompt-injection, enforce, hook, findings]
requires:
  - 05-01 # PromptInjectionConfig schema in Policy
  - 05-02 # prompt_injection_engine.scan / ScanResult
  - 05-04 # findings_hook.buffer.emit_finding
provides:
  - "enforce.decide() PI step (block→deny / warn,info→fall-through)"
  - "_extract_pi_payload helper"
affects:
  - src/ccguard/agent/enforce.py
tech-stack:
  added: []
  patterns:
    - "Severity → permission mapping (block=deny, warn/info=allow w/ finding)"
    - "Engine fail-mode reuse of policy.block_fail_mode (D-2)"
    - "model_missing marker passthrough (D-3)"
key-files:
  created:
    - tests/unit/test_enforce_pi_block.py
    - tests/unit/test_enforce_pi_warn.py
    - tests/unit/test_enforce_pi_info.py
  modified:
    - src/ccguard/agent/enforce.py
decisions:
  - "Reuse existing policy.block_fail_mode for engine crash (no new field)"
  - "model_missing emits info-severity finding regardless of policy.severity"
  - "PI step injected inside the existing PreToolUse guard, BEFORE _decide_*"
metrics:
  duration: ~10min
  completed: 2026-05-26
---

# Phase 5 Plan 03: Enforce ↔ Prompt-Injection Wiring Summary

Wires `prompt_injection_engine.scan()` into `enforce.decide()` so the PreToolUse hook actually detects + acts on injection attempts on real endpoints.

## What changed

`src/ccguard/agent/enforce.py`:
- Added imports: `pi_scan as scan`, `ScanResult`, `emit_finding`, stdlib `logging`.
- Added module-level `log = logging.getLogger(__name__)`.
- Added `_PI_PAYLOAD_FIELDS = ("command","prompt","instructions","description","content")` and `_extract_pi_payload(tool_input)`.
- Inserted PI step inside `decide()` directly after the PreToolUse guard and before the `_decide_bash/_decide_mcp/_decide_web` dispatch. Logic:
  1. `pi_cfg.enabled` gate.
  2. `pi_scan(text, pi_cfg)` wrapped in `try/except`. Crash → `block_fail_mode=closed` returns `EnforceDecision(deny, rule_id=prompt_injection.engine_error)`; `open` logs `log.warning` and continues.
  3. `ScanResult.rule_id == "prompt_injection.llama_guard.model_missing"` → `emit_finding(severity="info", ...)`, fall through. Marker never blocks.
  4. Otherwise emit finding with `severity=pi_cfg.severity`. If severity is `"block"` → return deny; else fall through.

`_decide_bash/_decide_mcp/_decide_web` untouched (pipeline integrity).

## Tests added (13 new, all green)

- `tests/unit/test_enforce_pi_block.py` (10 tests): deny path, finding emission, fail-open continuation, fail-closed deny, model_missing marker, payload extraction (2), enabled=False, non-PreToolUse, no-match.
- `tests/unit/test_enforce_pi_warn.py` (2 tests): warn match → allow + finding, warn falls through into existing `always_deny`.
- `tests/unit/test_enforce_pi_info.py` (1 test): info match → allow + info finding.

## Commits

- `30dcb1f` — test(05-03): add failing integration tests for enforce PI step
- `da80663` — feat(05-03): integrate prompt-injection engine into PreToolUse enforce pipeline

## Verification

- New PI tests + existing 22-test enforce baseline: **35/35 passed** (0.07s).
- Full non-e2e suite: **728 passed** (35.41s).
- e2e failures pre-existed on `master` HEAD (verified by re-running e2e against unchanged HEAD); they are not caused by this plan.
- Latency: PI step adds one `_extract_pi_payload` (O(5) dict lookups) + one `pi_scan` call. With LlamaGuard disabled, the regex stage stays within the <30 ms budget set in plan 05-02. `emit_finding` is a single SQLite `INSERT` under autocommit — sub-millisecond on WAL.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 — Critical functionality] Added `logging` import**

- **Found during:** Task 1 implementation.
- **Issue:** The plan's `<action>` block assumes a `log` Logger already exists in `enforce.py`. Inspection showed no logger was imported.
- **Fix:** Added `import logging` and `log = logging.getLogger(__name__)` at module scope — minimal addition, no behavioural change.
- **Files modified:** `src/ccguard/agent/enforce.py`
- **Commit:** `da80663`

No other deviations. The `tests/agent/conftest.py` fixture sketch from the plan was unnecessary because the project keeps tests flat under `tests/unit/` (no `tests/agent/` directory exists); the three test files define their own `_make_policy/_payload` helpers inline, matching the style of the existing `tests/unit/test_enforce.py`.

## Known Stubs

None.

## Self-Check: PASSED

- `src/ccguard/agent/enforce.py` modified — confirmed.
- `tests/unit/test_enforce_pi_block.py` exists — confirmed.
- `tests/unit/test_enforce_pi_warn.py` exists — confirmed.
- `tests/unit/test_enforce_pi_info.py` exists — confirmed.
- Commits `30dcb1f` and `da80663` exist on `master` — confirmed.
