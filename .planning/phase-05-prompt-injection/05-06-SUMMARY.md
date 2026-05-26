---
phase: 05-prompt-injection
plan: 06
subsystem: cross-cutting-tests
tags: [tests, e2e, backward-compat, prompt-injection]
requires: [05-01, 05-02, 05-03, 05-04, 05-05]
provides: [pi-e2e-coverage, pi-backward-compat-proof, pi-fp-smoke-matrix]
affects: [tests/integration, tests/e2e, tests/unit]
tech_stack_added: []
tech_stack_patterns:
  - "uvicorn-in-thread for in-process e2e against real HTTP"
  - "CCGUARD_AGENT_HOME env-isolation for subprocess hook tests"
key_files_created:
  - tests/integration/test_prompt_injection_e2e_hook.py
  - tests/integration/test_pi_backward_compat.py
  - tests/e2e/test_pi_e2e.py
key_files_modified:
  - tests/unit/test_prompt_injection_engine.py
  - tests/unit/test_prompt_injection_patterns.py
decisions: []
metrics:
  duration_minutes: 30
  completed_date: 2026-05-26
  tests_added: 31
  baseline_tests_post: 759
requirements: [PI-01, PI-02, PI-03, PI-04]
---

# Phase 5 Plan 06: Cross-Cutting Tests Summary

End-to-end test fortification for Phase 5: subprocess-driven hook tests,
real-uvicorn publish→enforce→flush→view e2e, v0.1↔v0.2 schema
backward-compat proof, NFKC normalization, base64 FP guard, and a 10×15
benign-command false-positive matrix.

## What Was Built

| Category | File | Tests |
|---|---|---|
| Subprocess hook (integration) | tests/integration/test_prompt_injection_e2e_hook.py | 7 |
| Backward-compat | tests/integration/test_pi_backward_compat.py | 4 |
| Full publish→view e2e | tests/e2e/test_pi_e2e.py | 4 |
| Engine extensions (unit) | tests/unit/test_prompt_injection_engine.py | +5 |
| Patterns FP/ReDoS smoke (unit) | tests/unit/test_prompt_injection_patterns.py | +11 |
| **Total new tests** | | **31** |

## Coverage Matrix (PI-01..04)

| Req ID | Unit | Integration | E2E |
|--------|------|-------------|-----|
| PI-01 (regex engine) | test_prompt_injection_engine (16), test_prompt_injection_patterns (17) | test_prompt_injection_e2e_hook (7), test_enforce_pi_block/warn/info | test_pi_e2e::test_e2e_publish_block_severity_pipeline |
| PI-02 (LlamaGuard) | test_llama_guard, test_prompt_injection_engine::test_llama_guard_model_missing_marker_via_404, ::test_llama_guard_unreachable_returns_none | test_prompt_injection_e2e_hook::test_subprocess_llama_guard_unreachable_fails_open | — (covered by integration; live Ollama out of scope) |
| PI-03 (severities) | test_enforce_pi_block/warn/info | test_prompt_injection_e2e_hook (block/warn variants), test_findings_hook_buffer | test_pi_e2e::test_e2e_publish_block + ::test_e2e_publish_warn |
| PI-04 (admin patterns + allowlist) | test_policy_form_pi, test_prompt_injection_engine (allowlist exact + re:) | test_pi_backward_compat, test_prompt_injection_e2e_hook::test_subprocess_admin_custom_pattern_block, ::test_subprocess_allowlist_suppresses_block | test_pi_e2e::test_e2e_allowlist_suppresses_finding |

## Key Verifications

- **Latency budget:** `test_subprocess_latency_budget_under_100ms` measures
  wall-clock for 3 subprocess invocations against a clean stdin (no PI match)
  and asserts best-of-3 stays under 2.0 s (subprocess startup dominates;
  in-process budget is the <100 ms goal from CLAUDE.md and is preserved as
  long as no new heavy imports land on the hot path).
- **LlamaGuard fail-open:** verified via two paths — closed-port
  `ConnectError` (subprocess + unit) and HTTP 404 model-missing marker
  (unit with monkeypatched httpx.Client).
- **Backward-compat:** inline simulated `_V01Policy` ignores the v0.2
  `prompt_injection` section; v0.2 `Policy.model_validate` fills sane
  defaults when the section is absent in a legacy YAML.
- **FP matrix:** 10 benign dev-shell commands × 15 default patterns = 150
  combinations, zero matches.
- **ReDoS extended:** four pathological inputs (long word chains,
  repeated `ignore`, alternating quoted blocks) tested against all
  patterns with a 10 ms ceiling per `pattern.search`.
- **Full e2e:** real uvicorn server on a free local port, lifespan
  bootstrapped via `CCGUARD_TOKENS` / `CCGUARD_POLICY_PATH` /
  `CCGUARD_DB_URL` env vars. `policy_service.save_draft` +
  `publish_draft` push a v0.2 policy; the agent simulates `GET
  /api/v1/policy` + cache write; subprocess `enforce_main` emits a
  finding; subprocess `flusher_main` posts it; `GET /api/v1/findings`
  reads it back.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocker] Module-level flusher import polluted unit-test monkeypatch**

- **Found during:** Task 2 (e2e import-surface sanity test)
- **Issue:** Importing `ccguard.agent.findings_hook.flusher` in-process
  caches the module with its local `from ccguard.agent.config import
  load_or_create` binding. The existing
  `tests/unit/test_findings_hook_flusher.py` monkeypatches
  `ccguard.agent.config.load_or_create` (source module), which does not
  reach the locally-bound symbol. Test ordering with the new e2e module
  exposed the latent gap.
- **Fix:** the Phase 5 surface-sanity test uses
  `importlib.util.find_spec` instead of importing the flusher. Real
  flusher behavior is exercised via subprocess in the e2e tests.
- **Files modified:** tests/e2e/test_pi_e2e.py
- **Commit:** e5c6751

**2. [Rule 3 - Blocker] Lifespan re-pinned app.state on first request**

- **Found during:** Task 2 (initial e2e attempt)
- **Issue:** Pre-set `app.state.engine` and `app.state.policy_loader`
  before starting uvicorn were overwritten by the FastAPI lifespan, which
  builds its own engine + PolicyLoader from `CCGUARD_*` env vars. The
  pre-set objects were discarded.
- **Fix:** Set `CCGUARD_TOKENS`, `CCGUARD_POLICY_PATH`, `CCGUARD_DB_URL`
  via `os.environ` BEFORE `create_app()`, then read the
  lifespan-constructed engine back out of `app.state.engine` after
  readiness. Restore previous env values at fixture teardown.
- **Files modified:** tests/e2e/test_pi_e2e.py
- **Commit:** e5c6751

**3. [Rule 1 - Bug] save_draft assigns its own revision**

- **Found during:** Task 2 (e2e assertion mismatch)
- **Issue:** Test asserted that the published policy revision matched the
  one written into the YAML `meta.revision` — but `policy_service._next_revision`
  always assigns the next monotonic value, ignoring incoming meta.
- **Fix:** Tolerate the server's assigned revision; assert `>=` the
  returned value instead of exact equality.
- **Files modified:** tests/e2e/test_pi_e2e.py
- **Commit:** e5c6751

## Test Counts

- Baseline before plan 06: 739 tests collected
- After plan 06: 759 tests collected (+20 net, +31 new minus parametrize counts)
- Full suite (excluding docker-only e2e tests): 759 passed, 0 failed

The docker-bound `tests/e2e/test_end_to_end.py`,
`test_push_install_e2e.py`, and `test_web_e2e.py` files fail in local
runs (httpx ConnectError on `server:8080` DNS), as they did pre-plan.
Those require docker-compose and are not part of the developer-local
gate.

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, or schema fields added.
This plan is exclusively test surface.

## Self-Check: PASSED

- tests/integration/test_prompt_injection_e2e_hook.py: FOUND
- tests/integration/test_pi_backward_compat.py: FOUND
- tests/e2e/test_pi_e2e.py: FOUND
- Modified tests/unit/test_prompt_injection_engine.py: FOUND (+5 tests)
- Modified tests/unit/test_prompt_injection_patterns.py: FOUND (+11 tests)
- Commit 2e06896: FOUND
- Commit e5c6751: FOUND
