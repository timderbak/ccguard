---
phase: 05-prompt-injection
verified: 2026-05-26T21:20:00Z
status: human_needed
score: 5/5 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Edit Prompt-Injection card on /policy UI manually in a browser"
    expected: "All five form controls render (enabled toggle, severity dropdown, regex_patterns textarea, allowlist_patterns textarea, LlamaGuard fieldset with enabled/endpoint/timeout_ms); form submit round-trips values and shows validation errors inline on invalid regex"
    why_human: "Server-side rendering and parser are verified by tests, but real-browser UX (HTMX swap, validation feedback rendering, dropdown selected-state restore on re-render) requires a human looking at the page"
  - test: "Run a real PreToolUse Bash event through the installed agent with prompt_injection.severity=block and a matching command"
    expected: "Claude Code blocks the tool with the ccguard rule_id surfaced in the user-visible reason string, and a finding lands in /findings after the flusher runs"
    why_human: "End-to-end shim → finding → server pipeline is covered by tests/e2e/test_pi_e2e.py with a publish-block harness, but the real Claude Code hook contract (stdin schema, stdout JSON consumption) is only meaningful when exercised by Claude Code itself"
  - test: "Enable LlamaGuard with a real Ollama running llama-guard3:8b locally and feed a jailbreak prompt"
    expected: "Hook returns within ~150ms; on unsafe verdict a llama_guard-source finding is emitted; on Ollama unavailable the hook fails open and emits the model_missing info marker"
    why_human: "Tests mock the Ollama HTTP layer; only a live Ollama can confirm prompt template compatibility with llama-guard3:8b, response parsing on real model output, and the actual <100ms latency on the operator's hardware"
---

# Phase 5: Prompt-Injection Detection — Verification Report

**Phase Goal:** Regex + optional LlamaGuard на PreToolUse с policy-конфигурируемой severity.
**Verified:** 2026-05-26T21:20:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (5 ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | ccguard-enforce проверяет `tool_input.command`/`tool_input.prompt` против regex-набора → finding если matched | VERIFIED | `src/ccguard/agent/enforce.py:189-261` calls `pi_scan` before existing dispatch; `_extract_pi_payload` (enforce.py:34-50) concatenates `command`, `prompt`, `instructions`, `description`, `content`. Engine `src/ccguard/agent/prompt_injection_engine.py:160-232` runs default 15-pattern catalog (`prompt_injection_patterns.py:_DEFAULTS`) plus admin custom. On match, `emit_finding` is invoked (enforce.py:246). Tests: `test_enforce_pi_warn.py`, `test_enforce_pi_block.py`, `test_enforce_pi_info.py`, `test_prompt_injection_engine.py` — 121 PI tests passing. |
| 2 | При `llama_guard.enabled=true` shim делает локальный call к Ollama LlamaGuard 8B; failure fail-open | VERIFIED | `prompt_injection_engine.py:299-399` `_llama_guard_scan` POSTs to `{endpoint}/api/generate` with model `llama-guard3:8b` (default). Exception path returns `None` (fail-open); 404 / "model not found" → `model_missing` marker only at info severity (enforce.py:235-244). Tests: `test_llama_guard.py` covers unsafe/safe/timeout/404/network-error branches. Module-level `httpx.Client` reuse keeps connection pool warm (CR-04). |
| 3 | Severity finding'а берётся из `policy.prompt_injection.severity` (warn default, block opt-in) | VERIFIED | `schemas/policy.py:218` `severity: Literal["info", "warn", "block"] = "warn"`. `enforce.py:248,254` uses `pi_cfg.severity` for emit_finding and only returns deny when severity == "block". Tests cover all three severities individually. |
| 4 | Policy section `prompt_injection` редактируется в /policy UI: enabled, severity, regex_patterns, allowlist_patterns, llama_guard toggle | VERIFIED | Template `templates/components/_policy_section_prompt_injection.html` renders all 5 controls + endpoint + timeout_ms; included into `policy_editor.html:22`. Form parser `policy_form.py:133-205` (`_parse_prompt_injection`) handles enabled/severity/regex/allowlist/llama_guard. ReDoS publish-time guard wired (uses `prompt_injection_safety`). Tests: `test_policy_form_pi.py`, `test_policy_editor_pi_render.py`. |
| 5 | PreToolUse latency <100ms при выключенном LlamaGuard; тесты match/no-match/allowlist/llama_guard mock | VERIFIED | `tests/unit/test_prompt_injection_perf.py:22` asserts `<30ms` mean over 100 runs on 4KiB input with 45 patterns (15 default + 30 admin) — well inside the 100ms budget. LlamaGuard timeout clamped to 50–200ms at schema level (`policy.py:204`). Test coverage exhaustive: match/no-match/allowlist substring/allowlist re:/llama_guard mocked. |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/ccguard/schemas/policy.py` (PromptInjectionConfig, LlamaGuardConfig) | Pydantic schema + defaults | VERIFIED | Both classes present (lines 186-221); additive on Policy with `default_factory` (line 252); `extra="ignore"` for backward compat. |
| `src/ccguard/agent/prompt_injection_patterns.py` | 15+ default regex catalog | VERIFIED | 21 patterns across 5 categories (ignore/instruction_override/role_swap/jailbreak/base64); ReDoS-safe; lazy `lru_cache`-compiled. Exceeds 15-pattern target. |
| `src/ccguard/agent/prompt_injection_engine.py` | Pure scan function + LlamaGuard | VERIFIED | `scan()` implements 6-gate order incl. base64 entropy heuristic (WR-06); fail-open via `_llama_guard_scan`; module-level httpx client. |
| `src/ccguard/agent/enforce.py` integration | decide() PI step before existing dispatch | VERIFIED | Lines 194-261 inserted before tool_name dispatch; engine-crash safety w/ fail-mode (open/closed); model_missing marker handled separately. |
| `src/ccguard/agent/findings_hook/buffer.py` + `flusher.py` | Local buffer + batched POST | VERIFIED | `emit_finding` writes to SQLite buffer; `flusher.flush()` reads undelivered/retries with backoff/marks delivered; flusher_main entrypoint exists. |
| `src/ccguard/server/api/findings.py` | POST batch endpoint | VERIFIED | POST `/api/v1/findings` accepts envelope `{schema_version, machine_id, findings}` with `max_length=_MAX_FINDINGS_PER_BATCH`. |
| `src/ccguard/server/web/policy_form.py` (PI parser) | Form → Pydantic dict | VERIFIED | `_parse_prompt_injection` handles all fields; raises `PromptInjectionSectionError` on validation failure with section context for inline re-render. |
| `templates/components/_policy_section_prompt_injection.html` | UI card | VERIFIED | Renders all 5 controls + LlamaGuard fieldset; included into `policy_editor.html:22`. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `enforce.decide()` | `prompt_injection_engine.scan` | `pi_scan(text, pi_cfg)` import + call | WIRED | enforce.py:21 import, line 203 call. |
| `enforce.decide()` (PI match) | `findings_hook/buffer.emit_finding` | import + call | WIRED | enforce.py:19 import, called at lines 218, 236, 246. |
| `findings_hook/flusher` | server `/api/v1/findings` (POST) | HTTP retry loop | WIRED | flusher.py defines `_post_with_retry`; server route accepts batch envelope. |
| `/policy` route | PI form parser | `_parse_prompt_injection(form)` | WIRED | policy_form.py:512 calls parser; routes.py:451-512 includes overlay path for re-render on error. |
| `policy_editor.html` | PI section template | `{% include %}` | WIRED | policy_editor.html:22. |
| `PromptInjectionConfig.llama_guard` | `_llama_guard_scan` | `cfg.llama_guard.enabled` gate | WIRED | engine.py:227 — only enters deep-scan when enabled. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `enforce.decide()` PI step | `pi_result` | `pi_scan(text, pi_cfg)` on actual tool_input fields | YES — engine runs compiled regex over normalized text and returns ScanResult or None | FLOWING |
| `_policy_section_prompt_injection.html` form values | `policy.prompt_injection.*` | Server passes Policy from loaded YAML through `/policy` route | YES — template binds checked/selected attrs from real config | FLOWING |
| findings POST batch | flusher reads `findings_buffer` SQLite table | `_read_undelivered(conn, limit)` | YES — only undelivered rows written by `emit_finding`; retry/backoff logic operates on real rows | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| All 15 PI-related test modules pass | `uv run pytest tests/unit/test_prompt_injection_*.py tests/unit/test_enforce_pi_*.py tests/unit/test_llama_guard.py tests/unit/test_findings_hook_*.py tests/unit/test_policy_backcompat.py tests/integration/test_policy_form_pi.py tests/integration/test_prompt_injection_e2e_hook.py tests/integration/test_policy_editor_pi_render.py tests/integration/test_pi_backward_compat.py tests/e2e/test_pi_e2e.py` | 121 passed, 0 failed | PASS |
| Regex stage stays under 30ms / 100 iterations × 4KiB / 45 patterns | (included in run above) `test_regex_stage_under_30ms_mean_on_4kb_input` | passed | PASS |
| Full project suite for regressions | `uv run pytest` | 763 passed, 7 failed | PARTIAL — 7 failing tests are pre-existing e2e infrastructure tests (`test_end_to_end.py`, `test_web_e2e.py`) with `httpx.ConnectError` (no live server in fixture); none reference `prompt_injection`. Not introduced by Phase 5. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| PI-01 | 05-01..05-04 | PreToolUse regex on command/prompt | SATISFIED | enforce.py integration + 21-pattern catalog + 121 tests |
| PI-02 | 05-02 | Optional LlamaGuard 8B feature-flag | SATISFIED | `_llama_guard_scan` + `LlamaGuardConfig.enabled` toggle + mocked tests |
| PI-03 | 05-01, 05-03 | severity=warn default, block opt-in | SATISFIED | schema default + Literal enforcement + dedicated severity tests |
| PI-04 | 05-01, 05-05 | Policy section with enabled/severity/regex/allowlist/llama_guard | SATISFIED | full schema + UI card + parser |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none) | — | — | — | No `TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER` markers found in Phase 5 source files. |

### Human Verification Required

See frontmatter `human_verification:` block. Three checks need a human:
1. /policy UI Prompt-Injection card real-browser UX.
2. Live PreToolUse hook integration with Claude Code (real shim invocation).
3. Live Ollama LlamaGuard end-to-end smoke (model availability, real model output parsing, real-hardware latency).

### Gaps Summary

No gaps. All 5 ROADMAP success criteria verified in code, supported by 121 passing PI tests (unit + integration + e2e). The 7 failing tests in the full-suite run are pre-existing infrastructure failures in `test_end_to_end.py` and `test_web_e2e.py` (httpx.ConnectError — fixture does not start a live server) and do not touch prompt_injection code paths. Phase deliverables — schema, default catalog, scan engine, enforce integration, findings buffer+flusher, server batch endpoint, /policy UI card with form parser, ReDoS guard, perf budget assertion — are all present, wired, and exercised by the test suite.

Three human-verification items remain (above) because real-browser UX, live Claude Code hook contract, and live Ollama behaviour cannot be validated by grep or mocked tests.

---

_Verified: 2026-05-26T21:20:00Z_
_Verifier: Claude (gsd-verifier)_
