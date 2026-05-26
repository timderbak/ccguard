---
phase: 05-prompt-injection
plan: 01
subsystem: schemas + agent-patterns
tags: [pydantic, schema, regex, backward-compat, prompt-injection]
status: complete
completed: 2026-05-26
requires: []
provides:
  - "ccguard.schemas.policy.PromptInjectionConfig"
  - "ccguard.schemas.policy.LlamaGuardConfig"
  - "Policy.prompt_injection field with default-factory"
  - "ccguard.agent.prompt_injection_patterns.get_default_patterns()"
affects:
  - "src/ccguard/schemas/policy.py"
tech-stack:
  added: []
  patterns:
    - "Additive Pydantic v2 schema extension (schema_version=1 unchanged)"
    - "extra='ignore' on new configs for forward-compat with v0.1/v0.2 agents"
    - "lru_cache(maxsize=1) for lazy pattern compilation"
key-files:
  created:
    - "src/ccguard/agent/prompt_injection_patterns.py"
    - "tests/unit/test_policy_backcompat.py"
    - "tests/unit/test_prompt_injection_patterns.py"
  modified:
    - "src/ccguard/schemas/policy.py"
decisions:
  - "Test files placed under tests/unit/ (project convention) instead of tests/schemas/ and tests/agent/ — those dirs do not exist in this codebase (Rule 3 deviation)"
  - "15 patterns exactly: 4 ignore_previous_instructions (incl. Cyrillic) + 3 instruction_override + 3 role_swap + 3 jailbreak_template + 2 base64_encoded_prompt"
  - "schema_version NOT bumped — additive change per RESEARCH"
metrics:
  duration_minutes: 8
  tasks_completed: 2
  files_changed: 4
  tests_added: 12
  tests_total_after: 650
---

# Phase 5 Plan 01: Prompt-Injection Schema + Default Pattern Catalog Summary

PromptInjectionConfig + LlamaGuardConfig added to Policy as additive section; 15-pattern default regex catalog shipped behind lazy lru_cache loader.

## What Shipped

- **`PromptInjectionConfig`** (extra=ignore): `enabled`, `severity` (Literal info/warn/block), `regex_patterns`, `allowlist_patterns`, `llama_guard` sub-config.
- **`LlamaGuardConfig`** (extra=ignore): `enabled=False` by default, Ollama endpoint, `llama-guard3:8b` model, `timeout_ms` bounded `[50, 10000]` to fit PreToolUse <100ms latency budget.
- **`Policy.prompt_injection`** via `Field(default_factory=PromptInjectionConfig)` — additive, schema_version stays 1.
- **`ccguard.agent.prompt_injection_patterns`** module — `get_default_patterns()` returns frozen tuple of 15 `(category, re.Pattern)` entries across 5 categories. Lazy compile, no import-time side effects. One Cyrillic smoke pattern (`игнорируй / забудь … предыдущ / прошл`).
- **Backward-compat round-trip test** verifies that `extra="ignore"` lets future fields (`future_field`, `future_llama_field`) flow through Policy without ValidationError.

## Test Coverage

| Test File | Count | Purpose |
|-----------|-------|---------|
| `tests/unit/test_policy_backcompat.py` | 6 | Defaults, range/Literal validation, extra=ignore round-trip, missing-section fallback |
| `tests/unit/test_prompt_injection_patterns.py` | 6 | Catalog count, shape, positive/negative matches, ReDoS smoke, lru_cache identity |

Full non-e2e suite: **650 passed** (baseline 644 + 6 new). Zero regressions.

## Commits

| Hash | Type | Subject |
|------|------|---------|
| `ffbaba8` | test | failing backcompat tests for prompt_injection schema (RED) |
| `c1a7c45` | feat | PromptInjectionConfig + LlamaGuardConfig (GREEN) |
| `29d0366` | test | failing tests for default pattern catalog (RED) |
| `70db13c` | feat | default regex catalog (GREEN) |

## Threat Model Coverage

| Threat ID | Disposition | How Mitigated |
|-----------|-------------|---------------|
| T-05-01-01 | mitigate | Every pattern uses bounded quantifiers (`\s+`, `.{0,N}` with N≤200, no `.*`). `test_redos_smoke` enforces <5ms on 4KB blob per pattern. |
| T-05-01-02 | mitigate | `extra="ignore"` on both new configs + inherited on Policy. `test_prompt_injection_extra_ignore_round_trip` verifies a YAML with hypothetical `future_field` / `future_llama_field` parses cleanly. |
| T-05-01-03 | accept | Regex patterns travel through existing authenticated `/api/v1/policy` channel; not new surface. |
| T-05-01-SC | mitigate | Zero new dependencies — pure stdlib (`re`, `functools.lru_cache`). |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Test files moved to `tests/unit/`**
- **Found during:** Task 1 setup
- **Issue:** Plan specified `tests/schemas/test_policy_backcompat.py` and `tests/agent/test_prompt_injection_patterns.py`, but those directories do not exist in the repo. Project convention places all unit tests under `tests/unit/` (per `pyproject.toml testpaths=["tests"]` and observed structure with 30+ existing `tests/unit/test_*.py` files).
- **Fix:** Placed tests at `tests/unit/test_policy_backcompat.py` and `tests/unit/test_prompt_injection_patterns.py`.
- **Impact:** None — pytest collection is recursive; tests are discovered and run identically.

**2. [Rule 1 - Bug] Fixed SyntaxWarning on backslash in docstring**
- **Found during:** Task 2 verification
- **Issue:** Module docstring contained `\s+` (unescaped backslash) which Python 3.14 raises as `SyntaxWarning: invalid escape sequence`.
- **Fix:** Changed docstring to escape backslash (`\\s+`).
- **Files modified:** `src/ccguard/agent/prompt_injection_patterns.py`
- **Commit:** Folded into `70db13c` (GREEN task 2) before commit.

## Decisions Made

- **Cyrillic coverage scope:** One smoke marker only (`(?:игнорируй|забудь)\s+(?:все\s+)?(?:предыдущ|прошл)`). Full RU corpus deferred to v0.3 per RESEARCH "Deferred Ideas".
- **`base64_encoded_prompt` pinning:** Both base64 patterns require the literal `base64` keyword nearby. This makes the negative case `aws s3 cp s3://bucket/AAAAAA...` safe — a bare alphanumeric blob is not enough to fire.
- **`ignore_previous_instructions` whitespace gate:** Pattern requires `\s+` after `ignore`, so `--ignore-merge-options` (no whitespace) is immune.

## Self-Check: PASSED

- File `src/ccguard/schemas/policy.py` (modified): FOUND
- File `src/ccguard/agent/prompt_injection_patterns.py` (created): FOUND
- File `tests/unit/test_policy_backcompat.py` (created): FOUND
- File `tests/unit/test_prompt_injection_patterns.py` (created): FOUND
- Commit `ffbaba8`: FOUND
- Commit `c1a7c45`: FOUND
- Commit `29d0366`: FOUND
- Commit `70db13c`: FOUND
- 650/650 non-e2e tests pass
