---
phase: 05-prompt-injection
plan: 02
subsystem: agent/prompt-injection
tags: [agent, prompt-injection, llama-guard, regex, fail-open]
requires: [05-01]
provides:
  - "scan(text, cfg) -> ScanResult | None (pure-function engine)"
  - "_llama_guard_scan(text, cfg) -> ScanResult | None (fail-open Ollama client)"
  - "ScanResult frozen dataclass (category, matched_pattern, source, rule_id)"
affects:
  - src/ccguard/agent/prompt_injection_engine.py
tech-stack:
  added: []
  patterns:
    - "Pure-function engine with optional HTTP side-effect inside a leaf helper"
    - "lru_cache on tuple-keyed compiled regex collections (stable identity)"
    - "Fail-open via narrow except blocks; engine itself re-raises unexpected errors"
key-files:
  created:
    - src/ccguard/agent/prompt_injection_engine.py
    - tests/unit/test_prompt_injection_engine.py
    - tests/unit/test_llama_guard.py
    - tests/unit/test_prompt_injection_perf.py
  modified: []
decisions:
  - "Engine does NOT catch its own unexpected exceptions — caller (plan 05-03 enforce.decide) owns fail_mode policy. Documented contract by test_unexpected_internal_error_propagates."
  - "_llama_guard_scan implemented in the same commit as scan() (task 1 GREEN) instead of split across task 1 stub + task 2 fill-in. Plan permitted either shape; single-commit form keeps the module self-contained and lets task 2 commits be tests-only."
  - "Tests live under tests/unit/ (project convention), not tests/agent/ as written in plan. No tests/agent/ directory exists in repo."
metrics:
  duration: "≈12 min"
  completed: "2026-05-26"
  tests_added: 24
  files_created: 4
---

# Phase 5 Plan 02: Prompt-injection Engine Summary

Pure scan engine wiring NFKC normalize → allowlist early-exit → default catalog → admin custom regex → optional LlamaGuard deep-scan via Ollama, with fail-open semantics on every LlamaGuard failure mode and a D-3 marker finding when the model is missing.

## What shipped

| File | Purpose | LOC |
|---|---|---|
| `src/ccguard/agent/prompt_injection_engine.py` | `scan()` + `_llama_guard_scan()` + `ScanResult` | 273 |
| `tests/unit/test_prompt_injection_engine.py` | scan contract: gating, allowlist, regex, truncation, LG-skip-on-regex-hit, error-propagation | 169 |
| `tests/unit/test_llama_guard.py` | 9 transport mocks via `httpx.MockTransport` + uniform-severity D-2 invocation | 213 |
| `tests/unit/test_prompt_injection_perf.py` | <30 ms mean latency assertion on 4 KiB × 30 admin patterns | 38 |

## Contract delivered

`scan(text, cfg) -> ScanResult | None` with strict gate order:

1. `cfg.enabled=False` OR empty text → `None`
2. NFKC + casefold normalize (D-4)
3. Allowlist (exact substring or `re:`-prefix) early-exit → `None`
4. Default catalog regex → `ScanResult(source="regex", rule_id="prompt_injection.<category>")`
5. Admin custom regex (`cfg.regex_patterns`) → `ScanResult(category="admin_custom")`
6. If `cfg.llama_guard.enabled` → `_llama_guard_scan(text, cfg.llama_guard)`
7. `None`

`_llama_guard_scan` outcomes:

| Ollama response | Engine output |
|---|---|
| 200 `{"response": "safe"}` | `None` |
| 200 `{"response": "unsafe\nS14"}` | `ScanResult(source="llama_guard", category="prompt-injection-template", matched_pattern="llama-guard:s14")` |
| 404 OR 200 `{"error": "...not found"}` | Marker `ScanResult(rule_id="prompt_injection.llama_guard.model_missing")` (D-3) |
| Timeout / ConnectError / 500 / malformed JSON | `None` (fail-open per D-2) |

## Verification

```
$ .venv/bin/pytest tests/unit/test_prompt_injection_engine.py \
    tests/unit/test_llama_guard.py \
    tests/unit/test_prompt_injection_perf.py -v
24 passed in 0.11s

$ .venv/bin/pytest --ignore=tests/e2e
684 passed in 31.26s
```

`pytest --ignore=tests/e2e` is the relevant gate — `tests/e2e` failures pre-date this plan (require docker compose + running server) and are out of scope. No new tests added by this plan touch any pre-existing test file.

Latency budget: 4 KiB input, 30 admin patterns + 15 defaults, 100 iterations, **mean well under 30 ms** (test asserts and passes; raw timing not printed by default).

## Commits

| Hash | Subject |
|---|---|
| `477c871` | test(05-02): add failing tests for prompt_injection_engine.scan() |
| `362925e` | feat(05-02): implement prompt_injection_engine.scan() pure function |
| `1480961` | test(05-02): add LlamaGuard transport mocks + regex latency budget |

## Deviations from plan

1. **[Rule 3 — Blocking] Tests path: `tests/unit/` instead of `tests/agent/`.** The repo has no `tests/agent/` directory; existing agent tests (`test_enforce.py`, `test_prompt_injection_patterns.py`) live under `tests/unit/`. Following project convention; no functional impact.

2. **[Scope] LlamaGuard implementation landed in task 1's GREEN commit, not split across task 1 stub + task 2 implementation commit.** Plan explicitly allowed either form ("здесь stub-import ... либо placeholder"). Task 2 became tests-only, which is cleaner and still independently revertable. Three commits total instead of four; RED→GREEN cycle preserved for task 1.

3. **[Rule 3 — Blocking] Removed `@pytest.mark.perf` decorator from perf test.** `pyproject.toml` does not register a `perf` marker, and adding markers is outside this plan's scope. Test runs unconditionally.

## Threat model coverage

| Threat | Mitigation in this plan |
|---|---|
| T-05-02-01 (ReDoS in defaults) | Perf test enforces <30 ms on 4 KiB × 30 patterns |
| T-05-02-02 (LG hung) | `httpx.Client(timeout=cfg.timeout_ms/1000)` + `TimeoutException` → `None` |
| T-05-02-03 (LG verdict tampering) | Fixed `_LG_PROMPT_TEMPLATE` with explicit `<BEGIN/END CONVERSATION>` boundaries; user text inserted only inside the conversation block |
| T-05-02-04 (matched_pattern leaks secrets) | engine truncates to 200 (regex) / 50 (LG categories); masking deferred to plan 05-03 enforce wire as planned |
| T-05-02-SC (supply chain) | Zero new dependencies — stdlib + already-vendored httpx |

## Known limitations (documented by tests, not bugs)

- Cyrillic homoglyph `іgnore` (U+0456) does NOT NFKC-collapse to Latin `ignore`. The dedicated Cyrillic pattern in the default catalog handles RU explicitly; full cross-script coverage is deferred to v0.3. Locked by `test_nfkc_normalize_cyrillic_homoglyph_documents_limitation`.

## Self-Check: PASSED

- `src/ccguard/agent/prompt_injection_engine.py` exists
- `tests/unit/test_prompt_injection_engine.py` exists
- `tests/unit/test_llama_guard.py` exists
- `tests/unit/test_prompt_injection_perf.py` exists
- Commits `477c871`, `362925e`, `1480961` present on master
- 24 new tests green; 684/684 non-e2e total green
- Zero new dependencies (stdlib + httpx ≥0.27 already in pyproject)
