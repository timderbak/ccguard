---
phase: 03-llm-content-scanner
plan: 02
subsystem: llm-content-scanner
tags: [anthropic, llm-client, tool-use, cost-estimation, fail-safe]
requires: [03-01]
provides:
  - "LLMClient async wrapper around anthropic.AsyncAnthropic"
  - "ScanOutcome dataclass (risk_score, category, rationale, tokens, cost, model)"
  - "LLMClientError(retryable: bool)"
  - "REPORT_RISK_TOOL JSON schema (strict:true) + CATEGORIES enum"
  - "Cost formula constants (Haiku 4.5: $1/$5 per MTok)"
  - "ServerConfig.anthropic_api_key + llm_enabled_at_startup property"
affects:
  - "pyproject.toml (declared anthropic dep)"
  - "src/ccguard/server/config.py (ANTHROPIC_API_KEY env loader)"
  - "src/ccguard/server/services/llm_client.py (new module)"
tech-stack:
  added:
    - "anthropic>=0.40,<1 (installed: 0.104.1)"
  patterns:
    - "tool_use + strict:true for reliable structured outputs (D-05)"
    - "Fail-safe synthetic outcome on any malformed response branch (no raise)"
    - "math.ceil for safe cost rounding (never under-report cost)"
key-files:
  created:
    - "src/ccguard/server/services/llm_client.py"
    - "tests/unit/test_llm_client.py"
  modified:
    - "pyproject.toml"
    - "src/ccguard/server/config.py"
decisions:
  - "D-02 honored: one-pass protocol — single Anthropic call per scan, no follow-up"
  - "D-05 honored: tool_use with strict:true; tool_choice forces report_risk invocation"
  - "D-06 honored: Haiku 4.5 pricing ($1/$5 per MTok); math.ceil rounding"
  - "Fail-safe matrix: missing tool_use, missing field, out-of-range score, non-enum category → synthetic (50, benign, scanner_error: ...)"
  - "Network/API errors raise LLMClientError(retryable=bool); APIConnectionError + RateLimitError + APIStatusError 5xx → retryable=True; other 4xx → False"
metrics:
  duration_minutes: 8
  tasks_completed: 2
  files_created: 2
  files_modified: 2
  tests_added: 12
  tests_total_after: 473
completed: 2026-05-26
---

# Phase 03 Plan 02: Anthropic SDK Wrapper Summary

One-liner: LLMClient async wrapper for Anthropic Haiku 4.5 with tool_use+strict
structured output, fail-safe synthetic outcome on malformed responses, and Haiku
4.5 cost estimation ($1/$5 per MTok via math.ceil).

## What Shipped

### SDK Integration

- Added `anthropic>=0.40,<1` to `pyproject.toml` `[project].dependencies`
  (installed: **0.104.1**).
- Wired `ANTHROPIC_API_KEY` env var into `ServerConfig.anthropic_api_key` (read
  once at startup, never persisted).
- Added derived property `ServerConfig.llm_enabled_at_startup` — truthy iff
  `anthropic_api_key` is non-empty. This drives the "warm-up / no API key"
  UI state from the UI-SPEC without ever calling Anthropic on boot.

### LLMClient module — `src/ccguard/server/services/llm_client.py`

Module-level constants:

| Name | Value |
|------|-------|
| `MODEL` | `"claude-haiku-4-5-20251001"` |
| `MAX_TOKENS` | `512` |
| `INPUT_CENTS_PER_MTOK` | `100` ($1/MTok input — D-06) |
| `OUTPUT_CENTS_PER_MTOK` | `500` ($5/MTok output — D-06) |
| `CATEGORIES` | `("jailbreak","prompt-injection-template","data-exfil","privilege-escalation","benign")` |

`REPORT_RISK_TOOL` schema (passed to `messages.create` as `tools=[...]` with
`tool_choice={"type":"tool","name":"report_risk"}`):

```python
{
  "name": "report_risk",
  "description": "Report the risk classification of the scanned content.",
  "input_schema": {
    "type": "object",
    "properties": {
      "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
      "category":   {"type": "string", "enum": list(CATEGORIES)},
      "rationale":  {"type": "string", "maxLength": 500},
    },
    "required": ["risk_score", "category", "rationale"],
  },
  "strict": True,
}
```

Public API:

- `class LLMClient(api_key: str)` — constructs an `anthropic.AsyncAnthropic`
  client; one instance per server process.
- `async LLMClient.scan_content(content: str, file_path: str, scope: Literal["agent","skill"]) -> ScanOutcome`
- `@dataclass(frozen=True) ScanOutcome` — six fields: `risk_score`, `category`,
  `rationale`, `input_tokens`, `output_tokens`, `cost_cents`, `model`.
- `class LLMClientError(Exception)` with `.retryable: bool` flag.

### Cost formula (D-06)

```python
def _compute_cost_cents(input_tokens: int, output_tokens: int) -> int:
    raw = input_tokens * 100 + output_tokens * 500
    return 0 if raw <= 0 else math.ceil(raw / 1_000_000)
```

Examples (verified by unit tests):

| Input tokens | Output tokens | Cents |
|--------------|---------------|-------|
| 1            | 1             | 1 (math.ceil — never under-report) |
| 10 000       | 2 000         | 2 |
| 1 000 000    | 1 000 000     | 600 ($1 in + $5 out) |

### Fail-safe matrix

`scan_content` never raises on a malformed model reply. It returns a synthetic
conservative `ScanOutcome` (risk_score=50, category="benign", rationale starts
with `scanner_error: `) in every branch below:

| Branch | Trigger | Rationale text |
|--------|---------|----------------|
| No tool_use block | model replied text-only | `scanner_error: no tool_use in response` |
| Missing required field | tool_use dict lacks `risk_score`/`category`/`rationale` | `scanner_error: missing field <name>` |
| Out-of-range risk_score | not int OR `<0 or >100` | `scanner_error: risk_score out of range: <repr>` |
| Unknown category | string not in CATEGORIES enum | `scanner_error: unknown category '<value>'` |
| Non-string rationale | wrong type | `scanner_error: rationale not a string` |

Token usage from `response.usage` is preserved in the synthetic outcome so the
LLMCallLog still records a faithful billing record.

### Transport errors

| Exception | Mapped to | retryable |
|-----------|-----------|-----------|
| `anthropic.APIConnectionError` | `LLMClientError` | True |
| `anthropic.RateLimitError` | `LLMClientError` | True |
| `anthropic.APIStatusError` (5xx) | `LLMClientError` | True |
| `anthropic.APIStatusError` (4xx) | `LLMClientError` | False |
| Other `anthropic.APIError` | `LLMClientError` | False |

The scan_service in Plan 03-03 will decide retry / budget / 429 semantics; this
module stays single-purpose.

## Tests

`tests/unit/test_llm_client.py` (12 tests, all green; SDK fully mocked via
`unittest.mock.AsyncMock` patching `anthropic.AsyncAnthropic`):

1. `test_categories_match_context_md` — enum locked to CONTEXT.md
2. `test_report_risk_tool_schema_shape` — strict:true, required fields, ranges
3. `test_cost_formula_exact_one_million_each` — 1M+1M → 600 cents
4. `test_cost_formula_uses_haiku_45_pricing_constants` — D-06 constants
5. `test_cost_formula_round_up_safe` — math.ceil ≥1 cent for tiny usage
6. `test_scan_content_happy_path_parses_tool_use` — full happy path
7. `test_scan_content_missing_tool_use_returns_synthetic` — fail-safe branch
8. `test_scan_content_out_of_range_risk_score_synthetic` — 150 → synthetic
9. `test_scan_content_unknown_category_coerced_to_benign` — unknown enum
10. `test_scan_content_missing_required_field_synthetic` — missing rationale
11. `test_scan_content_network_error_raises_llm_client_error` — APIConnectionError → retryable=True
12. `test_scan_content_invokes_sdk_with_correct_params` — model, tools, tool_choice, messages

No real network calls happen during tests (AsyncMock substitutes the SDK
constructor).

## Deviations from Plan

None — plan executed as written.

Minor stylistic notes (not deviations):

- Used `math.ceil` for cost rounding rather than `round` as suggested in
  `<interfaces>`. The plan's must_haves explicitly say "math.ceil for safe
  rounding", which takes precedence. The `<interfaces>` formula was a sketch.
- Defensive truncate of `rationale` to 500 chars on the happy path matches the
  tool schema's `maxLength: 500`.

## Threat Flags

None — no new outbound surface introduced beyond what `<threat_model>` already
covered (T-03-04 mitigated by Plan 04 masking; T-03-05 mitigated by strict:true
+ defensive validation in `_parse_tool_use`; T-03-SC anthropic install validated
via uv lockfile resolution; T-03-06 audit logging deferred to Plan 03-03's
scan_service which calls into LLMClient).

## Self-Check: PASSED

- FOUND: `pyproject.toml` (anthropic dep line present)
- FOUND: `src/ccguard/server/config.py` (anthropic_api_key + llm_enabled_at_startup)
- FOUND: `src/ccguard/server/services/llm_client.py`
- FOUND: `tests/unit/test_llm_client.py`
- FOUND commit `ce557f0`: feat(03-02) declare anthropic dep + ServerConfig
- FOUND commit `d40c5ae`: test(03-02) RED — failing LLMClient tests
- FOUND commit `ec02f27`: feat(03-02) GREEN — implement LLMClient

## TDD Gate Compliance

Task 2 was `tdd="true"`. Gate sequence verified in git log:

1. RED: `d40c5ae test(03-02): add failing tests for LLMClient with mocked Anthropic SDK`
2. GREEN: `ec02f27 feat(03-02): implement LLMClient with tool_use parsing, cost, and fail-safe`

No REFACTOR commit needed — implementation was straight-through.
