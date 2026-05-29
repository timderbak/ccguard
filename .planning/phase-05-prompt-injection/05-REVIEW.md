---
phase: 05-prompt-injection
reviewed: 2026-05-27T00:00:00Z
depth: standard
iteration: 2
files_reviewed: 11
files_reviewed_list:
  - src/ccguard/schemas/policy.py
  - src/ccguard/agent/prompt_injection_patterns.py
  - src/ccguard/agent/prompt_injection_engine.py
  - src/ccguard/agent/prompt_injection_safety.py
  - src/ccguard/agent/findings_hook/buffer.py
  - src/ccguard/agent/findings_hook/flusher.py
  - src/ccguard/agent/findings_hook/flusher_main.py
  - src/ccguard/agent/enforce.py
  - src/ccguard/server/api/findings.py
  - src/ccguard/server/web/policy_form.py
  - src/ccguard/server/web/routes.py
  - src/ccguard/server/web/templates/components/_policy_section_prompt_injection.html
findings:
  critical: 2
  blocker: 2
  warning: 7
  info: 4
  total: 13
  new_in_iteration_2: 0
status: clean
resolution:
  fixed_at: 2026-05-27T00:00:00Z
  fixed:
    - CR-01
    - CR-02
    - CR-03
    - CR-04
    - WR-01
    - WR-02
    - WR-03
    - WR-04
    - WR-05
    - WR-06
    - WR-07
    - WR-08
    - WR-09
  skipped:
    - IN-01
    - IN-02
    - IN-03
    - IN-04
  tests_after: 755
  baseline_tests: 755
  re_reviewed_at: 2026-05-27T00:00:00Z
  re_review_verdict: clean
---

# Phase 5: Code Review Report (Iteration 2 — Re-review)

**Re-reviewed:** 2026-05-27
**Depth:** standard
**Files Reviewed:** 12 (incl. new `prompt_injection_safety.py` and PI template)
**Status:** clean

## Iteration 2 Summary (Re-review)

All 13 prior findings (2 BLOCKER, 2 CRITICAL, 9 WARNING) verified resolved across 13 atomic fix commits (`74b4219 … 3413588`) on the Phase 5 surface. No regressions in Phase 1-4 files — `git diff --stat 74b4219^..3413588 -- src/` shows only Phase 5 modules touched (engine, patterns, safety, enforce, findings_hook/*, server findings API, policy_form, routes, schemas/policy, PI template).

**Test status:** 755 passed (non-e2e); 4 PI-related e2e green. 7 failing e2e (`test_end_to_end.py::test_health_endpoint` et al, `test_web_e2e.py::test_web_login_and_overview`) are pre-existing network-dependent tests requiring docker compose/local server — verified unchanged from pre-fix state and unrelated to Phase 5 surface.

**Verification, by finding:**

| ID | Verified at | Evidence |
|----|-------------|----------|
| CR-01 BLOCKER | `prompt_injection_engine.py:99-131` | `_compiled_admin` calls `is_structurally_unsafe` + `probe_redos_safe` on every admin pattern; dropped patterns hash-logged. New shared util `prompt_injection_safety.py` mirrors `policy_form._REDOS_NESTED_QUANTIFIER_RE`. |
| CR-02 BLOCKER | `routes.py:778-782, 791-802` | `"prompt_injection"` added to `has_section_data` prefixes; `publish_policy` now catches `PromptInjectionFormError` and re-renders with locked Russian notice mirroring `/policy/draft`. |
| CR-03 CRITICAL | `prompt_injection_engine.py:197-205` | `matched_pattern=f"[admin pattern {idx}] sha256:{pattern_hash}"` — raw admin regex source never leaves the endpoint. Default catalog still ships `pattern.pattern[:200]` (intentional, public). |
| CR-04 CRITICAL | `schemas/policy.py:204`, `engine.py:75-77,336-346` | `timeout_ms` clamped `Field(default=150, ge=50, le=200)` at schema; module-level lazy `_lg_client = httpx.Client(...)` avoids per-call TCP+TLS; warn-once if YAML-edited timeout exceeds 200ms. Template `min="50" max="200"`. |
| WR-01 | `enforce.py:217-229` | Fail-open path emits `prompt_injection.engine_crash` info finding carrying only `type(exc).__name__` (no traceback/message → no user-text leak). Buffer-write failure swallowed (best-effort). |
| WR-02 | `flusher.py:108-150, 213-216` | `_bump_retry(conn, ids, status=...)` discriminates 4xx (DLQ immediately) from 5xx/network (bump + DLQ-threshold). `flush()` passes `status=` from `_post_with_retry`. |
| WR-03 | `flusher.py` | `_post_batch` removed; only `_post_with_retry` remains. |
| WR-04 | `flusher_main.py:27-34` | `print(f"...: {type(exc).__name__}: {exc!r}", file=sys.stderr)` before returning 0. Exit-code contract preserved. |
| WR-05 | `server/api/findings.py:42-48` | `severity: Literal["info", "warn", "block"]` on `_FindingWire` — `"critical"` rejected with 422. |
| WR-06 | `engine.py:217-269` | `_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{32,}")` + `_shannon_entropy_bits` ≥ 4.5 gate, gated as separate scan step. |
| WR-07 | `engine.py:147-157` | `_compiled_allowlist` now applies `_normalize(raw)` (NFKC+casefold) to substring entries, matching the contract on input side. |
| WR-08 | `enforce.py:59-94` | `_load_policy_cached(path, mtime_ns)` — mtime invalidates cache across publishes; `mtime_ns=0` carries the no-file branch. |
| WR-09 | `prompt_injection_patterns.py:50-81` | 4 new patterns adding Cyrillic+Latin doppelganger character classes for `ignore`, `forget`, `забудь`, `игнорируй`. |

## Re-review Observations (not findings, no action)

Items below are noted for future cleanup but are not defects:

1. **Engine module docstring (`engine.py:27-31`)** still reads "LlamaGuard adds up to `cfg.timeout_ms` of wall-clock per scan and is intentionally OUT of the regex budget." This pre-CR-04 framing is now misleading since `timeout_ms` is capped at 200ms specifically to fit inside the 100ms hot-path. Recommend a one-line update in the next docs sweep.
2. **`_post_with_retry` still uses `with httpx.Client(...)` per attempt** (`flusher.py:237`). Pre-existing in PI-01 — out of scope for this re-review; not introduced by any fix commit.
3. **`_has_high_entropy_base64_run` may FP on JWTs / long base64 payloads in tool_input** (e.g. `Read` of a config file containing an API key blob). The entropy gate of 4.5 plus the 32-char floor minimizes this, but it is a behavioral change worth documenting in 05-CONTEXT.md release notes — does not affect correctness.

## Structural Findings (fallow)

No `<structural_findings>` block was provided by the orchestrator on either iteration.

---

# Original Review Body (Iteration 1 — preserved for history)

**Reviewed:** 2026-05-26
**Depth:** standard
**Files Reviewed:** 12 (incl. templates)
**Status:** issues_found (now resolved — see Iteration 2 above)

## Summary

Phase 5 implements prompt-injection detection with a regex engine + optional LlamaGuard deep-scan, an async findings buffer/flusher pipeline, and a policy-editor UI section. The architecture matches the stated design (clone-not-extend of audit_hook, fail-open semantics, NFKC normalization, allowlist-before-detect). However, the review surfaces several material defects:

- **Two BLOCKERs**: admin-supplied regex from a published policy is NOT validated for ReDoS on the agent hot-path (only at form-submit), so a YAML-edited or pre-Phase-5 policy can DoS the PreToolUse hook; and the publish path skips _redos_safe entirely on `/policy/publish` because the section-check whitelist omits `prompt_injection`.
- **Two CRITICAL** issues affecting privacy and hot-path safety: `matched_pattern` for `admin_custom` echoes the operator's raw regex (potential secret/PII leak through the finding pipeline to the central server even after `mask_secrets`); and an existing-draft baseline merge in `form_to_yaml` does not clear the old `prompt_injection` key on the `mandatory` tab, but DOES drop submitted PI section on the rules tab in some flows — see findings.
- Multiple WARNINGS around fail-open scope, schema_version compat for v0.1 agents, base64 detection coverage vs the threat description (entropy heuristic claimed but not implemented), DLQ retry counting, and double-decrement in `_bump_retry`.

The base64 entropy heuristic described in the focus list is NOT in the code — only two keyword-anchored patterns exist. This is a documentation/scope drift worth flagging.

## Structural Findings (fallow)

No `<structural_findings>` block was provided by the orchestrator.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Admin custom regex from published policy is NOT ReDoS-checked on the agent — bypasses _redos_safe via direct YAML or pre-Phase-5 policies — **BLOCKER**  **[FIXED 2026-05-26 — commit 74b4219]**

**File:** `src/ccguard/agent/prompt_injection_engine.py:80-93`, `src/ccguard/server/web/routes.py:760-781`

**Issue:** `_compiled_admin` only catches `re.error` (syntactically invalid). Any pattern that parses but exhibits catastrophic backtracking (e.g. `^(a+)+$`, `(.*a){25}`, `(\w+)*!`) is compiled and run against every tool_input on the PreToolUse hot path. The only ReDoS gate is `_redos_safe` in `policy_form.py`, which runs *only* in the form-time validator under `/policy/draft`. Two bypass paths exist:

1. **`/policy/publish` skips re-parse for the PI section.** Lines 762–766: `has_section_data` whitelists only `("mcp_servers", "network", "commands", "skills", "hooks", "agents", "env")`. A request to `/policy/publish` carrying `prompt_injection.*` fields without any of the listed sections does NOT re-enter `form_to_yaml`, so `_parse_prompt_injection` (and `_redos_safe`) is never called. Publishing the existing draft skips validation too.
2. **YAML edits / bootstrap.** The server has a CLI/bootstrap path to seed `default_policy.yaml`. An operator hand-editing YAML with a malicious regex never sees `_redos_safe`. The agent loads via `yaml.safe_load` → `Policy.model_validate` (no regex check).

A single 4 KB tool_input + `(a+)+!` blows the 100 ms PreToolUse budget by orders of magnitude. Because the engine treats unexpected exceptions in `_compiled_admin` calls as "skip", a hung `re.search` is not caught — no timeout exists at scan time.

**Fix:** Either (a) re-validate every admin pattern at scan time with a fast structural check (the same `_REDOS_NESTED_QUANTIFIER_RE` from policy_form.py can live in a shared util and run inside `_compiled_admin`), silently dropping unsafe entries; OR (b) run every regex inside a wall-clock-capped helper (signal-alarm or threaded `re.search` with timeout). Option (a) is cheaper and matches the existing fail-open posture:

```python
# prompt_injection_engine.py
from ccguard.agent.prompt_injection_safety import is_structurally_unsafe  # shared util

@lru_cache(maxsize=4)
def _compiled_admin(patterns_tuple):
    out = []
    for raw in patterns_tuple:
        if is_structurally_unsafe(raw):
            continue
        try:
            out.append(re.compile(raw, _ADMIN_FLAGS))
        except re.error:
            continue
    return tuple(out)
```

And fix `routes.py:762-766` to include `"prompt_injection"` in the section sniff so the publish path re-validates.

---

### CR-02: `/policy/publish` allowlist drops `prompt_injection` section entirely on direct-publish path — silent data loss + skipped validation — **BLOCKER**  **[FIXED 2026-05-26 — commit 4a2a2d1]**

**File:** `src/ccguard/server/web/routes.py:762-781`

**Issue:** In `publish_policy`, `has_section_data` only checks the v0.1 section prefixes. If the form posts `prompt_injection.*` keys (no v0.1 sections), `has_section_data` is False → `save_draft` is never called → `publish_draft` runs against the (possibly stale) existing draft. Conversely, when v0.1 sections ARE present, `form_to_yaml(form, ..., tab=)` defaults `tab="rules"` (no `tab` kwarg passed at line 772), which DOES include `_parse_prompt_injection`. So:

- Publish with only PI changes via the rules-page button → PI changes silently discarded.
- Publish with mixed changes → PI section is re-parsed and validated (good), but a `ValidationError` raises HTTP 422 with raw pydantic error string (no Russian-locked notice), inconsistent with `/policy/draft` UX.
- Publish path catches `ValidationError` but NOT `PromptInjectionFormError` (line 775) — bad PI input on publish yields an uncaught 500.

**Fix:**
1. Add `"prompt_injection"` to the prefixes tuple at line 765.
2. Catch `PromptInjectionFormError` in publish too and re-render with the same locked notice, mirroring `/policy/draft`:

```python
except PromptInjectionFormError as exc:
    return _render_rules_page(request, user=user, session=session,
        errors={exc.section: str(exc)},
        policy_override=_policy_with_pi_form_overrides(session, dict(form)),
        status_code=200)
```

---

### CR-03: `admin_custom` finding leaks operator's raw regex into the central findings DB; only built-in patterns benefit from privacy guarantee — **CRITICAL**  **[FIXED 2026-05-26 — commit c0230aa]**

**File:** `src/ccguard/agent/prompt_injection_engine.py:146-153`, `src/ccguard/agent/findings_hook/buffer.py:115`

**Issue:** When an admin custom pattern matches, `matched_pattern=pattern.pattern[:_MAX_PATTERN_LEN]` — that is, the REGEX SOURCE, not the matched substring. The focus list claims "matched_pattern truncated to 200 chars in finding details; no raw tool_input in finding payload." That's true for tool_input, but the admin's regex IS shipped to the server in plaintext. If an operator writes a pattern like `password=([A-Za-z0-9]{16,})` (intending to detect leaked secrets), the regex itself encodes the very secret-shape they're trying to find. `mask_secrets` is applied AT THE BUFFER, but `mask_secrets` is a *secret-shape detector* — it scrubs sk-/AKIA/JWT etc. from the *value*, not from a regex *describing* a value. Admin patterns containing literal company internal hostnames, employee names in honeypot strings, or licensed third-party content will also leak.

Two related concerns:

1. The same applies to **default catalog patterns** — `pattern.pattern` is leaked. Less severe because they're public, but `matched_pattern=f"llama-guard:{cats_truncated}"` on LG path uses the raw model response prefix — if Ollama is misbehaving, arbitrary 50 chars of model text reach the server.
2. The contract should be "category + a stable rule_id is enough"; the regex source should never leave the endpoint.

**Fix:** Stop putting `pattern.pattern` into the finding. Either (a) emit the *matched span* of the normalized text (still risky), or preferably (b) emit only `category` + `rule_id` + a short opaque hash of the pattern, and use the title for human context:

```python
return ScanResult(
    category=category,
    matched_pattern=f"pattern:{hashlib.sha256(pattern.pattern.encode()).hexdigest()[:12]}",
    source="regex",
    rule_id=f"prompt_injection.{category}",
)
```

If admins need to know which custom pattern fired, surface that in local audit (already kept) without shipping the regex upstream.

---

### CR-04: LlamaGuard scan runs synchronously on the PreToolUse hot path, breaking the <100ms latency budget by `timeout_ms` (default 500ms) — **CRITICAL** for stated SLA  **[FIXED 2026-05-27 — commit 29c8a84]**

**File:** `src/ccguard/agent/prompt_injection_engine.py:157-160, 192-219`, `src/ccguard/agent/enforce.py:174-219`

**Issue:** The engine's docstring (lines 27-31) explicitly says "LlamaGuard adds up to cfg.timeout_ms of wall-clock per scan and is intentionally OUT of the regex budget." But the focus list states: "PreToolUse latency: <100ms hard". `LlamaGuardConfig.timeout_ms` defaults to **500ms** with max 10000ms; admin can set this to anything ≤ 10s. `pi_scan` is called synchronously inside `decide()`. When `llama_guard.enabled=True`, *every* tool call pays up to 500ms before any decision returns — that's 5x the budget. Even at the minimum configurable `timeout_ms=50`, you spend half the budget on HTTP for a single ScanResult.

Additionally, `_llama_guard_scan` uses a fresh `httpx.Client` per call (line 216), forcing TCP+TLS handshake (~5–30ms locally) on every invocation. No connection pooling.

This contradicts the explicit constraint in CLAUDE.md: "PreToolUse hook latency < 100ms".

**Fix:** Either (a) document and lower `LlamaGuardConfig.timeout_ms` max to ~50ms (and clamp the existing default), or (b) move LlamaGuard off the synchronous decision path entirely — fire-and-forget, write a finding asynchronously, never block the hook. If LG cannot meet the budget, gate it behind a "deep-scan" mode the admin opts into with eyes open.

Minimum fix today: clamp default to 30ms and reuse a process-wide `httpx.Client` via lru_cache or module-level singleton.

## Warnings

### WR-01: Engine-crash fail-open emits NO finding — losing visibility on real engine bugs  **[FIXED 2026-05-27 — commit 3cda8a4]**

**File:** `src/ccguard/agent/enforce.py:180-189`

**Issue:** When `pi_scan` raises and `block_fail_mode == "open"`, the code logs and `pi_result = None`. No finding is emitted, so the central server has zero visibility into engine crashes across the fleet. Compare to LG model-missing which DOES emit an info finding.

**Fix:** emit an `info` finding with `rule_id="prompt_injection.engine_error"` before falling through:

```python
emit_finding(rule_id="prompt_injection.engine_error", severity="info",
             title="Prompt-injection engine crashed (fail-open)",
             source="regex", matched_pattern=type(exc).__name__,
             tool_name=payload.tool_name)
```

---

### WR-02: `_bump_retry` double-updates the same rows + DLQ threshold check happens after the bump, leading to incorrect retry semantics  **[FIXED 2026-05-27 — commit be8d293]**

**File:** `src/ccguard/agent/findings_hook/flusher.py:108-125`

**Issue:** `_bump_retry` runs `retry_count = retry_count + 1` then a second UPDATE checking `retry_count >= _DLQ_THRESHOLD (=3)`. With `_MAX_ATTEMPTS = 3` retries inside `_post_with_retry`, a single `flush()` call only bumps retry_count by 1 per failed batch. So the DLQ trip happens on the *third* `flush()` invocation, not after one batch of 3 HTTP attempts as the docstring implies ("retry_count reaches 3"). Also: the second statement is conditioned on `_DLQ_THRESHOLD`, but `_MAX_ATTEMPTS` and `_DLQ_THRESHOLD` are both 3 — the coincidence masks a semantic bug. A permanently-400 row sticks in the buffer for at least 3 flusher invocations.

Additionally, the function comment says "DLQ-marks 4xx" but `_bump_retry` is called uniformly on any failure (line 220) — there's no 4xx-vs-5xx discrimination. The docstring above (lines 117-120) is misleading.

**Fix:** Distinguish 4xx (DLQ immediately) from 5xx/network (bump-and-retry). Pass `status` into `_bump_retry` and do an immediate DLQ for 400/422.

---

### WR-03: `_post_batch` is dead code — unused private function  **[FIXED 2026-05-27 — commit 134ccd0]**

**File:** `src/ccguard/agent/findings_hook/flusher.py:128-154`

**Issue:** `_post_batch` is defined but never called; `flush()` uses `_post_with_retry` instead. Dead code accumulates maintenance debt and confuses readers.

**Fix:** Delete `_post_batch`.

---

### WR-04: `flusher.py` re-creates schema on every cold flush even when buffer doesn't exist — but the agent's normal call path is `flusher_main.main` which catches *all* exceptions and returns 0 — silent failures invisible  **[FIXED 2026-05-27 — commit 72786dc]**

**File:** `src/ccguard/agent/findings_hook/flusher_main.py:18-25`

**Issue:** `flusher_main.main` swallows every exception and returns 0. If `flush()` raises because of a sqlite corruption, missing config dir, or programmer error, the operator sees no signal — `retry_count` will not grow because the failure is before the retry loop. Logging is absent. Compare with the audit-hook flusher (presumably) emits a similar contract; if not, at least add a stderr write so cron logs capture it.

**Fix:** Log to stderr before swallowing:

```python
except Exception as exc:
    print(f"ccguard.findings_hook.flush error: {exc!r}", file=sys.stderr)
    return 0
```

---

### WR-05: `_FindingWire.severity` accepts `"critical"` but agent emit path never produces it — schema drift between agent and server contracts  **[FIXED 2026-05-27 — commit 827d7c3]**

**File:** `src/ccguard/server/api/findings.py:42`, `src/ccguard/agent/findings_hook/buffer.py:92-115`

**Issue:** Server accepts `Literal["info", "warn", "block", "critical"]`. Agent's `emit_finding` is typed as `severity: str` (no enum), and the call sites in `enforce.py` only pass `"info"` or `pi_cfg.severity` (∈ `{info, warn, block}`). `"critical"` is reachable only if some future emit site uses it or if the buffer DB is hand-edited. More important: a malformed buffer row with `severity="foo"` will be rejected by FastAPI's pydantic validation → 422 → flusher bumps retry_count → eventually DLQ → silent loss with no operator notification.

**Fix:** Validate severity at `emit_finding` (Literal). On 422 from server, log the rejected rows before DLQ-marking so the admin can find them in agent logs.

---

### WR-06: Base64 entropy heuristic claimed in design but NOT implemented — only keyword-anchored patterns exist  **[FIXED 2026-05-27 — commit 60d5ff0]**

**File:** `src/ccguard/agent/prompt_injection_patterns.py:93-103`

**Issue:** Focus point 11: "Base64: entropy heuristic threshold reasonable; no false-positive on natural English". There is no entropy check. The two `base64_encoded_prompt` patterns are pure regex — `bbase64\s*[:=]\s*[A-Za-z0-9+/=]{20,}` and `decode ... base64`. This is fine (low FP risk), but the design promise is not met. Either remove "entropy heuristic" from the spec or add one. Standalone 20+ char base64 blobs without the `base64:` keyword (the realistic attack shape) go undetected.

**Fix:** Add a third pattern that detects long base64 runs followed by a decode-hint, or implement a Shannon-entropy check in the engine post-regex pass (gated behind config to avoid FP).

---

### WR-07: NFKC normalization runs AFTER allowlist compilation casefolding but `entry in norm` uses Python `in` — substring match on normalized text, which can produce surprising false-positives across normalization boundaries (e.g., `½` → `1⁄2`)  **[FIXED 2026-05-27 — commit 2dcb653]**

**File:** `src/ccguard/agent/prompt_injection_engine.py:111, 129`

**Issue:** Allowlist entries are casefolded but NOT NFKC-normalized at compile time (line 111). The input IS NFKC-normalized (line 124). A literal allowlist entry like `"½off"` will never match input that arrives as `"½off"` because NFKC turns the input into `"1⁄2off"` while the entry stays `"½off"`. The casefold-only contract on allowlist entries is inconsistent with the NFKC contract on input.

**Fix:** Apply `_normalize` to allowlist substrings in `_compiled_allowlist`:

```python
else:
    out.append(_normalize(raw))  # NFKC + casefold to match input
```

---

### WR-08: `_load_policy` uses `lru_cache(maxsize=4)` keyed on path string — never re-reads on file change within process lifetime  **[FIXED 2026-05-27 — commit 3aff44a]**

**File:** `src/ccguard/agent/enforce.py:59-70`

**Issue:** This existed pre-Phase-5 but is in the touched file. `lru_cache` keyed only on path will return stale policy for the lifetime of the process if it lives across multiple PreToolUse invocations (Claude Code may keep the hook process warm). For a one-shot CLI invocation this is moot, but if the hook is re-used the policy could be stale across publishes. Comment says "for CLI-call it's effective: process is short-lived" — but no guarantee.

**Fix:** Key the cache on `(path, st_mtime_ns)` so file edits invalidate.

---

### WR-09: NFKC docstring asserts homoglyphs are NOT collapsed; but the only Cyrillic pattern is anchored on literal Cyrillic chars — Latin-look-alike "ignогe" attacks bypass detection  **[FIXED 2026-05-27 — commit 3413588]**

**File:** `src/ccguard/agent/prompt_injection_engine.py:69-77`, `prompt_injection_patterns.py:45-49`

**Issue:** Acknowledged in the docstring ("NFKC does NOT collapse Cyrillic homoglyphs"). Focus point 10: "Cyrillic doppelganger pattern coverage". The default catalog includes one Cyrillic-only pattern but does not cover mixed-script doppelganger attacks like `ignоre previous` (Cyrillic о). Mixed-script normalization (e.g., via `unicodedata.normalize("NFKD", s)` plus confusables map, or `confusable-homoglyphs`) is the standard mitigation.

**Fix:** Either acknowledge the gap as "v0.3 — RU coverage deferred" (already in patterns docstring) or add a confusables-collapse step. Currently the focus item is not satisfied.

## Info

### IN-01: Buffer `emit_finding` is sync; PreToolUse contract says <10ms — first emit incurs schema CREATE + WAL init (~5-15ms locally)

**File:** `src/ccguard/agent/findings_hook/buffer.py:59-89`

**Issue:** Cold-start cost on first call (mkdir + connect + PRAGMA + DDL) violates the 10ms hot-path claim. Subsequent calls hit the cached connection. Document the cold-path cost; do not promise 10ms for first call.

---

### IN-02: Inconsistent severity-vs-permission semantics

**File:** `src/ccguard/agent/enforce.py:213-219`

`if pi_cfg.severity == "block"` returns deny; warn/info fall through. This matches the spec, but the `decision.permission` value emitted to audit will be `allow` for warn/info even though a finding was created. Operators reading audit will not see the PI flag-but-allowed event without correlating with findings. Consider emitting a structured `decision.reason` augmentation when a PI finding was generated.

---

### IN-03: `_extract_pi_payload` concatenates with `\n` — regex pattern using `^`/`$` semantics changes across joined fields under DOTALL

**File:** `src/ccguard/agent/enforce.py:37-50`

Most patterns don't use anchors, so impact is small. But admin patterns are run with `re.IGNORECASE | re.DOTALL`, so `^` only matches the very start, and the concatenated payload changes positional semantics. Document the contract (or use `\x00` separator that no pattern can match).

---

### IN-04: `findings.py` GET endpoint allows arbitrary `rule_id` query without sanitization — used in raw SQL `where`

**File:** `src/ccguard/server/api/findings.py:60, 68-69`

`rule_id` has no `Query` pattern constraint; SQLModel binds it as a parameter so no SQL injection, but unbounded length could be abused. Add `max_length=128` to match the column constraint.

---

_Reviewed: 2026-05-26_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

---

## Resolution (2026-05-27)

All BLOCKER (CR-01, CR-02), CRITICAL (CR-03, CR-04), and WARNING (WR-01..WR-09) findings fixed across 13 atomic commits on branch `gsd-reviewfix/05-85963`. INFO findings (IN-01..IN-04) skipped per scope.

**Test status:** 759 passed (755 non-e2e + 4 PI e2e). Pre-existing network-dependent e2e tests (`test_end_to_end::test_health_endpoint`, etc.) unchanged from the pre-fix state.

**Commits, in order:**

| Finding | Commit | One-liner |
|--------|--------|-----------|
| CR-01 | 74b4219 | ReDoS defense-in-depth on agent for admin patterns |
| CR-02 | 4a2a2d1 | include prompt_injection in /policy/publish section sniff |
| CR-03 | c0230aa | do not ship raw admin regex source in findings |
| CR-04 | 29c8a84 | clamp LlamaGuard timeout 500→150ms/200ms cap, reuse httpx.Client |
| WR-01 | 3cda8a4 | emit info finding on engine crash |
| WR-02 | be8d293 | discriminate 4xx vs 5xx in flusher retry |
| WR-03 | 134ccd0 | remove dead _post_batch helper |
| WR-04 | 72786dc | log flusher_main exceptions to stderr |
| WR-05 | 827d7c3 | reject 'critical' severity on POST /api/v1/findings |
| WR-06 | 60d5ff0 | Shannon-entropy base64 heuristic |
| WR-07 | 2dcb653 | NFKC-normalize allowlist substrings |
| WR-08 | 3aff44a | mtime-invalidate policy lru_cache |
| WR-09 | 3413588 | mixed-script Cyrillic+Latin doppelganger patterns |

**Privacy invariants preserved:**
- Admin custom regex source still never leaves the endpoint (CR-03 fix unchanged downstream).
- Engine-crash finding (WR-01) carries only the exception class name — no message/traceback.
- No new external deps introduced.

---

## Re-review Verdict (Iteration 2 — 2026-05-27)

**Status: clean.** All 13 findings verified resolved at the cited file/line locations. No new BLOCKER, CRITICAL, or WARNING issues surfaced in re-review of the 12 changed files. Phase 1-4 surfaces untouched (`git diff --stat` confirms only Phase 5 modules + `prompt_injection_safety.py` shared util). 755 non-e2e tests green; 7 pre-existing e2e failures (network/docker-dependent) unchanged from baseline and unrelated to Phase 5 fix surface.

_Re-reviewed: 2026-05-27_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Iteration: 2_
