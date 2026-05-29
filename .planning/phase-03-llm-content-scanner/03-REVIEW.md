---
phase: 03-llm-content-scanner
reviewed: 2026-05-26T00:00:00Z
depth: standard
files_reviewed: 18
files_reviewed_list:
  - src/ccguard/server/services/llm_client.py
  - src/ccguard/server/services/scan_service.py
  - src/ccguard/server/services/settings_service.py
  - src/ccguard/server/api/scan.py
  - src/ccguard/schemas/scan.py
  - src/ccguard/schemas/finding.py
  - src/ccguard/server/db/models.py
  - src/ccguard/server/db/session.py
  - src/ccguard/server/main.py
  - src/ccguard/server/scheduler.py
  - src/ccguard/agent/inventory_scan.py
  - src/ccguard/agent/masking.py
  - src/ccguard/agent/cli.py
  - src/ccguard/server/api/findings.py
  - src/ccguard/server/web/routes.py
  - src/ccguard/server/web/templates/findings_feed.html
  - src/ccguard/server/web/templates/components/_finding_row.html
  - src/ccguard/server/config.py
findings:
  critical: 3
  warning: 9
  info: 5
  total: 17
status: clean
resolved_at: 2026-05-26
resolution:
  critical_fixed: 3
  warning_fixed: 9
  info_fixed: 0
  info_skipped: 5
  pytest: 553 collected; non-e2e (546) → 545 passed, 1 pre-existing failure (test_audit_smoke::test_audit_1000_events_render_table_and_timeline; unrelated to phase 3, failing at baseline before any fix); 7 e2e tests excluded (require docker-compose)
re_reviewed_at: 2026-05-26
re_review:
  iteration: 2
  critical_verified: 3
  warning_verified: 9
  new_findings: 0
  pytest: 545 passed, 1 deselected (pre-existing flake) in 24.86s
  status: all_resolved
---

# Phase 3: Code Review Report

**Reviewed:** 2026-05-26
**Re-reviewed:** 2026-05-26 (iteration 2)
**Depth:** standard
**Files Reviewed:** 18
**Status:** clean (all Critical + Warning findings verified resolved)

## Summary

Phase 3 introduces the LLM content scanner: agent-side collection/masking, server-side scan orchestration, budget enforcement, KV settings, and admin UI. Architecture is generally sound — privacy invariants (hash-only persistence) hold and the synthetic fail-safe path is well-documented. However, the review surfaced multiple correctness defects: the **budget gate is a non-atomic check-then-act and is easily exceeded under concurrency**, the **findings UI severity column hard-codes the old severity ladder and silently mis-renders the new `critical` tier**, the **/findings API regex pattern accepts `critical` but the HTML severity filter dropdown omits it**, and the **admin "budget exhausted" indicator triggers when `budget=0`** (matching disabled state). Several smaller issues exist around backward compat (synthetic `machine_id="_server"` may violate FK on existing DBs), dead code, and the wrong probe-cache layering in `/api/v1/scan-content`.

## Re-Review Summary (iteration 2, 2026-05-26)

All 3 Critical and 9 Warning findings were verified resolved against the working tree. Verification covered code-level fixes for each ID and a full non-e2e test run:

- **545 passed, 1 deselected** (`test_audit_1000_events_render_table_and_timeline`, pre-existing flake unrelated to Phase 3), 89 warnings, 24.86s.
- Phase 1 + Phase 2 surfaces (anomaly scheduler, machine/finding routes, web auth) untouched — no regressions surfaced in `test_anomaly_*`, `test_scheduler_tick`, `test_web_auth`, `test_web_smoke`.

Per-finding verification:

| ID | Commit | Verified file / line | Notes |
|----|--------|----------------------|-------|
| CR-01 | 03b146e | `scan_service.py:198-295` | Budget read, LLM call, and LLMCallLog/ScanResult/Finding insert all run inside `async with self._lock:` + single `Session(...).commit()`. Module docstring (lines 34-43) documents single-process limitation and mandates `uvicorn --workers 1`. |
| CR-02 | 6b43a3d | `_finding_row.html:24-26` | `severity in ('block', 'critical')` → `text-red-600 font-semibold`. |
| CR-03 | 4a2c44e | `findings_feed.html:8` | `<option value="critical">` placed above `block`. |
| WR-01 | a904cb3 | `routes.py:665-674`, `_finding_row.html:31-32` | Distinct `budget_zero` notice ("бюджет равен 0; задайте лимит на /settings") branched before `budget_exhausted`. |
| WR-02 | e9e2dc5 | `_finding_row.html:13-21` | `_server` machine_id rendered as non-link `<span>` with tooltip; no FK violation, no 404 link. |
| WR-03 | 3d5ce11 | `llm_client.py:35,212-214` | `LLM_REQUEST_TIMEOUT_SEC = 30.0` passed to `anthropic.AsyncAnthropic(..., timeout=...)`. |
| WR-04 | d593532 | `settings_service.py:54-72` | `parse_budget()` helper warn-logs once per distinct bad value via `_budget_parse_warned`. Consumed by `scan_service.py:205,348` and `routes.py:509,552`. |
| WR-05 | b4a2425 | `inventory_scan.py:42-59,121` | `_scrub_path()` converts absolute path to `~/.claude/<rel>` BEFORE base64 packing. Fallback to last-2-segments on `ValueError`/`OSError`. |
| WR-06 | 4cca052 | `_finding_row.html:39` | `{{ finding.details.get('file_hash') | urlencode }}` applied. Server-side 64-char-hex validator (`routes.py:624`) intact as defense-in-depth. |
| WR-07 | c59039a | `scan_service.py:297-312`, `scan.py:179-183` | Public `ScanService.peek_cache(content) -> bool` in service; route delegates and the `svc._engine` private access is gone. |
| WR-08 | 4a49750 | `scan_service.py:326-329` | `rescan_file` raises `ValueError` on non-64-char-hex at service surface. Route validator at `routes.py:624` retained. |
| WR-09 | 8d88c1f | `scheduler.py:114-121` | Single `update(ScanResult).values(ttl_expires_at=now_expired)` statement; no per-row Python loop, no long-held write transaction. |

Status closed: **clean**. All Info findings (IN-01..IN-05) remain intentionally deferred per the original fix-pass scope (Critical + Warning only); they are nits and do not block ship.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Budget gate is a check-then-act race; daily budget can be exceeded
**Resolved: 2026-05-26 (commit 03b146e).** Budget read + LLM call + LLMCallLog insert now run inside a single asyncio.Lock-protected Session transaction. Single-process limitation documented in module docstring; v0.2 requires uvicorn --workers 1.
**Re-verified: 2026-05-26 (iteration 2).** Confirmed `scan_service.py:198-295` — entire critical section (budget count + LLM await + LLMCallLog/ScanResult/Finding insert + commit) is inside `async with self._lock:` and one `Session(self._engine)` block. Docstring lines 34-43 codify the `--workers 1` requirement.

**File:** `src/ccguard/server/services/scan_service.py:194-212`
**Issue:** `scan_file` reads `used = SELECT count(*) FROM llmcalllog WHERE ts >= day_start` in one session, releases it, **then** awaits the LLM call **inside** the lock, and **then** inserts the `LLMCallLog` row in a third session. The `asyncio.Lock` only covers `self._llm.scan_content`; the count query happens BEFORE the lock and the insert happens AFTER the lock releases. Two concurrent callers can both observe `used == budget - 1`, both pass the gate, both acquire the lock serially, and both insert. End state: `used == budget + 1`. With higher concurrency the over-run grows linearly with concurrent request count. The class docstring says "atomic-per-call" — it is not. Worse, the `/scan-content` endpoint deliberately runs sequentially per batch, but multiple *agents* (or multiple batches from one agent) can race trivially.

Additionally, the budget check is multi-process unsafe: `asyncio.Lock` is per event loop / process. With any uvicorn `--workers > 1` deployment, the lock is useless.

**Fix:** Move both the count and insert inside the same lock-protected critical section, AND use a single SQL transaction that does `INSERT ... WHERE (SELECT count(*) ...) < :budget` (or `INSERT` then immediately re-count and rollback on overrun). At minimum:
```python
async with self._lock:
    with Session(self._engine) as s:
        used = s.exec(select(func.count()).select_from(LLMCallLog)
                       .where(LLMCallLog.ts >= day_start)).one()
        used = used[0] if isinstance(used, tuple) else used
        if used >= budget:
            raise BudgetExhaustedError(...)
        # ... call LLM, then insert log + result in same session.commit()
```
And document explicitly in the module docstring that **single-worker uvicorn is mandatory** (or move budget tracking to a DB-level UPSERT counter that works cross-process).

### CR-02: `_finding_row.html` does not color the `critical` severity; renders grey "info" style
**Resolved: 2026-05-26 (commit 6b43a3d).** `critical` now shares the red-600 + font-semibold styling with `block`, matching the risk badge.
**Re-verified: 2026-05-26 (iteration 2).** `_finding_row.html:24` reads `{% if finding.severity in ('block', 'critical') %}text-red-600 font-semibold`.

**File:** `src/ccguard/server/web/templates/components/_finding_row.html:18-20`
**Issue:** The severity cell uses:
```jinja
{% if finding.severity == 'block' %}text-red-600
{% elif finding.severity == 'warn' %}text-amber-600
{% else %}text-slate-500{% endif %}
```
Phase 3 added `critical` to the severity ladder (per D-01) — `critical` falls into the `else` branch and is painted with the same neutral slate-500 color as `info`. The whole purpose of LLM-scanner findings >70 (the most dangerous) is to stand out, and they currently render less prominently than a `block` finding from Phase 1. This is a regression of the security UX promise locked in 03-CONTEXT.md.

**Fix:**
```jinja
{% if finding.severity in ('block', 'critical') %}text-red-600 font-semibold
{% elif finding.severity == 'warn' %}text-amber-600
{% else %}text-slate-500{% endif %}
```

### CR-03: `/findings` UI dropdown silently filters out the new `critical` severity
**Resolved: 2026-05-26 (commit 4a2c44e).** Added `<option value="critical">` above `block` in the severity select.
**Re-verified: 2026-05-26 (iteration 2).** `findings_feed.html:8` exposes the `critical` option above `block`, ordering matches severity weight.

**File:** `src/ccguard/server/web/templates/findings_feed.html:6-11` (and `src/ccguard/server/api/findings.py:18`)
**Issue:** The HTML `<select name="severity">` exposes only `block | warn | info` — there is no option for `critical`. A user filtering by "block" gets only Phase 1+2 findings and never sees LLM-scanner criticals. The JSON API regex `^(info|warn|block|critical)$` was updated, but the UI was not. Combined with CR-02 (criticals are visually indistinguishable from info), criticals are effectively invisible in the only feed UI that lists them.

**Fix:** Add `<option value="critical" {% if filters.severity == "critical" %}selected{% endif %}>critical</option>` to the severity select, place it ABOVE `block` so the ordering matches severity weight.

## Warnings

### WR-01: Admin "budget exhausted" notice fires when `budget=0` (default disabled state)
**Resolved: 2026-05-26 (commit a904cb3).** Added a distinct `budget_zero` notice ("бюджет равен 0; задайте лимит на /settings") rendered when scanner is enabled but budget is 0.
**Re-verified: 2026-05-26 (iteration 2).** `routes.py:665-674` branches `budget == 0` → `budget_zero` before the `used >= budget` check; `_finding_row.html:31-32` renders the dedicated message.

**File:** `src/ccguard/server/web/routes.py:663-668`
**Issue:** `admin_scan_rescan` builds the inline notice as:
```python
if not usage["enabled"]:
    notice = "scanner_disabled"
elif usage["used"] >= usage["budget"]:
    notice = "budget_exhausted"
```
With the seeded default `daily_call_budget=100` this is fine, but if an admin sets budget to `0` (or the value fails to parse — see WR-04) AND the scanner is enabled, `used (0) >= budget (0)` evaluates true and the row gets a misleading "бюджет исчерпан" label even though no scan has been attempted today. The same fall-through exists in `ScanService.scan_file` at line 205 — `if used >= budget:` raises `BudgetExhaustedError` immediately when `budget=0`, which is arguably correct behavior but undocumented; a UI hint that "scanner is enabled but budget=0 disables it" would be safer.

**Fix:** Treat `budget == 0` as a distinct state (e.g., notice `"budget_zero"` with text "бюджет равен 0; задайте лимит") OR validate at `admin_llm_settings_save` that an *enabled* scanner cannot have budget 0.

### WR-02: `synthetic _server` finding may violate Machine FK on pre-Phase-3 SQLite DBs
**Resolved: 2026-05-26 (commit e9e2dc5).** Template option (b): `_server` machine_id is rendered as a non-link `<span>` with a tooltip ("LLM-сканер (серверная находка)") instead of a 404-prone `<a>`. No DB migration needed.
**Re-verified: 2026-05-26 (iteration 2).** `_finding_row.html:13-21` switches on `finding.machine_id == '_server'` → `<span class="text-slate-500" title="LLM-сканер (серверная находка)">`.

**File:** `src/ccguard/server/services/scan_service.py:272-281`
**Issue:** LLM findings are inserted with `machine_id="_server"` without first ensuring a corresponding `Machine` row exists. There is no SQL-level FK declared between `FindingRecord.machine_id` and `Machine.machine_id` so this won't raise on insert, but several places assume the join succeeds:
- `findings.py:36` does `session.get(Machine, r.machine_id)` — returns None, label_cache stores None — OK.
- `_finding_row.html:13` renders `<a href="/machines/_server">` which 404s on click (machine_detail at routes.py:158-160).
The user sees a clickable link to a 404. Inventory upload (Phase 1) also creates `Machine` rows on the fly; the LLM scanner does not, so the `_server` row never exists.

**Fix:** Either (a) create a singleton `Machine(machine_id="_server", machine_label="ccguard server (LLM scanner)")` on first finding emit (idempotent get-or-create), or (b) special-case the template to render `_server` as a non-link badge. Option (a) is cleaner and avoids template branching everywhere `machine_id` is rendered.

### WR-03: `LLMClient` does not pass an HTTP timeout to the Anthropic SDK
**Resolved: 2026-05-26 (commit 3d5ce11).** Set `LLM_REQUEST_TIMEOUT_SEC = 30.0` on `anthropic.AsyncAnthropic(...)`, mirroring agent-side timeout.
**Re-verified: 2026-05-26 (iteration 2).** `llm_client.py:35` defines `LLM_REQUEST_TIMEOUT_SEC: Final[float] = 30.0`; `llm_client.py:212-214` passes it to `anthropic.AsyncAnthropic(api_key=..., timeout=...)`.

**File:** `src/ccguard/server/services/llm_client.py:203-228`
**Issue:** `anthropic.AsyncAnthropic(api_key=...)` is constructed without an explicit `timeout` argument, and `messages.create` is also called without one. The Anthropic SDK default is 10 minutes. A hung or slow API call holds the `ScanService._lock` indefinitely (since the await happens *inside* the lock at line 212), which blocks every other concurrent `scan_file` caller. Combined with the per-instance lock, one slow LLM call freezes the entire scanner subsystem for up to 10 minutes.

**Fix:** Set a sensible per-request timeout (e.g., 30s) either at SDK init (`anthropic.AsyncAnthropic(api_key=..., timeout=30.0)`) or per-call (`messages.create(..., timeout=30.0)`). The HTTP agent already uses `DEFAULT_TIMEOUT_SEC = 30.0`; mirror it on the server side.

### WR-04: `_settings_context` and `admin_llm_settings_save` silently coerce invalid `daily_call_budget` to 0/`-1`
**Resolved: 2026-05-26 (commit d593532).** Added `settings_service.parse_budget()` helper that warn-logs once per distinct bad value. All three call sites (scan_service, _settings_context, _llm_usage_summary) now delegate.
**Re-verified: 2026-05-26 (iteration 2).** `settings_service.py:54-72` defines `parse_budget` with `_budget_parse_warned: set[str]` for once-per-value warning. Imports in `scan_service.py:63`, `routes.py:505,546` confirm all three callers delegate.

**File:** `src/ccguard/server/web/routes.py:502-505`, `:586-589`
**Issue:** `int(get_setting(...) or "0")` in a `try/except ValueError → budget = 0` masks corruption: if the KV row ever stores a non-numeric value (manual DB edit, future migration bug), the UI silently shows budget 0 and `ScanService.scan_file` will immediately raise `BudgetExhaustedError` on every call. There is no log line, no admin warning. Same anti-pattern in `scan_service.py:189-192` and `:312-316`. The pattern should at least warn-log when the parse fails so operators see the corruption in journalctl.

**Fix:** Wrap the parse in a helper that logs once on failure:
```python
def _parse_budget(raw: str | None) -> int:
    if not raw:
        return 0
    try:
        return int(raw)
    except ValueError:
        logger.warning("daily_call_budget value %r is not an int; treating as 0", raw)
        return 0
```

### WR-05: Server logs `file_path` from the agent — potential PII leak if file path contains usernames or repo names
**Resolved: 2026-05-26 (commit b4a2425).** Agent now scrubs `file_path` to a `~/.claude/<rel>` form via `_scrub_path(path, claude_home)` BEFORE base64 packing, so the server log and the Anthropic user message never carry the OS username. Fallback to last-2-segments if `relative_to()` fails.
**Re-verified: 2026-05-26 (iteration 2).** `inventory_scan.py:42-59` defines `_scrub_path`; line 121 applies it before constructing `ScanRequestItem`. Fallback at lines 54-58 uses last-2-segments on `ValueError`/`OSError`.

**File:** `src/ccguard/server/api/scan.py:151,159,217,236`; `src/ccguard/server/services/llm_client.py:218`
**Issue:** `file_path` is logged at INFO ("scan-content: file_path=%s file_hash=%s ...") and is included in the user-message body sent to Anthropic. The agent passes `str(path)`, which is the absolute filesystem path (`/Users/<username>/.claude/agents/foo.md` or `C:\Users\<corpid>\.claude\skills\bar\SKILL.md`). This leaks the developer's OS username — a low-grade PII / identifying signal that may be in scope under the project's own privacy promises ("server NEVER stores raw content" — but absolute paths arguably are content). The README/CONTEXT promise is content-privacy, but the threat model in 03-CONTEXT.md should be cross-checked.

**Fix:** Have the agent send the *relative* path (`agents/foo.md`, `skills/bar/SKILL.md`) instead of the absolute one, OR have the server strip the leading `/Users/<x>/.claude/` / `C:\Users\<x>\.claude\` segment before logging/sending to the LLM. The path is metadata, not load-bearing for classification.

### WR-06: `_finding_row.html` interpolates `file_hash` directly into hx-post URL without server-side validation in the form action
**Resolved: 2026-05-26 (commit 4cca052).** Template applies `| urlencode` to `file_hash` before interpolation; server-side validator at `/admin/scan/{file_hash}/rescan` still enforces 64-char hex as defense-in-depth.
**Re-verified: 2026-05-26 (iteration 2).** `_finding_row.html:39` reads `hx-post="/admin/scan/{{ finding.details.get('file_hash') | urlencode }}/rescan"`. Server validator `routes.py:624` unchanged.

**File:** `src/ccguard/server/web/templates/components/_finding_row.html:31`
**Issue:** `hx-post="/admin/scan/{{ finding.details.get('file_hash') }}/rescan"` — Jinja's default autoescape applies to HTML attributes but does NOT URL-encode. `file_hash` comes from `payload_json` which originated from `ScanService.scan_file` (sha256 hex, safe). But the *template* trusts the payload shape: if a future code path emits an LLM finding with a malformed `file_hash` containing `/` or `..`, the HTMX request would target the wrong path and 404 (best case) or hit an unintended route (worst case). The server-side handler at `routes.py:623` correctly validates `len==64` and hex-only, so this is defense-in-depth, not a present exploit.

**Fix:** Add `| urlencode` filter in the template AND assert the payload `file_hash` matches the expected sha256 shape when building the view-model (`_finding_view_model`).

### WR-07: `cached` flag in `/scan-content` response is computed by re-implementing cache logic outside `ScanService`
**Resolved: 2026-05-26 (commit c59039a).** Added public `ScanService.peek_cache(content) -> bool`; `/scan-content` route delegates to it. Removed `svc._engine` private access. Hash + TTL logic now lives in one place.
**Re-verified: 2026-05-26 (iteration 2).** `scan_service.py:297-312` exposes `peek_cache` using `_file_hash` + `_aware_utc` helpers (shared with `scan_file`). `scan.py:179-183` calls `svc.peek_cache(content)`; grep confirms no remaining `svc._engine` references in the route.

**File:** `src/ccguard/server/api/scan.py:178-198`
**Issue:** The HTTP handler probes the cache via a private `svc._engine` access (`# noqa: SLF001`) and duplicates the TTL check from `ScanService`. This is brittle: if `ScanService` changes its cache key (e.g., includes scope in the hash, normalizes whitespace), the probe will diverge silently and report `cached=false` while the service still hits the cache. The response field becomes a lie. The accepted approach should be exposing `ScanService.peek_cache(content) -> bool | ScanResult | None` and using it from the route.

**Fix:** Add a `peek_cache(content_or_hash)` method on `ScanService` and use it; remove the `svc._engine` private-access probe.

### WR-08: `rescan_file` does not enforce sha256 shape on its argument
**Resolved: 2026-05-26 (commit 4a49750).** `rescan_file` now raises `ValueError` on non-64-char-hex input at the service surface. Route handler validation remains as defense-in-depth.
**Re-verified: 2026-05-26 (iteration 2).** `scan_service.py:326-329` enforces `len(file_hash) != 64` or non-hex chars → `ValueError`.

**File:** `src/ccguard/server/services/scan_service.py:287-303`
**Issue:** `rescan_file(file_hash)` accepts any string and does `SELECT WHERE file_hash == ?`. No callers currently pass user input directly (the route at `routes.py:623` validates), but the service surface is the natural call point and offers no defense. Adding length+hex validation here would mean every caller doesn't have to remember to do it.

**Fix:** At the top of `rescan_file`:
```python
if len(file_hash) != 64 or any(c not in "0123456789abcdef" for c in file_hash):
    raise ValueError(f"invalid file_hash: {file_hash!r}")
```

### WR-09: `rescan_all_files` loads every ScanResult row into memory, mutates, and commits in one transaction
**Resolved: 2026-05-26 (commit 8d88c1f).** Replaced select+per-row mutate with a single `UPDATE scanresult SET ttl_expires_at = :ts` bulk statement; the SQLite WAL writer is no longer held while iterating in Python.
**Re-verified: 2026-05-26 (iteration 2).** `scheduler.py:114-121` uses `update(ScanResult).values(ttl_expires_at=now_expired)` — single SQL round-trip, no Python-side iteration.

**File:** `src/ccguard/server/scheduler.py:102-116`
**Issue:** `rows = list(s.exec(select(ScanResult)))` materializes every row, then sets `ttl_expires_at` on each, then commits. At the project's stated scale (<100 machines × ~10 agents+skills each = ~1000 rows) this is fine today, but a single `UPDATE scanresult SET ttl_expires_at = ?` would be one round-trip vs N. More importantly, the long-held write transaction blocks the SQLite WAL writer for everyone else.

**Fix:** Replace with a bulk UPDATE:
```python
with engine.begin() as conn:
    conn.execute(text("UPDATE scanresult SET ttl_expires_at = :ts"), {"ts": now_expired})
```

## Info

_All Info findings (IN-01 through IN-05) were intentionally skipped during the 2026-05-26 fix pass per `/gsd:code-review --fix` scope (Critical + Warning only). They remain as documented nits for a future cleanup pass._

### IN-01: Dead code — `finding_row` variable in `admin_scan_rescan`

**File:** `src/ccguard/server/web/routes.py:638-642`
**Issue:** `finding_row = session.exec(...).first()` is computed and then only used as a fallback at line 661 (`target = finding_row`). The second query at line 646-651 immediately overrides this with a 50-row iterator. The first `.first()` query is redundant — `cands.first()` could be reused, or `finding_row` could be removed and the fallback set to `None`.

**Fix:** Delete the first query; set `target = None` as the fallback.

### IN-02: `_extract_tool_use` uses `getattr` with default `[]` then short-circuits via `or []`

**File:** `src/ccguard/server/services/llm_client.py:136`
**Issue:** `for block in getattr(response, "content", []) or []:` — the `or []` is unreachable; `getattr` already supplies `[]` as the default. If `response.content` is explicitly `None`, then `None or []` does work, so this is defensive against an SDK quirk. Worth a comment if intentional.

**Fix:** Either drop the `or []` (relying on the `getattr` default) or add a comment explaining the SDK may set `content=None`.

### IN-03: `seed_llm_settings` uses `.in_` with a list inside `select` — extra eager `.all()`

**File:** `src/ccguard/server/services/settings_service.py:55-62`
**Issue:** Builds a set of existing keys via SELECT + `.all()` + set comprehension. Simpler: two `session.get(SettingsRecord, key)` calls (since there are only two known keys). Less code, no list materialization. Not load-bearing — purely a clarity nit.

**Fix:** Replace the select+set with per-key `if session.get(SettingsRecord, key) is None: session.add(...)`.

### IN-04: `_finding_view_model` uses inner `class` and `__slots__` for a one-shot wrapper

**File:** `src/ccguard/server/web/routes.py:190-218`
**Issue:** An inner class is constructed on every call. A module-level `dataclass` (or even a `SimpleNamespace`) would be cheaper, more testable, and clearer. The `__slots__` micro-optimization saves <1KB across 200 findings — not worth the indirection.

**Fix:** Promote to a module-level `@dataclass(slots=True)` named `_FindingVM`.

### IN-05: `LLMClient` constructs `AsyncAnthropic` eagerly in lifespan with broad exception swallow

**File:** `src/ccguard/server/main.py:50-60`
**Issue:** `LLMClient(api_key=...)` does not perform I/O at construction time, so the broad `except Exception` catch is defensive against an SDK version that *might* validate the key. If it ever does start raising (e.g., empty key, invalid format), the only signal is a logged exception and a silently disabled scanner — the operator never gets a startup failure. Consider explicit `if not cfg.anthropic_api_key.startswith("sk-ant-"): logger.warning(...)` to surface obviously-bad keys early.

**Fix:** Add a startup-time key-shape sanity check; keep the try/except as last-resort.

---

_Reviewed: 2026-05-26_
_Re-reviewed: 2026-05-26 (iteration 2)_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
