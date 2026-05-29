---
phase: 03-llm-content-scanner
verified: 2026-05-26T06:11:30Z
status: human_needed
score: 5/5 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Open /findings in browser, verify 'Риск' and 'Действия' columns render with badge colors (emerald/amber/red) per UI-SPEC and the per-row 'Пересканировать' button appears only on llm.scan.* rows"
    expected: "Columns visible after 'Серьёзность', badge color matches risk_score band (0-29 emerald-600, 30-70 amber-600, 71-100 red-600), em-dash on non-LLM rows"
    why_human: "Visual rendering, Tailwind color appearance, HTMX confirm dialog UX"
  - test: "Open /settings, verify 'LLM-сканер' section: toggle, daily_call_budget input, live HTMX usage counter (30s poll), last-10-scans list, 'Пересканировать всё' button with confirm dialog"
    expected: "Russian copy matches UI-SPEC byte-for-byte; usage strip auto-refreshes; toggle persists after POST; budget validation message appears for out-of-range values"
    why_human: "Visual layout, HTMX polling behavior, Russian copywriting fidelity, confirm() UX"
  - test: "Trigger per-row Re-scan button on an llm.scan.* finding, confirm dialog appears, row swaps via HTMX outerHTML"
    expected: "Confirm: 'Пересканировать этот файл? Списание из дневного бюджета.'; row replaced in-place; budget-exhausted/disabled inline notices render correctly"
    why_human: "HTMX swap behavior, dialog UX, inline notice rendering"
  - test: "End-to-end with REAL Anthropic API (ANTHROPIC_API_KEY set, scanner enabled): agent inventory cycle picks up ~/.claude/agents/*.md + ~/.claude/skills/*/SKILL.md, masks secrets, POSTs /scan-content, scan persists, finding appears in /findings"
    expected: "Real Anthropic call returns valid tool_use; ScanResult row created; Finding visible in UI; daily counter increments"
    why_human: "External Anthropic API integration; test suite mocks the SDK so real network behavior is unverified"
---

# Phase 3: LLM Content Scanner — Verification Report

**Phase Goal:** Сканировать agents/skills через Anthropic API на jailbreak/prompt-injection с кэшем по hash.
**Verified:** 2026-05-26T06:11:30Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Агент шлёт content `~/.claude/agents/*.md` и `~/.claude/skills/*/SKILL.md` если scanner вкл и ANTHROPIC_API_KEY задан | ✓ VERIFIED | `src/ccguard/agent/inventory_scan.py:62 collect_scannable_files()` walks both paths; `send_scan_batch()` calls GET /api/v1/scanner-config first (line 163) and short-circuits if `enabled=false`; CLI hook `agent/cli.py:156` imports `run_scan_cycle`; server gates `enabled = Settings.llm_scanner_enabled AND ServerConfig.llm_enabled_at_startup` |
| 2 | Сервер вызывает Anthropic API → risk_score (0-100) + категория в ScanResult | ✓ VERIFIED | `LLMClient` (`services/llm_client.py:206`) uses `anthropic.AsyncAnthropic` with `report_risk` tool (strict=true), enum exactly `jailbreak|prompt-injection-template|data-exfil|privilege-escalation|benign`; `ScanService.scan_file` UPSERTs `ScanResult` row with risk_score, category, rationale, scanned_at, model, ttl_expires_at |
| 3 | Cache по file_hash (TTL 30d); manual Re-scan кнопка | ✓ VERIFIED | `ScanResult.file_hash` is UNIQUE; `scan_file` returns cached row when `ttl_expires_at > utcnow`; `rescan_file` sets `ttl_expires_at = utcnow - 1s`; POST `/admin/scan/{file_hash}/rescan` (`routes.py:605`) and POST `/admin/scan/rescan-all` (`routes.py:688`) wired; scheduler.enqueue_rescan_all + rescan_all_files implemented (`scheduler.py:103,124`) |
| 4 | Settings UI: toggle, daily_call_budget, счётчик, список последних N | ✓ VERIFIED | `templates/settings.html:71` "LLM-сканер" section; POST `/admin/llm-settings` (`routes.py:571`) with validation message "Бюджет должен быть целым числом от 0 до 10000." (`routes.py:593`); GET `/_partials/settings/llm-usage` (`routes.py:708`) HTMX-polled every 30s; `_llm_usage_counter.html` renders "Использовано: X/Y calls" |
| 5 | Тесты: mock Anthropic, cache hit/miss, budget exhaustion, UI rendering | ✓ VERIFIED | 18 new test files exist (test_llm_client, test_scan_service, test_scan_models, test_severity_critical, test_scan_endpoint, test_scan_service_flow, test_llm_admin_routes, test_findings_ui_extension, test_llm_phase_e2e, test_severity_critical_badge, test_agent_masking_regression, test_llm_phase_regression, test_agent_scan_payload, plus scan_runner/hooks/mcp/skills/settings); full suite `pytest tests/ --ignore=tests/e2e` → **545 passed** |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/ccguard/schemas/finding.py` | Severity Literal includes 'critical' | ✓ VERIFIED | `Severity = Literal["info", "warn", "block", "critical"]` |
| `src/ccguard/server/db/models.py` | ScanResult + LLMCallLog tables | ✓ VERIFIED | Both classes present with `table=True` |
| `src/ccguard/server/services/llm_client.py` | LLMClient + ScanOutcome + cost formula | ✓ VERIFIED | MODEL=`claude-haiku-4-5-20251001`, INPUT_CENTS_PER_MTOK=100, OUTPUT_CENTS_PER_MTOK=500 (D-06) |
| `src/ccguard/server/services/scan_service.py` | scan_file/rescan_file/get_daily_usage with asyncio.Lock, budget gate, severity mapping | ✓ VERIFIED | `BudgetExhaustedError`, `ScannerDisabledError`, `_severity_from_score`, `RULE_ID_PREFIX="llm.scan."` all present |
| `src/ccguard/schemas/scan.py` | ScanRequest/ScanResponseItem/ScannerConfig with schema_version | ✓ VERIFIED | All four schemas with `schema_version=1`, items max_length=50 |
| `src/ccguard/server/api/scan.py` | POST /scan-content, GET /scanner-config | ✓ VERIFIED | Both endpoints, agent-auth dep, size-cap handling, per-item error mapping |
| `src/ccguard/agent/masking.py` | mask_secrets(text) | ✓ VERIFIED | Module exports mask_secrets; uses [REDACTED:type] replacement |
| `src/ccguard/agent/inventory_scan.py` | collect+mask+send pipeline | ✓ VERIFIED | `collect_scannable_files`, `send_scan_batch`, `run_scan_cycle` |
| `src/ccguard/server/web/templates/components/_risk_badge.html` | reusable risk pill | ✓ VERIFIED | File exists in components/ |
| `src/ccguard/server/web/templates/components/_finding_row.html` | single-tr partial with hx-swap=outerHTML | ✓ VERIFIED | Contains "Пересканировать этот файл? Списание из дневного бюджета." verbatim |
| `src/ccguard/server/web/templates/components/_llm_usage_counter.html` | usage strip partial | ✓ VERIFIED | "Использовано:" copy present |
| `src/ccguard/server/web/templates/settings.html` | LLM-сканер section appended | ✓ VERIFIED | Section header at line 71; validation_error block at line 79 |
| `src/ccguard/server/scheduler.py` | rescan_all_files + enqueue_rescan_all | ✓ VERIFIED | Both functions at lines 103/124 |

### Key Link Verification

| From | To | Via | Status |
|------|-----|-----|--------|
| `scan_service.scan_file` | LLMClient.scan_content | `async with self._lock` + budget gate | ✓ WIRED |
| `scan_service.scan_file` | Finding emit | `risk_score >= 30` → `llm.scan.{category}` | ✓ WIRED |
| `api/scan.py` POST /scan-content | scan_service.scan_file | FastAPI dep + per-item error mapping | ✓ WIRED |
| `agent/inventory_scan.py` | POST /api/v1/scan-content | X-CCGuard-Token + httpx.Client + JSON body | ✓ WIRED |
| `agent/inventory_scan.py` | mask_secrets | called before base64 encode | ✓ WIRED |
| `agent/cli.py` | inventory_scan.run_scan_cycle | import + call after inventory POST | ✓ WIRED |
| `_finding_row.html` re-scan form | POST /admin/scan/{file_hash}/rescan | hx-post + hx-target='closest tr' + hx-swap='outerHTML' | ✓ WIRED |
| `settings.html` usage strip | GET /_partials/settings/llm-usage | hx-trigger='every 30s' | ✓ WIRED |
| POST /admin/scan/rescan-all | APScheduler one-shot | `enqueue_rescan_all(scheduler, engine)` | ✓ WIRED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full test suite passes | `pytest tests/ --ignore=tests/e2e --deselect <audit smoke>` | 545 passed, 1 deselected | ✓ PASS |
| Severity 'critical' added | grep Severity Literal | `Literal["info", "warn", "block", "critical"]` | ✓ PASS |
| Haiku 4.5 pricing locked | grep INPUT_CENTS_PER_MTOK | 100 (D-06) | ✓ PASS |
| anthropic dep declared | grep pyproject.toml | `anthropic>=0.40,<1` | ✓ PASS |
| Russian copy verbatim | grep _finding_row.html | "Пересканировать этот файл? Списание из дневного бюджета." | ✓ PASS |

### Requirements Coverage

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| LLM-01 | Content-scanner для agents/skills через Anthropic API | ✓ SATISFIED | inventory_scan + LLMClient + ANTHROPIC_API_KEY plumbed via ServerConfig |
| LLM-02 | Risk score 0-100 + 5 категории | ✓ SATISFIED | `report_risk` tool input_schema enforces enum + 0..100 range; LLMClient validates & coerces |
| LLM-03 | Cache по file_hash TTL 30 дней + re-scan UI | ✓ SATISFIED | ScanResult.file_hash UNIQUE; ttl_expires_at; per-row + rescan-all routes; scheduler hook |
| LLM-04 | Settings UI: toggle, budget, счётчик, последние N | ✓ SATISFIED | settings.html LLM-сканер section + /admin/llm-settings + /_partials/settings/llm-usage |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none flagged in scoped review of modified files) | - | - | - | - |

### Human Verification Required

See frontmatter `human_verification` block. Four items:
1. Visual `/findings` columns + badge colors + per-row re-scan button.
2. Visual `/settings` LLM-сканер section + HTMX 30s poll + Russian copy fidelity.
3. HTMX per-row re-scan dialog + outerHTML swap + inline notices.
4. Real Anthropic API end-to-end (tests mock the SDK; live API integration is unverified by automated checks).

### Gaps Summary

No automated gaps. All 5 ROADMAP success criteria verified in code with 545/545 tests green and full vertical wiring (agent → API → service → DB → UI). Phase passes goal-backward verification with the caveat that visual UI rendering, HTMX dynamic behavior, and live Anthropic API call must be confirmed by human spot-check before declaring the phase complete in production.

---

_Verified: 2026-05-26T06:11:30Z_
_Verifier: Claude (gsd-verifier)_
