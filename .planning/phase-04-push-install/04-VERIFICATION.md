---
phase: 04-push-install
verified: 2026-05-26T00:00:00Z
status: human_needed
score: 5/5 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Open /policy in browser, confirm «Обязательные» tab is visible in tab strip; click it and verify 4 collapsible section cards render (required_mcp_servers, required_skills, required_agents, managed_claude_md_blocks) with Russian locked copy"
    expected: "Tab strip shows 'Обязательные' link active when on /policy/mandatory; 4 section cards visible with editable rows; '+ Добавить' row buttons functional via HTMX"
    why_human: "Visual rendering, HTMX interactivity, and Russian copy accuracy can only be confirmed in a real browser"
  - test: "On /policy/mandatory add a row to each section, fill fields, click Publish; reload and confirm values persisted and re-displayed"
    expected: "Submitted data persists; round-trip via GET /api/v1/policy returns the new required_* arrays with _managed_by: 'ccguard' on MCP entries"
    why_human: "UI CRUD end-to-end requires interactive form submission and visual confirmation per SC#5"
  - test: "Visit /audit and switch event_source filter to «События политики»; trigger an agent sync that produces a policy_apply event, then verify the row renders with success/rollback pill"
    expected: "Filter dropdown shows 'События политики' option; selecting it switches to 5-column PolicyApplyEvent table with green (success) or red (rollback) pill; timeline card hidden in this branch"
    why_human: "Pill colors, layout swap behavior, and timeline hiding need visual confirmation"
---

# Phase 4: Push-Install Verification Report

**Phase Goal:** Сервер декларирует required MCP/skills/agents/CLAUDE.md, агент применяет с rollback
**Verified:** 2026-05-26
**Status:** human_needed (all codebase truths VERIFIED; UI rendering needs browser confirmation)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | /api/v1/policy раздаёт `required_mcp_servers`/`required_skills`/`required_agents`/`managed_claude_md_blocks` | VERIFIED | `src/ccguard/schemas/policy.py:206-209` defines all 4 fields on `Policy`; `src/ccguard/server/api/policy.py:32` returns `policy.model_dump(mode="json")` — model_dump includes the new fields automatically since they're declared on Policy |
| 2 | Агент создаёт/обновляет файлы в ~/.claude/ (drop-in skills/agents, marker merge CLAUDE.md); ошибки → rollback | VERIFIED | `src/ccguard/agent/push_install.py:272 def apply()`; snapshot/rollback at lines 210-248; marker regex with backref at lines 56-69 (`<!-- ccguard:managed start ID -->` / `end ID`); atomic_write via `src/ccguard/agent/atomic_io.py` |
| 3 | Web UI /policy: «Обязательные» tab с editor'ом | VERIFIED (code) | `routes.py:534 @router.get("/policy/mandatory")` + `/policy/mandatory/_row` HTMX endpoint at line 543; `templates/policy_editor_mandatory.html` exists; tab strip partial `_policy_tab_strip.html` includes 'Обязательные' link. Visual rendering requires human check (see human_verification) |
| 4 | После apply агент шлёт policy.apply.success или policy.apply.rollback | VERIFIED | `agent/sync.py:205 _post_policy_apply_event` posts `event_source: "policy_apply"`; `sync.py:255 _apply_and_report` invokes `push_install_apply` and forwards result; `server/api/audit.py:87` routes to `_handle_policy_apply` (line 146) persisting PolicyApplyEvent rows |
| 5 | Тесты: drop-in skill, CLAUDE.md conflict preserved, rollback on perm error, UI CRUD | VERIFIED | Suite: **637 passed** (target ≥ baseline). Specific files: `tests/unit/test_push_install_marker_merge.py`, `tests/unit/test_push_install_mcp_merge.py`, `tests/unit/test_push_install_rollback.py`, `tests/integration/test_policy_mandatory_routes.py`, `tests/e2e/test_push_install_e2e.py`, `tests/integration/test_audit_policy_apply_endpoint.py`, `tests/unit/test_policy_backward_compat_v01_agent.py` |

**Score:** 5/5 truths verified in codebase

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/ccguard/schemas/policy.py` | 4 new policy sections + Pydantic models | VERIFIED | `RequiredMCPServer`, `RequiredSkill`, `RequiredAgent`, `ManagedClaudeMdBlock` + 4 list fields on Policy |
| `src/ccguard/server/db/models.py` | PolicyApplyEvent SQLModel | VERIFIED | imported by `server/api/audit.py:50` and used in `_handle_policy_apply` |
| `src/ccguard/agent/atomic_io.py` | atomic_write_bytes helper | VERIFIED | imported by `push_install.py:27` |
| `src/ccguard/agent/push_install.py` | apply() with snapshot/rollback/markers | VERIFIED | exported and consumed by `sync.py:32` |
| `src/ccguard/server/web/policy_form.py` | parse_indexed_list helper + mandatory parser | VERIFIED | imported by `routes.py:615` (`MandatorySectionError`) |
| `src/ccguard/server/web/templates/policy_editor_mandatory.html` | Mandatory editor page | VERIFIED | referenced from `routes.py` /policy/mandatory handler |
| `src/ccguard/server/web/templates/components/_audit_policy_apply_table.html` | 5-col table with pill | VERIFIED | rendered when `event_source=policy_apply` |
| `src/ccguard/server/api/audit.py` | event_source discriminator | VERIFIED | `_KNOWN_EVENT_SOURCES = {"tool_use", "policy_apply"}`; legacy path byte-identical |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `agent/cli.py sync` | `push_install.apply` | `_apply_and_report` → `push_install_apply(policy, home=home)` | WIRED | `sync.py:298` |
| `push_install.apply` | filesystem `~/.claude/` | `atomic_write_bytes` + snapshot/restore | WIRED | `push_install.py:244-248` rollback path |
| `agent/sync.py` | `POST /api/v1/audit` | `_post_policy_apply_event` with `event_source: "policy_apply"` | WIRED | `sync.py:216` |
| `POST /api/v1/audit` | `PolicyApplyEvent` table | `_handle_policy_apply` branch | WIRED | `audit.py:87,146` |
| `GET /policy` | `policy_editor_mandatory.html` | tab strip → `/policy/mandatory` route | WIRED | `routes.py:534`; `_policy_tab_strip.html:8` |
| `GET /audit?event_source=policy_apply` | `PolicyApplyEvent` rows | `_policy_apply_events` helper | WIRED | `routes.py:274,309,324` |
| `GET /api/v1/policy` | new Policy sections | `policy.model_dump(mode="json")` | WIRED | new fields are declared on Policy, included automatically |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Real Data | Status |
|----------|--------------|--------|-----------|--------|
| `_audit_policy_apply_table.html` | events list | `_policy_apply_events(session, ...)` SQLModel query | DB-backed | FLOWING |
| `policy_editor_mandatory.html` | section rows | `_policy_to_form_context(policy_obj)` from current Policy draft | DB-backed | FLOWING |
| `/api/v1/policy` response | required_* / managed_claude_md_blocks | `PolicyLoader.load_with_etag` → DB row → Pydantic | DB-backed | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full test suite (sans e2e/audit_smoke) | `.venv/bin/pytest tests/ --ignore=tests/e2e --deselect tests/integration/test_audit_smoke.py::test_audit_1000_events_render_table_and_timeline` | **637 passed, 1 deselected** in 30.06s | PASS |
| Policy schema imports cleanly | implicit via test suite | passes | PASS |

### Probe Execution

No conventional `scripts/*/tests/probe-*.sh` declared in plans; no probes harvested from PLAN/SUMMARY frontmatter. Phase relied on pytest as the verification driver, which executed cleanly.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| PUSH-01 | 04-01, 04-02, 04-06 | Policy расширяется required_* секциями, отдача через /api/v1/policy | SATISFIED | `schemas/policy.py:206-209`; `api/policy.py:32` model_dump |
| PUSH-02 | 04-03, 04-04, 04-06 | Агент применяет required-артефакты к ~/.claude/ с rollback | SATISFIED | `agent/push_install.py:272 apply()` + snapshot/restore; `tests/unit/test_push_install_rollback.py` |
| PUSH-03 | 04-03, 04-04, 04-06 | Marker-блоки `<!-- ccguard:managed start ID -->` merge с пользовательским CLAUDE.md | SATISFIED | `push_install.py:56-69` marker regex with id backref; `tests/unit/test_push_install_marker_merge.py` |
| PUSH-04 | 04-02, 04-06 | Web UI editor + «Обязательные» tab | SATISFIED (code) — needs human visual check | `routes.py:534`; `policy_editor_mandatory.html`; tab strip partial |

### Anti-Patterns Found

No blocker-level anti-patterns detected. Stub patterns scanned via codebase reading; no TBD/FIXME/XXX debt markers found in phase-modified files. Empty list defaults (`default_factory=list`) on Policy fields are intentional (additive optional sections, schema_version=1 backward-compat).

### Human Verification Required

Three UI-rendering items require browser confirmation — see frontmatter `human_verification` block above. Code paths are wired and tested, but visual fidelity (Russian copy, tab activation states, HTMX row addition, pill colors) cannot be verified via grep.

### Gaps Summary

No gaps found. All 5 ROADMAP success criteria have verified codebase evidence. All 4 PUSH requirements are satisfied. Test suite is green (637 passing). The phase is functionally complete pending UI visual confirmation by a human reviewer.

---

_Verified: 2026-05-26_
_Verifier: Claude (gsd-verifier)_
