---
phase: 05-prompt-injection
plan: 05
subsystem: server-web
tags: [ui, jinja, policy-editor, validation, redos, prompt-injection]
requires: [05-01]
provides: [PI-04-ui, prompt-injection-form-parser]
affects: [/policy GET, POST /policy/draft]
tech_stack_added: []
tech_stack_patterns:
  - structural-regex-redos-detection
  - wall-clock-bounded-redos-probe
  - locked-russian-error-copy
key_files:
  created:
    - src/ccguard/server/web/templates/components/_policy_section_prompt_injection.html
    - tests/integration/test_policy_editor_pi_render.py
    - tests/integration/test_policy_form_pi.py
  modified:
    - src/ccguard/server/web/templates/policy_editor.html
    - src/ccguard/server/web/policy_form.py
    - src/ccguard/server/web/routes.py
decisions:
  - "Test files go under tests/integration/ (not tests/server/) per existing repo layout — plan said tests/server/test_*.py but that directory does not exist."
  - "Probe-only ReDoS detection is insufficient under CPython 3.14: (.*)+ and (a+)+ are not catastrophic on plain a*1000 input. Layered with a structural detector (nested unbounded quantifiers) + adversarial probe input ('a'*30+'!') for failure-path backtracking."
  - "{% if errors is defined %} guard in the new partial so GET /policy works even without an errors dict in context — keeps the GET handler from needing a separate context shape per render path."
metrics:
  duration_minutes: 22
  completed_date: 2026-05-26
  task_count: 2
  files_touched: 6
  new_tests: 22
  commits: 4
---

# Phase 5 Plan 05: Prompt-Injection Editor Card Summary

8-я карточка «Prompt-Injection» добавлена в основной `/policy` редактор (вкладка «Правила») с полной server-side валидацией regex (структурный ReDoS-детектор + adversarial-probe), URL и timeout. Russian copy verbatim из 05-UI-SPEC.

## What Built

- **`components/_policy_section_prompt_injection.html`** — новый Jinja-partial: 8-я `<details open>` карточка с enabled-чекбоксом, severity-dropdown'ом (info/warn/block с расширенными подписями), regex_patterns + allowlist_patterns textarea'ами (с динамическими helper'ами «Пусто — …» / «Пользовательские паттерны…»), и LlamaGuard `<fieldset>` (enabled + endpoint + timeout). Strings verbatim per UI-SPEC §"Copywriting Contract".
- **`policy_editor.html`** — добавлен `{% include ... %}` после `_policy_section_env.html` (8-й и последний section перед sticky action bar). `/policy/mandatory` использует отдельный шаблон и не затронут.
- **`policy_form.py`:**
  - `PromptInjectionFormError` (analog of `MandatorySectionError`) с locked Russian copy.
  - `_is_valid_url`, `_redos_safe`, `_parse_prompt_injection` helpers.
  - `_REDOS_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")` — структурный детектор `(X+|X*)+|*` (отлавливает `(.*)+`, `(.+)+`, `(a+)+`).
  - Adversarial probe: `re.search` на `'a'*30+'!'` (вход с trailing literal, форсирующий backtracking failure path для `^(a+)+$`-семейства), wall-clock budget 50 ms через `ThreadPoolExecutor + future.result(timeout=…)`.
  - `_parse_prompt_injection` валидирует: каждый паттерн через `re.compile` + ReDoS check; `re:`-prefix паттерны в allowlist; severity enum; URL endpoint (только если LG enabled); timeout_ms ∈ [50, 10000] + integer.
  - `form_to_yaml` rules-tab branch теперь pop'нет старую `prompt_injection` секцию из baseline и применит свежую из формы (с дефолтами при отсутствии полей — backward-compat).
- **`routes.py`:**
  - `_render_rules_page` helper — DRY между GET `/policy` и error-re-render path; принимает опциональные `errors` и `policy_override`.
  - `_policy_with_pi_form_overrides` — строит `Policy` с overlay'ем admin-submitted PI значений (включая bad regex), чтобы textarea показывала точный ввод при re-render.
  - `policy_editor` GET теперь thin wrapper над `_render_rules_page`.
  - `save_policy_draft` ловит `PromptInjectionFormError` → 200 re-render `/policy` с error notice + preserved form values (вместо 303 redirect).

## Tasks Completed

| Task | Name | Commits |
|------|------|---------|
| 1 | Section card partial + include + 8 render tests | `72278eb` (RED), `a023a2a` (GREEN) |
| 2 | Form parser + validation + route wiring + 14 form tests | `0187898` (RED), `07d6bf9` (GREEN) |

## Test Results

- Новые: `tests/integration/test_policy_editor_pi_render.py` (8 tests) + `tests/integration/test_policy_form_pi.py` (14 tests) = **22 new tests, all green**.
- Существующий unit+integration suite: 704/704 passed (baseline 673 + 22 new + concurrent-plan additions). 0 регрессий.
- e2e: 5 pre-existing failures (test_end_to_end, test_web_e2e) — НЕ caused by этим планом (baseline уже сломан).

## Validation Coverage

| Trigger | Russian error copy | Status |
|---------|--------------------|--------|
| Invalid regex `re.compile` raises | `Невалидный regex в строке {N}: «{pat}». Исправьте и сохраните снова.` | ✓ |
| Structural ReDoS pattern `(X+|X*)+|*` | same as above | ✓ |
| Adversarial probe timeout (50 ms) | same as above | ✓ |
| Invalid `re:`-prefix in allowlist | `Невалидный regex в allowlist, строка {N}: «{pat}».` | ✓ |
| Bad LlamaGuard endpoint URL (LG enabled) | `Endpoint LlamaGuard должен быть валидным URL (http:// или https://).` | ✓ |
| Bad endpoint when LG disabled | (no error — validation skipped per UI-SPEC) | ✓ |
| `timeout_ms` < 50, > 10000, or non-int | `timeout_ms должен быть в диапазоне 50–10000 мс.` | ✓ |
| Severity not in enum | `severity должен быть одним из: info, warn, block.` | ✓ |
| Backward-compat: missing PI fields | defaults applied via `_parse_prompt_injection({})` (enabled=False from HTML semantics, severity=warn) | ✓ |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Probe-only ReDoS detection insufficient under CPython 3.14**
- **Found during:** Task 2 GREEN gate
- **Issue:** Plan said adversarial probe input `'a'*1000` would reject `(.*)+` and `^(a+)+$`. In CPython 3.14 `re`, `(.*)+ ` is fast on `'a'*1000` (`.*` consumes everything in one step), and `^(a+)+$` is fast on plain `'a'*1000` (it matches). The plan's test for `(.*)+` thus passes the probe even though it is ReDoS-risky on adversarial input.
- **Fix:** Added a structural detector `_REDOS_NESTED_QUANTIFIER_RE` that refuses any pattern containing `(...[+*]...)[+*]` (nested unbounded quantifiers — the textbook ReDoS family). Changed probe input from `'a'*1000` to `'a'*30+'!'` so trailing literal forces backtracking failure path for `^(a+)+$` and friends. Result: both `(.*)+` and `^(a+)+$` are now rejected.
- **Files modified:** `src/ccguard/server/web/policy_form.py`
- **Commit:** `07d6bf9`

**2. [Rule 3 - Blocking] Test directory `tests/server/` does not exist**
- **Found during:** Task 1 RED gate planning
- **Issue:** Plan called for `tests/server/test_policy_editor_pi_render.py` and `tests/server/test_policy_form_pi.py`. The repo uses `tests/unit/` and `tests/integration/` (per existing test layout — `tests/unit/test_policy_form.py`, `tests/integration/test_policy_mandatory_routes.py`).
- **Fix:** Both new test files placed under `tests/integration/` (they need the FastAPI TestClient + DB + auth fixtures, which is integration-test scope per the existing convention).
- **No code-impact** — only file-location decision.

### Architectural / Out-of-scope

None. All work confined to:
- `src/ccguard/server/web/templates/policy_editor.html` (+1 include line)
- `src/ccguard/server/web/templates/components/_policy_section_prompt_injection.html` (new)
- `src/ccguard/server/web/policy_form.py` (PI parser + helpers + form_to_yaml branch)
- `src/ccguard/server/web/routes.py` (`_render_rules_page` + error-path handler)
- `tests/integration/test_policy_form_pi.py` (new)
- `tests/integration/test_policy_editor_pi_render.py` (new)

Disjoint from plans 05-02 (scanner engine) and 05-04 (agent integration) as required.

## Authentication Gates

None encountered — all execution autonomous.

## Known Stubs

None. The card wires to the existing `PromptInjectionConfig` schema from plan 05-01; the form parser produces a complete dict that `Policy.model_validate` validates.

## Threat Flags

None — surface introduced (POST /policy/draft accepting admin regex) is already in the plan's `<threat_model>` and mitigated as designed (T-05-05-01 publish-time probe + structural detector).

## TDD Gate Compliance

All four required commits present in order:

```
72278eb test(05-05): add failing render tests for Prompt-Injection card
a023a2a feat(05-05): add Prompt-Injection section card to /policy editor
0187898 test(05-05): add failing tests for prompt_injection form parser
07d6bf9 feat(05-05): parse + validate prompt_injection form section
```

RED → GREEN sequence verified for both tasks.

## Self-Check: PASSED

- FOUND: src/ccguard/server/web/templates/components/_policy_section_prompt_injection.html
- FOUND: src/ccguard/server/web/templates/policy_editor.html (modified)
- FOUND: src/ccguard/server/web/policy_form.py (modified)
- FOUND: src/ccguard/server/web/routes.py (modified)
- FOUND: tests/integration/test_policy_editor_pi_render.py
- FOUND: tests/integration/test_policy_form_pi.py
- FOUND: commit 72278eb
- FOUND: commit a023a2a
- FOUND: commit 0187898
- FOUND: commit 07d6bf9
