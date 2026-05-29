# Phase 5 — UI Review

**Audited:** 2026-05-27
**Baseline:** 05-UI-SPEC.md (locked Russian copy + reused Phase 1-4 tokens)
**Screenshots:** not captured (no dev server detected on :3000/:8000)
**Audit mode:** code-only review of Jinja partial + parent template against spec

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 2/4 | Locked verbatim copy violated: `timeout_ms (50–200; при таймауте — fail-open)` instead of spec-locked `timeout_ms (50–10000; при таймауте — fail-open)` |
| 2. Visuals | 4/4 | Markup matches spec template structure 1:1 (8th `<details open>` card after `_policy_section_env.html`, sticky bar preserved) |
| 3. Color | 4/4 | All classes from Phase 1-4 palette (`bg-white`, `text-slate-400/500/700`, `text-red-600`, `border-slate-200/300`); no new tokens; no hardcoded hex |
| 4. Typography | 4/4 | Three sizes (24px page heading via parent, `text-sm`=14, `text-xs`=12) and two weights (400, 600) — within contract |
| 5. Spacing | 4/4 | Spec scale only (`p-4`, `space-y-4`, `space-y-2`, `mt-1`, `mt-3`, `mt-4`, `mb-3`, `gap-2`, `p-3`, `px-2`, `py-1`, `min-h-[120px]`); single arbitrary value `min-h-[120px]` is spec-authorised |
| 6. Experience Design | 2/4 | Numeric `<input>` constraints `min=50 max=200 step=10` and default `150` contradict spec `min=50 max=10000 step=50` default `500` — admin cannot enter spec-legal values like `500` or `5000` without browser validation rejection |

**Overall: 20/24**

---

## Top 3 Priority Fixes

1. **BLOCKER — LlamaGuard timeout copy violation** (`_policy_section_prompt_injection.html:73`) — Spec §"Copywriting Contract" locks the label verbatim as `timeout_ms (50–10000; при таймауте — fail-open)`. Implementation ships `timeout_ms (50–200; при таймауте — fail-open)`. Locked Russian copy is a hard requirement — this is a verbatim-bytes violation. **Fix:** change the `<span>` text to the spec-locked string exactly.

2. **BLOCKER — LlamaGuard timeout input range diverged from spec** (`_policy_section_prompt_injection.html:74-78`) — Spec §"Interaction & State" / §"Default (no draft, never configured)" mandates `min=50 max=10000 step=50` with default `500`. Implementation: `min="50" max="200" step="10"` default `150`. This breaks the server-side validation contract (`timeout_ms ∈ [50, 10000]`) — server accepts 5000 but browser-native validation will reject it; first-load default differs from the documented `500`. **Fix:** set `min="50" max="10000" step="50"` and `| default(500)`.

3. **WARNING — Severity dropdown lacks default selection guard** (`_policy_section_prompt_injection.html:21-27`) — When `policy.prompt_injection.severity` is absent or unexpected value, no `<option>` carries `selected`, so the browser silently picks `info` (first option). Spec mandates `warn` as default in the "no draft, never configured" state. **Fix:** add `{% if not policy.prompt_injection.severity %}` fallback or ensure `policy.prompt_injection.severity` always populated to `warn` by parent context before render.

---

## Detailed Findings

### Pillar 1: Copywriting (2/4)

Verbatim-Russian copy is a HARD requirement per audit instruction. Strings audited against spec §"Copywriting Contract" table-by-table:

| Locked string | File:line | Status |
|---|---|---|
| `Prompt-Injection` (`<summary>`) | `_policy_section_prompt_injection.html:2` | PASS |
| `Включить детекцию prompt-injection` | line 15 | PASS |
| `severity (действие при срабатывании)` | line 20 | PASS |
| `info — только в /findings` | line 24 | PASS |
| `warn — разрешить, но залогировать` | line 25 | PASS |
| `block — запретить вызов` | line 26 | PASS |
| `regex_patterns (по одному паттерну на строку, добавляются к встроенному набору)` | line 32 | PASS |
| `Пусто — используется встроенный набор паттернов.` / `Пользовательские паттерны добавляются к встроенному набору.` | line 38 | PASS |
| `allowlist_patterns (по одному на строку; матч → finding не создаётся)` | line 44 | PASS |
| `Пусто — allowlist отключён.` / `Проверяется до regex-детекции.` | line 49 | PASS |
| `LlamaGuard (опционально)` (`<legend>`) | line 55 | PASS |
| `Включить LlamaGuard (deep-scan через локальный Ollama)` | line 61 | PASS |
| `endpoint (URL Ollama API)` | line 65 | PASS |
| **`timeout_ms (50–10000; при таймауте — fail-open)`** | line 73 — ships `(50–200; при таймауте — fail-open)` | **FAIL — verbatim violation** |
| `Опционально — deep-scan через локальный Ollama. По умолчанию выключен. При недоступности — fail-open, tool-call разрешается.` | line 82 | PASS |

Score 2/4: one verbatim violation in a "locked" string. Per audit charter, locked-copy violation is a BLOCKER regardless of how minor the byte diff looks.

### Pillar 2: Visuals (4/4)

- `<details open>` card matches spec template at `_policy_section_prompt_injection.html:1` ✓
- 8th card placed after `_policy_section_env.html` at `policy_editor.html:22` — matches spec File-Level Inventory ✓
- Sticky bottom action bar preserved at `policy_editor.html:24-30` ✓
- LlamaGuard nested in `<fieldset>` with `<legend>` per spec §"Card layout (top-to-bottom)" #6 ✓
- Error notice slot at `_policy_section_prompt_injection.html:4-6` matches spec §"Validation error path" ✓
- `{% if errors is defined and errors.prompt_injection %}` guard (line 4) prevents AttributeError on GET — solid defensive rendering ✓

### Pillar 3: Color (4/4)

Audit of CSS classes in partial — all from approved palette:
- `bg-white` (card), `text-red-600` (error), `text-slate-400` (muted hints), `text-slate-500` (field labels), `text-slate-700` (legend), `border-slate-200` (fieldset), `border-slate-300` (inputs), `focus:ring-slate-400`, `focus:ring-slate-500`, `focus:border-slate-500` ✓
- No hardcoded `#...` hex values in partial ✓
- No `bg-primary` / `text-primary` (project does not use that token system) ✓
- Accent color (`bg-slate-900 text-white` Save button + `bg-emerald-700` Publish) lives in parent `policy_editor.html:25-29`, unchanged — accent reserved correctly ✓

### Pillar 4: Typography (4/4)

Sizes used inside partial:
- `text-sm` (14px) — body, labels, legend, error notice, mono inputs
- `text-xs` (12px) — field-name annotations + helper hints
- `text-2xl` (page heading) inherited from parent

Weights:
- `font-semibold` (600) — `<summary>` + `<legend>`
- default (400) — everything else

`font-mono` correctly applied to regex textareas, allowlist textarea, endpoint URL, timeout numeric per spec §Typography table. Within the 3-size / 2-weight contract.

### Pillar 5: Spacing (4/4)

Spacing classes used:
- `p-4` card padding, `p-3` fieldset, `px-2 py-1` select, `px-1` legend
- `mt-1`, `mt-3`, `mt-4`, `mb-3` (helper + error notice margins)
- `space-y-4` (rows), `space-y-2` (fieldset children)
- `gap-2` (toggle ↔ label)
- `min-h-[120px]` — single arbitrary value, explicitly allowed by spec §"Exceptions"
- `w-full`, `w-48`, `w-32` — widths from spec template

All values map to spec spacing scale tokens. No rogue padding values.

### Pillar 6: Experience Design (2/4)

State coverage:
- Error state (validation) ✓ — `errors.prompt_injection` red notice with preserved values
- Loading state ✓ — server-rendered, no spinner needed per spec
- Empty state ✓ — helper text swap (`Пусто — …` / `Пользовательские…`)
- Defaults on first-load ✗ — endpoint default `http://localhost:11434` ✓, but timeout default `150` instead of spec-mandated `500`; severity default not guarded (browser selects `info` first option if value missing — should be `warn`)
- Focus states ✓ — `focus:ring-2 focus:ring-slate-400 focus:border-slate-500` on inputs, `focus:ring-2 focus:ring-slate-500` on checkboxes
- Form CSRF token ✓ — present in parent
- Confirm dialog ✓ — publish button retains `confirm('Опубликовать черновик на все машины?')`
- Tab order ✓ — natural document order matches spec

Score 2/4 driven by:
- Hard input constraint `max="200"` blocks any value above 200 at the browser level, so an admin cannot type the spec-documented `500` ms default, let alone the upper bound `10000` — server validation logic at `policy_form.py` reportedly accepts `[50, 10000]` per 05-05-SUMMARY.md; HTML and parser disagree.
- Severity dropdown lacks fallback `selected` when value absent.

---

## Registry Safety

Registry audit: not applicable. `components.json` does not exist in this project (per UI-SPEC §"Registry Safety" — "shadcn is not applicable"). No third-party blocks installed; zero supply-chain surface.

---

## Files Audited

- `/Users/timderbak/dev/ccguard/.planning/phase-05-prompt-injection/05-CONTEXT.md`
- `/Users/timderbak/dev/ccguard/.planning/phase-05-prompt-injection/05-UI-SPEC.md`
- `/Users/timderbak/dev/ccguard/.planning/phase-05-prompt-injection/05-05-SUMMARY.md`
- `/Users/timderbak/dev/ccguard/src/ccguard/server/web/templates/components/_policy_section_prompt_injection.html`
- `/Users/timderbak/dev/ccguard/src/ccguard/server/web/templates/policy_editor.html`
