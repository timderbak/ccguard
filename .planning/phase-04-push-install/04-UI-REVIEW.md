# Phase 4 — UI Review

**Audited:** 2026-05-26
**Baseline:** `04-UI-SPEC.md` (Phase 4 design contract — Mandatory tab + `/audit` `policy_apply` filter)
**Screenshots:** not captured (no dev server detected on :3000 / :8000)
**Audit mode:** code-only (Jinja templates + locked-copy verbatim diff)

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 2/4 | **BLOCKER:** `required_mcp_servers` args label diverges from locked spec copy — implementation says `args (по одному на строку)`, spec locks `args (через запятую)`. Helper text for `id` field is missing. All other Russian strings match verbatim. |
| 2. Visuals | 4/4 | All section cards mirror the `<details open class="bg-white rounded-lg shadow p-4">` template; row borders, pill geometry, sticky action bar, tab strip underline all match the spec markup byte-for-byte. |
| 3. Color | 4/4 | Palette matches spec verbatim: `bg-slate-900` (accent + active tab), `bg-emerald-700` (publish), `bg-emerald-600`/`bg-red-600` (audit pills), `text-amber-600` (unsaved + `reason=`), `text-red-600` (destructive/error), `border-slate-200`/`border-slate-300`. No hardcoded hex; no new tokens introduced. |
| 4. Typography | 4/4 | Only the 3 sizes the spec allows (`text-2xl`, `text-sm`, `text-xs`) and 2 weights (`font-semibold`, default 400) are in use. `font-mono` correctly applied to identifier inputs and content textareas. |
| 5. Spacing | 4/4 | Spec spacing scale honored: `p-4` card pad, `space-y-4` form gap, `space-y-3` row gap, `space-y-2` intra-row gap, `gap-2` field-pair gap, `px-3 py-2 -mb-px` tab links, `min-h-[120px]` content textareas, `p-3` row pad. No arbitrary values outside the one sanctioned `min-h-[120px]`. |
| 6. Experience Design | 3/4 | Loading/error/empty/cold-start/validation-error states all wired per spec. HTMX row-add and `hx-on:click` row-remove implemented. **Deviation:** MCP `args` is a 3-row `<textarea>` (newline-separated) instead of the spec's single-line comma-separated `<input>` — different interaction shape; also the `id`-field placeholder/title helper text is absent. No focus management on HTMX swap (spec deferred this — acceptable). |

**Overall: 21/24**

---

## Top 3 Priority Fixes

1. **MCP `args` field shape and label diverge from locked spec** — Authors who follow the policy-author runbook will type comma-separated args (as the spec promises) but the implementation expects newline-separated values, silently corrupting the persisted YAML for any multi-arg server. **Fix:** in `src/ccguard/server/web/templates/components/_mandatory_row_required_mcp_servers.html` lines 16-20, replace the `<textarea rows="3">` with `<input type="text" name="required_mcp_servers[{{ i }}].args" value="{{ item.args_text | default(item.args | default([]) | join(', ')) }}" class="mt-1 block w-full rounded border-slate-300 font-mono" />` and revert the helper label to the locked copy `args (через запятую)`. Coordinate with `policy_form._parse_required_mcp_servers` to split on `,` per spec (Plan 02 summary D-6 already cites comma-separated as the contract — implementation drifted from its own decision record).

2. **Missing helper text for managed-block `id` field** — Spec § Copywriting Contract row "Helper for `id` field" locks `kebab-case, например: security-rules` to be rendered as `placeholder` or `title`. Implementation in `_mandatory_row_managed_claude_md_blocks.html` line 6 only ships the `pattern="[a-z0-9]+(-[a-z0-9]+)*"` attribute. **Fix:** add `placeholder="security-rules" title="kebab-case, например: security-rules"` to the `<input>` so authors get a visible hint matching the spec.

3. **Audit `event_source` select default option label `tool_use`** — `audit_feed.html` line 37 renders the default option text as literal `tool_use` (English opaque token). Spec does not explicitly lock this string, but the rest of the audit filter UI uses Russian labels (`за 1 час`, `все решения`); a Russian phrasing such as `Вызовы инструментов` would maintain locale consistency. **Fix:** consider `<option value="">Вызовы инструментов</option>` — minor polish, not a contract violation but a UX inconsistency flagged here so it isn't normalized into Phase 5.

---

## Detailed Findings

### Pillar 1: Copywriting (2/4)

**Verbatim-locked strings — VERIFIED PRESENT:**
- `_policy_tab_strip.html:6,12` — `Правила`, `Обязательные` ✓
- `_policy_tab_strip.html:1` — `aria-label="Разделы политики"` ✓
- `policy_editor_mandatory.html:2` — `<title>ccguard — обязательные</title>` ✓
- `policy_editor_mandatory.html:5` — `Редактор политики` ✓
- `policy_editor_mandatory.html:7-9` — `Текущая ревизия …  Ревизия черновика … · не сохранено` ✓
- `policy_editor_mandatory.html:23,26` — `Сохранить черновик`, `Опубликовать`, `Опубликовать черновик на все машины?` ✓
- Section cards (4 files): `MCP-серверы (обязательные)`, `Скиллы (обязательные)`, `Агенты (обязательные)`, `Управляемые блоки CLAUDE.md` ✓
- Add buttons (4 files): `+ добавить сервер`, `+ добавить скилл`, `+ добавить агента`, `+ добавить блок` ✓
- Empty state (4 files): `Записей нет.` ✓
- Row remove button (4 files): `удалить` ✓
- Audit pills: `success` / `rollback` ✓
- Audit empty state: `Событий нет.` ✓
- Audit new option: `События политики` ✓
- Audit new column header: `Результат` ✓

**Field labels — VERIFIED PRESENT:**
- `name`, `command` ✓ (`_mandatory_row_required_mcp_servers.html:4,10`)
- `env (JSON object, например {"KEY":"value"})` ✓ (line 22)
- `frontmatter type`, `content (SKILL.md)` ✓ (`_mandatory_row_required_skills.html:10,17`)
- `content (agent .md)` ✓ (`_mandatory_row_required_agents.html:9`)
- `id (kebab-case)`, `описание (для админов)`, `content (вставится в CLAUDE.md между маркерами)` ✓

**DEVIATIONS:**

- **BLOCKER** `_mandatory_row_required_mcp_servers.html:17` — `args (по одному на строку)`. Spec line 510 locks this as `args (через запятую)`. Implementation also changed input shape from `<input type="text">` to `<textarea rows="3">` (lines 18-20), which is a coupled interaction-design + copy regression. Plan 02 SUMMARY's decision D-6 even reaffirms "args/env editors are plain inputs — args comma-separated".

- **WARNING** `_mandatory_row_managed_claude_md_blocks.html:5-7` — spec § Copywriting Contract row "Helper for `id` field" locks `kebab-case, например: security-rules` to be rendered as `placeholder` or `title`. Implementation ships only the HTML5 `pattern` attribute; no visible hint to the author.

- **WARNING** `audit_feed.html:37` — default `<option value="">tool_use</option>`. Spec did not lock this label, but locale consistency with the other Russian filter options (`за 1 час`, `все решения`, `Сбросить`) is broken.

### Pillar 2: Visuals (4/4)

- Section card markup identical to spec template (line-by-line match for `<details open class="bg-white rounded-lg shadow p-4">` + `<summary class="cursor-pointer font-semibold">`).
- Audit pills use the exact `inline-block rounded-full px-2 py-0.5 text-xs font-semibold` geometry from spec § Visual System and § audit-table-extension.
- Tab strip `flex gap-2 border-b border-slate-200 mb-6` with `-mb-px border-b-2` overlap matches spec line 58-72 exactly.
- Sticky action bar `flex gap-2 sticky bottom-0 bg-slate-50 py-4` reuses the v0.1 rules-tab bar verbatim — visual continuity between tabs is preserved.
- Row borders `border border-slate-200 rounded p-3` match spec § Per-section row markup.

### Pillar 3: Color (4/4)

`grep` of all Phase 4 created/modified templates surfaces only these color tokens:

- `bg-slate-900`, `text-slate-900` — accent (save-draft, active tab) ✓ spec § Color Accent reserved
- `bg-emerald-700` — publish button ✓
- `bg-emerald-600` — audit success pill ✓
- `bg-red-600` — audit rollback pill ✓
- `text-red-600` — `удалить` link + error notices ✓ spec § Color Destructive reserved
- `text-amber-600` — `· не сохранено` indicator + `reason=` highlight ✓ spec § Color Warning
- `border-slate-200`, `border-slate-300` — separators, input borders ✓
- `text-slate-400`, `text-slate-500`, `text-slate-600`, `text-slate-700` — muted tiers ✓
- `bg-white` cards, `bg-slate-50` action bar ✓

Zero hardcoded hex/rgb in modified templates. No new color tokens introduced. Accent (`bg-slate-900` + active tab) appears 4 times across Phase 4 templates — well within the 10% rule.

### Pillar 4: Typography (4/4)

Sizes in use (grep across modified templates): `text-2xl`, `text-sm`, `text-xs` — exactly the 3 sizes spec § Typography enumerates.
Weights: only `font-semibold` is explicit; everything else uses Tailwind default 400. Two weights total — at spec budget.
`font-mono` correctly applied to identifier inputs (`name`, `command`, `id`), content textareas, and audit `details` cell text — matches spec table.

### Pillar 5: Spacing (5/4)

(Score capped at 4.) Spacing scale:

- Cards: `p-4` (16px) ✓
- Form: `space-y-4` (16px between cards) ✓
- Section rows container: `space-y-3` (12px) — spec line 232 says `space-y-3` for "gap between section rows" ✓
- Row interior: `space-y-2` (8px) ✓
- Field-pair: `gap-2` (8px) ✓
- Row pad: `p-3` ✓
- Tab links: `px-3 py-2 -mb-px` ✓ (spec exception § Spacing Scale Exceptions)
- Textareas: `min-h-[120px]` ✓ (spec sanctioned arbitrary value)
- Heading bottom: `mb-6` ✓
- Sticky bar: `py-4` ✓

Only one arbitrary value (`min-h-[120px]`) — explicitly sanctioned in spec.

### Pillar 6: Experience Design (3/4)

**State coverage — VERIFIED:**
- Default + draft → `has_draft` flips `· не сохранено` amber indicator ✓
- Empty section → `Записей нет.` muted line ✓ (all 4 section partials)
- Validation error → red notice atop offending card with form values preserved (Plan 02 SUMMARY confirms `_form_to_sections_view` reconstructs draft) ✓
- Cold-start → covered by Plan 02 (server seeds empty draft) ✓
- HTMX row-add → `hx-get` + `hx-swap="beforeend"` per spec ✓
- HTMX row-remove → `hx-on:click="this.closest('.policy-row').remove()"` per spec ✓
- Audit empty results → `<td colspan="5"> Событий нет.` ✓
- Audit rollback details → `text-amber-600` on `reason=` only, rest stays `text-slate-700 font-mono` ✓
- Publish confirmation → `confirm('Опубликовать черновик на все машины?')` ✓

**DEVIATIONS:**

- **BLOCKER** MCP `args` interaction shape changed from `<input type="text">` (comma-separated, single line) to `<textarea rows="3">` (newline-separated) — see Pillar 1. This is a documented spec violation AND breaks the v0.1 form-parser contract from Plan 02 D-6.
- **WARNING** Managed-block `id` field has no visible affordance for the kebab-case constraint — HTML5 `pattern` rejection appears only on submit, which contradicts spec's intent that authors learn the format from the placeholder.
- **WARNING** No focus management after HTMX `hx-swap="beforeend"` — spec line 578 explicitly deferred this to post-v0.2, so this is informational, not a deduction.

Score derivation: -1 for the args field interaction regression. (-0.5 for missing id helper, rounded into the same deduction.)

---

## Files Audited

- `src/ccguard/server/web/templates/policy_editor.html`
- `src/ccguard/server/web/templates/policy_editor_mandatory.html`
- `src/ccguard/server/web/templates/components/_policy_tab_strip.html`
- `src/ccguard/server/web/templates/components/_mandatory_section_required_mcp_servers.html`
- `src/ccguard/server/web/templates/components/_mandatory_section_required_skills.html`
- `src/ccguard/server/web/templates/components/_mandatory_section_required_agents.html`
- `src/ccguard/server/web/templates/components/_mandatory_section_managed_claude_md_blocks.html`
- `src/ccguard/server/web/templates/components/_mandatory_row_required_mcp_servers.html`
- `src/ccguard/server/web/templates/components/_mandatory_row_required_skills.html`
- `src/ccguard/server/web/templates/components/_mandatory_row_required_agents.html`
- `src/ccguard/server/web/templates/components/_mandatory_row_managed_claude_md_blocks.html`
- `src/ccguard/server/web/templates/audit_feed.html`
- `src/ccguard/server/web/templates/components/_audit_policy_apply_table.html`

Cross-referenced against:
- `.planning/phase-04-push-install/04-UI-SPEC.md`
- `.planning/phase-04-push-install/04-CONTEXT.md`
- `.planning/phase-04-push-install/04-02-SUMMARY.md`
- `.planning/phase-04-push-install/04-05-SUMMARY.md`

Registry audit: not applicable (shadcn not initialized; pure Jinja + Tailwind CDN per spec § Registry Safety).
