# Phase 3 — UI Review: LLM Content Scanner

**Audited:** 2026-05-26
**Baseline:** `03-UI-SPEC.md` (Russian copy verbatim locked)
**Screenshots:** not captured (dev server returned 401 — auth-gated admin UI; code-only audit)

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 2/4 | Locked header "Серьёзность" replaced with "Критичность"; un-locked string "бюджет равен 0; задайте лимит на /settings" injected; validation copy proxied through variable |
| 2. Visuals | 2/4 | Spec-mandated "Подробности" column dropped from findings table; column order diverges from contract (Правило before Критичность instead of after Риск) |
| 3. Color | 4/4 | Badge color bands exact (`bg-emerald-600`/`bg-amber-600`/`bg-red-600`); accent (`bg-slate-900`) reserved for the three declared CTAs; no hardcoded hex |
| 4. Typography | 4/4 | Only `text-2xl`, `text-sm`, `text-xs` in use (3 sizes ≤ limit); weights `font-semibold` + default (2) ≤ limit; `font-mono` confined to tokens (rule_id, file_hash, category, score, timestamps) |
| 5. Spacing | 3/4 | New LLM-сканер card uses `mb-4` while sibling settings cards use `mb-6` — visible rhythm break at section boundary; all other tokens (`p-4`, `gap-2`, `gap-3`, `space-y-3`, `mb-3`, `ml-2`, `px-2 py-0.5`) match the declared scale |
| 6. Experience Design | 3/4 | All declared states wired (default, empty, scanner-disabled, budget-exhausted, API-key-missing, validation error); HTMX confirm + outerHTML swap implemented; minor: usage counter goes red when `budget==0` even though no calls were spent (misleading state outside the contract); usage counter has no `aria-live` (spec accepts this) |

**Overall: 18/24**

---

## Top 3 Priority Fixes

1. **Rename `<th>Критичность</th>` → `<th>Серьёзность</th>` in `findings_feed.html:31`** — User-facing header copy is part of the locked contract; the term "Серьёзность" is referenced by ops runbooks and matches the value rendered in each cell (`finding.severity`). One-byte fix.
2. **Restore the dropped "Подробности" column in `findings_feed.html`** — UI-SPEC §"Findings table — extended column layout" explicitly preserves all 5 v0.1 columns and adds only 2 new ones (Риск, Действия). The current `<thead>` has 6 columns; "Подробности" is missing entirely, hiding finding rationale that existed in v0.1. Update `<thead>` to `Когда / Машина / Серьёзность / Риск / Правило / Подробности / Действия`, then add the 7th `<td>` in `_finding_row.html` rendering `finding.details` summary (`text-slate-700 truncate max-w-md`), and update empty-state `colspan="6"` → `colspan="7"`.
3. **Remove or formalize the unlisted "бюджет равен 0; задайте лимит на /settings" notice** in `_finding_row.html:32` — UI-SPEC Copywriting Contract is verbatim-locked; only `бюджет исчерпан` and `сканер выключен` are sanctioned inline notices. Either (a) collapse the `budget_zero` branch into `budget_exhausted` reusing the locked `бюджет исчерпан` string, or (b) escalate the new copy to a UI-SPEC amendment before shipping.

---

## Detailed Findings

### Pillar 1: Copywriting (2/4)

**BLOCKER — locked-string violations:**
- `findings_feed.html:31` — `<th>Критичность</th>` is not the locked header. UI-SPEC §"Findings table" specifies column 3 header `Серьёзность` (the value rendered inside each cell IS `finding.severity` — so the data and header drifted apart).
- `_finding_row.html:32` — new inline notice `"бюджет равен 0; задайте лимит на /settings"` is not in the locked copy table. The Copywriting Contract enumerates exactly two inline notices: `бюджет исчерпан` (amber) and `сканер выключен` (slate). Adding a third string without a contract amendment violates the verbatim-locked rule.

**WARNING — verbatim verification gaps:**
- `settings.html:80` — validation error displayed as `{{ validation_error }}` (server-controlled string). Spec mandates exactly `Бюджет должен быть целым числом от 0 до 10000.` Cannot verify from template alone; route handler must emit the locked bytes. Recommend hard-coding the literal in the template or pinning a test.

**PASS — verified verbatim:**
- "Риск" header (`findings_feed.html:31`) ✓
- "Действия" header (`findings_feed.html:31`) ✓
- "Пересканировать" button label (`_finding_row.html:47`) ✓
- Per-row confirm `Пересканировать этот файл? Списание из дневного бюджета.` (`_finding_row.html:42`) ✓
- Scope options `все типы` / `только LLM-сканер` / `кроме LLM-сканера` (`findings_feed.html:17-19`) ✓
- `LLM-сканер` section heading (`settings.html:71`) ✓
- API-key-missing notice (`settings.html:74-76`) verbatim ✓
- `Включить сканер` toggle label (`settings.html:90`) ✓
- `Дневной бюджет (calls):` budget label (`settings.html:93`) ✓
- `Сохранить` save button (`settings.html:102`) ✓
- Usage counter `Использовано:` / `calls сегодня` / `Сканер выключен.` (`_llm_usage_counter.html:5,7,9`) ✓
- `Последние 10 сканов` sub-heading (`settings.html:112`) ✓
- `Сканов ещё не было.` empty state (`settings.html:131`) ✓
- `Пересканировать всё` global button (`settings.html:139`) ✓
- Global confirm `Пересканировать ВСЕ файлы? Может превысить дневной бюджет.` (`settings.html:135`) ✓
- Inline `бюджет исчерпан` / `сканер выключен` (`_finding_row.html:30, 34`) ✓

### Pillar 2: Visuals (2/4)

**BLOCKER — column inventory drift:**
- `findings_feed.html:30-32` declares 6 `<th>` cells: `Когда / Машина / Правило / Критичность / Риск / Действия`. UI-SPEC mandates 7: `Когда / Машина / Серьёзность / Риск / Правило / Подробности / Действия`. Two divergences:
  1. **"Подробности" column is missing entirely** — finding details/rationale that existed in v0.1 is no longer rendered. Spec §"Findings table — extended column layout" explicitly preserves existing columns verbatim.
  2. **Order swap:** spec puts Серьёзность→Риск adjacent (semantic pairing: numeric risk next to severity), executor puts Правило before Критичность, then Риск. Visual grouping of related fields is broken.
- Empty-state `colspan="6"` (`findings_feed.html:37`) correctly matches the broken 6-column layout but does not match the intended 7-column layout.

**WARNING — visual hierarchy:**
- `_finding_row.html:27` "Риск" cell is `text-center` per spec ✓, but the `Действия` cell uses `text-right` ✓. The risk badge's adjacent category label (`font-mono text-xs text-slate-500`) renders to the right of the badge with `ml-1` ✓.
- All icon-free; severity/risk encoded as text + color (good — not color-only).

### Pillar 3: Color (4/4)

`grep` of color classes confirms exact reuse of Phase 1+2 palette:
- Badge fills: `bg-emerald-600 text-white`, `bg-amber-600 text-white`, `bg-red-600 text-white` (`_risk_badge.html:7-9`, `settings.html:121-123`) — match spec mapping (<30/30-70/>70).
- Accent `bg-slate-900 text-white` reserved for the three declared CTAs: Фильтр (`findings_feed.html:25`), Сохранить (`settings.html:101`), Пересканировать всё (`settings.html:138`). No accent leakage.
- Muted greys `text-slate-400` (em-dash placeholders, empty states), `text-slate-500` (headers, category label, scanner-disabled notice), `text-slate-700` (form labels) all per spec.
- Amber `text-amber-600` confined to budget-exhausted notice + API-key-missing notice + warn severity (existing pattern).
- Red `text-red-600` confined to critical severity + budget-exhausted counter (`_llm_usage_counter.html:8`) + validation error (`settings.html:80`).
- Zero hardcoded hex / `rgb(`. No new tokens introduced.

### Pillar 4: Typography (4/4)

Distinct text-size classes touched by this phase:
- `text-2xl` — page heading (existing) ✓
- `text-sm` — body, table cells, form labels, buttons ✓
- `text-xs` — badge text, inline notices, timestamps in scan list, category label ✓

Three sizes total — matches spec ceiling of three. No `text-lg`/`text-base`/`text-xl` introduced in Phase 3 templates.

Weights: `font-semibold` (badge text, section headings, severity-critical cells) and default `font-normal`. Two weights — within limit. No `font-bold`/`font-medium` introduced.

`font-mono` correctly restricted to opaque tokens: rule_id, score number, category, file_hash usage, timestamps in scan list, budget input field, and the dollar cost. Matches spec usage table.

### Pillar 5: Spacing (3/4)

Class inventory from Phase 3 templates:
- Card padding: `p-4` ✓
- Card margin: `mb-4` (new LLM-сканер) vs `mb-6` (existing settings sections) — **inconsistency at section boundary**. The new card is visually 8px tighter to the next element than its siblings. Spec §"Spacing Scale" lists `md=16px` (mb-4) but the *rendered context* (existing settings cards) uses `mb-6` (24px). Either fix the new card to `mb-6` for visual consistency, or update preceding cards (out of scope) — the simpler fix is `mb-4` → `mb-6` on `settings.html:70`.
- Form internal spacing: `space-y-3`, `gap-2`, `gap-3` — match spec.
- Badge: `px-2 py-0.5` ✓
- Inline notice margin: `ml-2` ✓, category label `ml-1` ✓
- Scan list item: `py-1` border-separated ✓

No arbitrary `[Xpx]` values. No exotic spacing. The single rhythm break (mb-4 vs mb-6) is the only finding.

### Pillar 6: Experience Design (3/4)

**State coverage — verified:**
- Default (data present) — covered.
- Empty findings table — `findings_feed.html:37` `colspan="6"` empty state ✓ (will need colspan bump when "Подробности" restored).
- Empty scans list — `settings.html:131` `Сканов ещё не было.` ✓.
- Scanner disabled — toggle unchecked branch in settings; `_llm_usage_counter.html:4-5` shows `Сканер выключен.` ✓; per-row click returns `сканер выключен` notice ✓.
- Budget exhausted — `_llm_usage_counter.html:8` renders count in `text-red-600 font-semibold` ✓; per-row `бюджет исчерпан` notice ✓.
- API key missing — `settings.html:73-77` amber notice + `disabled` attr on checkbox ✓.
- Validation error — `settings.html:79-81` red notice block above form ✓ (copy delegated to server variable — see Pillar 1).
- Confirmations — HTMX `hx-confirm` on per-row, inline `onsubmit confirm()` on global — both per spec.

**WARNING — extra-contract state:**
- `_finding_row.html:31-32` introduces a third notice branch `rescan_notice == 'budget_zero'` rendering an unlisted string. This is a behavior + copy expansion not in the spec.
- `_llm_usage_counter.html:8`: when `budget == 0` AND `used == 0`, the counter still renders red `0/0` because `used >= budget` is true. This is a false-positive "exhausted" signal for the never-configured-budget case. Recommend guard: `{% if budget > 0 and used >= budget %}`.

**PASS — interaction wiring:**
- `hx-target="closest tr"` + `hx-swap="outerHTML"` ✓ (`_finding_row.html:40-41`).
- CSRF token hidden inputs added to all POST forms (`_finding_row.html:44`, `settings.html:84,136`) — beyond spec but a correct hardening.
- HTMX polling on usage counter `hx-trigger="every 30s"` ✓ (`settings.html:108`).
- No client-side JS beyond HTMX runtime + the one sanctioned inline `confirm()` — matches CSS-only constraint.

---

## Registry Safety

No `components.json` present (`shadcn_initialized: false` in UI-SPEC frontmatter). Phase 3 introduces zero external component blocks. No third-party registries in use. Skipped per spec.

---

## Files Audited

- `/Users/timderbak/dev/ccguard/.planning/phase-03-llm-content-scanner/03-UI-SPEC.md`
- `/Users/timderbak/dev/ccguard/.planning/phase-03-llm-content-scanner/03-CONTEXT.md`
- `/Users/timderbak/dev/ccguard/src/ccguard/server/web/templates/findings_feed.html`
- `/Users/timderbak/dev/ccguard/src/ccguard/server/web/templates/settings.html`
- `/Users/timderbak/dev/ccguard/src/ccguard/server/web/templates/components/_finding_row.html`
- `/Users/timderbak/dev/ccguard/src/ccguard/server/web/templates/components/_risk_badge.html`
- `/Users/timderbak/dev/ccguard/src/ccguard/server/web/templates/components/_llm_usage_counter.html`
