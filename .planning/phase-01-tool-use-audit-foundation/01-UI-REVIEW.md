---
phase: 1
slug: tool-use-audit-foundation
audited: 2026-05-25
baseline: 01-UI-SPEC.md (locked design contract)
screenshots: not_captured (no dev server running; code-only audit)
overall_score: 23
pillars:
  copywriting: 4
  visuals: 4
  color: 4
  typography: 4
  spacing: 4
  experience_design: 3
blockers: 0
warnings: 2
---

# Phase 1 — UI Review: Tool-Use Audit (Foundation)

**Audited:** 2026-05-25
**Baseline:** `01-UI-SPEC.md` (Jinja2 + HTMX + Tailwind CDN, RU-locked admin UI)
**Screenshots:** Not captured — code-only audit (no dev server detected; this phase is a server-rendered Jinja stack with no React/Storybook to screenshot in isolation).

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 4/4 | Every locked RU string from UI-SPEC §Copywriting matches verbatim — placeholders, options, headings, empty states, tooltip format, ARIA. |
| 2. Visuals | 4/4 | Three-card vertical stack (filter → timeline → table) matches spec; chart has `role="img"` + `aria-label`; per-bar tooltip via native `title`. |
| 3. Color | 4/4 | Accent `bg-slate-900` reserved for Фильтр CTA; bars `bg-slate-700`; decision tri-state colors (emerald/red/amber) match spec; no hardcoded hex. |
| 4. Typography | 4/4 | Two weights (400 / 600) + three sizes (text-2xl heading, text-sm body, text-xs axis labels — spec's own sample uses text-xs); `font-mono` correctly applied to `tool_name` and `fingerprint`. |
| 5. Spacing | 4/4 | Card padding `p-4`, card gap `mb-4`, heading margin `mb-6`, filter `gap-4`, bar `gap-1` (4px), container `h-32`, bar `min-height: 2px` floor — all on-spec. |
| 6. Experience Design | 3/4 | Empty states, filter echo, HTMX polling with `hx-include`, sr-only labels — all present. **Submit button missing explicit focus ring** that UI-SPEC §Accessibility explicitly required. |

**Overall: 23/24**

---

## Top 3 Priority Fixes

1. **Submit button missing explicit focus ring (WARNING)** — UI-SPEC §Accessibility line 316 explicitly requires `focus:outline-none focus:ring-2 focus:ring-slate-500` on the `<button>` "since CDN Tailwind is JIT but defaults may not include focus-visible utilities". The implemented button at `audit_feed.html:34` has only `bg-slate-900 text-white text-sm rounded px-4 py-2` — no focus styling. Keyboard users hitting Tab to the submit button get no visible focus indicator on CDN Tailwind. Add `focus:outline-none focus:ring-2 focus:ring-slate-500` (and consider the same on the "Сбросить" link at line 35).

2. **Decision color `else` branch silently catches unexpected values (WARNING)** — at `_audit_events_table.html:20`, the conditional is `{% if 'allow' %}emerald{% elif 'deny' %}red{% else %}amber{% endif %}`. Spec defines exactly three decisions (`allow` / `deny` / `error`), and the `else` correctly colors `error` amber. **But any future fourth decision value silently inherits the warning color**, hiding data-model drift. Defensive fix: change the `{% else %}` to `{% elif event.decision == 'error' %}` and add an explicit muted `{% else %}` (or render the literal value without color so the drift is visible). Low-impact today, future-proofs the page.

3. **No real screenshot verification possible without dev server (informational)** — this audit could not exercise the page in a browser. Recommend a manual visual pass at three viewports (1440×900, 768×1024, 375×812) before phase sign-off to confirm: (a) filter bar wraps cleanly on narrow widths (it uses `flex-wrap`, additive over the spec), (b) the 24-bar chart remains legible at 375px width, (c) the overflow `<tfoot>` renders correctly at the table's natural width. None of these are spec violations; they are gaps in this audit's evidence base.

---

## Detailed Findings

### Pillar 1: Copywriting (4/4)

UI-SPEC §Copywriting Contract defines a strict RU-string lockdown. Every entry verified against the implementation:

| Lockdown item | File:Line | Match |
|---------------|-----------|-------|
| Sidebar `Аудит` | `base.html:19` | exact |
| Page heading `Аудит` | `audit_feed.html:4` | exact |
| `<title>` `ccguard — аудит` | `audit_feed.html:2` | exact |
| Placeholder `machine_id` | `audit_feed.html:8` | exact (English token kept) |
| Placeholder `tool_name` | `audit_feed.html:13` | exact |
| `decision` default option `все решения` | `audit_feed.html:20` | exact |
| Decision options `allow` / `deny` / `error` | `audit_feed.html:21-23` | exact (English enum) |
| Timeframe options `за 1 час` / `за 24 часа` / `за 7 дней` | `audit_feed.html:29-31` | exact |
| Submit button `Фильтр` | `audit_feed.html:34` | exact |
| Reset link `Сбросить` | `audit_feed.html:35` | exact |
| Timeline heading `Активность за 24 часа` | `_audit_timeline.html:1` | exact |
| Timeline empty `Нет данных за выбранный период.` | `_audit_timeline.html:3` | exact |
| Tooltip `{hour_label} — {N} событий` | `_audit_timeline.html:10` | exact |
| ARIA `Гистограмма аудит-событий по часам` | `_audit_timeline.html:5` | exact |
| Column headers `Когда` / `Машина` / `Инструмент` / `Решение` / `Результат` / `Fingerprint` | `_audit_events_table.html:4-9` | exact |
| Table empty row `Аудит-событий нет.` | `_audit_events_table.html:25` | exact |
| Overflow footer `Показано {N} из {total} событий за период. Сузьте фильтры если нужно больше.` | `_audit_events_table.html:30` | exact |

No generic English copy bled through (`Submit`, `Save`, `No data`, `try again` — zero matches in the audit templates). Per `01-06-SUMMARY.md` there is also an integration test `test_audit_smoke.py` that locks these strings in CI.

### Pillar 2: Visuals (4/4)

- Three-card vertical stack matches UI-SPEC §IA: heading → filter form → timeline card → events table card (`audit_feed.html:4,6,38,45`).
- Each card carries the canonical `bg-white rounded-lg shadow p-4 mb-4` (last card omits `mb-4` — fine, it's the last child).
- Timeline has `role="img"` + `aria-label="Гистограмма аудит-событий по часам"` (`_audit_timeline.html:5`) per spec §Accessibility.
- Per-bar hover tooltip uses native `title` (`_audit_timeline.html:10`) — no JS tooltip library, matches "no new dependencies" constraint in §Performance.
- X-axis labels: only first and last bucket rendered (`_audit_timeline.html:14-15`) — matches "keeps the chart visually quiet" spec rationale.
- Empty-state branch lives **inside** the partial (`_audit_timeline.html:2-4`), so the HTMX 30s swap can transition to/from empty atomically — confirmed by `01-05-SUMMARY.md`.
- Decision color is text-only (no background fills) — matches `findings_feed.html` precedent called out in spec §Color.

### Pillar 3: Color (4/4)

- 60/30/10 split inherited from `base.html`: body `bg-slate-50` (dominant, line 10), cards `bg-white` (secondary), sidebar `bg-slate-900` (accent territory).
- Accent `bg-slate-900` reserved for the Фильтр submit button (`audit_feed.html:34`) — single instance in the audit templates, no other accent leakage.
- Timeline bars use `bg-slate-700` (`_audit_timeline.html:8`) — one shade lighter than accent per spec §Color "Accent reserved for".
- Decision tri-state mapping at `_audit_events_table.html:20`: `allow → text-emerald-600`, `deny → text-red-600`, else → `text-amber-600`. Matches spec table verbatim.
- Borders `border-slate-300` on form inputs (`audit_feed.html:10,15,19,28`) — matches §Color border token.
- Muted slate-400 / slate-500 used only on empty states, table header, timestamps, axis labels — matches spec roles.
- **No hardcoded hex codes** in any audit template (grep confirms zero `#[0-9a-f]` or `rgb(` matches in `audit_feed.html`, `_audit_timeline.html`, `_audit_events_table.html`).

### Pillar 4: Typography (4/4)

Sizes observed in audit templates:
- `text-2xl` — page heading (`audit_feed.html:4`).
- `text-sm` — filter inputs, table cells, table header, card sub-heading, empty states, footer.
- `text-xs` — timeline x-axis hour labels (`_audit_timeline.html:13`).

Spec §Typography line 151 says "Sizes used: 24px, 14px (2 sizes)" but the spec's own bar-chart code example at line 216 emits `text-xs text-slate-400` on the x-axis row. The implementation follows the code sample, which is the operative artifact. Counted as compliant.

Weights observed:
- `font-semibold` (600) — page heading, card sub-heading.
- Default `400` — body, inputs, table cells.

Within spec's "2 weights" limit. `font-bold` on the sidebar h1 is inherited from `base.html` (out of audit scope).

`font-mono` correctly applied to:
- `tool_name` column (`_audit_events_table.html:19`).
- `fingerprint` column with `text-slate-500` (`_audit_events_table.html:22`).

### Pillar 5: Spacing (4/4)

Token usage on the 4/8/16/24/32 scale:
- `p-4` (16px) — all three cards.
- `mb-4` (16px) — gap between cards.
- `mb-6` (24px) — heading-to-content gap (`audit_feed.html:4`).
- `gap-4` (16px) — filter form gap (`audit_feed.html:6`).
- `gap-1` (4px) — bar chart gap (`_audit_timeline.html:5`).
- `h-32` (128px) — timeline container height (`_audit_timeline.html:5`), exact match for spec §Timeline Sizing line 224.
- `min-height: 2px` — non-empty bar visibility floor (`_audit_timeline.html:9`), matches spec §Spacing exception line 138.
- `p-8` (32px) — `<main>` padding inherited from `base.html` (line 29).

Filter input internal padding `px-2 py-1` (8px / 4px) — `px-2` matches spec `sm=8px` token; `py-1` (4px = xs token) is on-scale, just on the smaller side for `text-sm` content. Within standard Tailwind defaults; not flagged.

`flex-wrap` on the filter form (`audit_feed.html:6`) is **additive** over the spec (spec only listed `gap-4`). It improves responsive behavior on narrow viewports without violating any locked rule.

No arbitrary spacing (`[12px]`, `[1.5rem]`, etc.) found in any audit template.

### Pillar 6: Experience Design (3/4)

**Present and on-spec:**
- Empty states both cards: table empty row `Аудит-событий нет.` (`_audit_events_table.html:25`), timeline empty paragraph `Нет данных за выбранный период.` (`_audit_timeline.html:3`).
- Filter echo: every input/select preserves submitted value via `value="..."` or `selected` (`audit_feed.html:9, 14, 21-23, 29-31`).
- HTMX polling: `hx-get="/_partials/audit/timeline"` + `hx-trigger="every 30s"` + `hx-include="closest form"` on the timeline card (`audit_feed.html:39-41`) — matches spec §HTMX polling and `overview.html` precedent.
- Click-through: machine_id link to `/machines/{full_id}` with body truncated to first 12 chars (`_audit_events_table.html:17`).
- Overflow signaling: `<tfoot>` row rendered only when `total > limit` (`_audit_events_table.html:28-32`).
- `sr-only` labels on all four form controls (`audit_feed.html:7, 12, 17, 26`) — matches spec §Accessibility line 315.
- Input focus rings: `focus:ring-2 focus:ring-slate-400 focus:border-slate-500` on every `<input>` and `<select>` (`audit_feed.html:10, 15, 19, 28`).
- Read-only page — no destructive actions, no confirmations needed (matches spec).
- Silent HTMX retry on poll failure — no toast (matches spec, acceptable for v0.2 admin tool).

**Gap (−1 from a perfect score):**
- **WARNING — Submit button has no explicit focus styling.** UI-SPEC §Accessibility line 316 explicitly requires `focus:outline-none focus:ring-2 focus:ring-slate-500` on the submit button. The implementation at `audit_feed.html:34` only has `bg-slate-900 text-white text-sm rounded px-4 py-2`. The "Сбросить" anchor at line 35 has only `text-sm text-slate-500 hover:underline self-center` with no `focus-visible:ring` either, though spec was less prescriptive for it.

**Secondary observation (informational):**
- The decision-color conditional uses `{% else %}` to catch `error`, which means any future fourth `decision` value (e.g. `unknown`, `pending`) silently inherits amber. Defensive but invisible to a maintainer reading the template. See Top-3 fix #2.

---

## Registry Safety

Not applicable. UI-SPEC §Registry Safety line 343-348 explicitly states: "This phase uses **zero** external component blocks. All UI built from raw Jinja templates + Tailwind classes already used in v0.1. No supply-chain risk introduced." Verified — no `components.json`, no shadcn, no third-party block registries in the audited files. No `npx shadcn view` checks needed.

---

## Files Audited

- `src/ccguard/server/web/templates/audit_feed.html` (48 lines)
- `src/ccguard/server/web/templates/components/_audit_timeline.html` (17 lines)
- `src/ccguard/server/web/templates/components/_audit_events_table.html` (33 lines)
- `src/ccguard/server/web/templates/base.html` (35 lines — read for sidebar nav + tokens)
- `src/ccguard/server/web/templates/findings_feed.html` (44 lines — read as the spec-cited reference pattern)

Cross-referenced against:
- `01-UI-SPEC.md` (383 lines — locked design contract)
- `01-CONTEXT.md`, `01-01-SUMMARY.md` through `01-06-SUMMARY.md` (execution evidence + RU copy lockdown test confirmed in `01-06`).
