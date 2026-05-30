# Rule Discovery Agent — Full Plan

> Stage E in the Behavioral Detection v2 roadmap. Builds an LLM-driven loop that
> monitors threat-intel sources, drafts new catalog signals, and asks the admin
> to approve them. Approved drafts hot-reload into agents via the existing
> policy sync — no code change required to roll out a new signal.

**Goal:** New ATT&CK technique drops on Monday → cron-monitor catches it Tuesday → LLM drafts a `Signal` Tuesday afternoon → admin clicks Approve Wednesday morning → all agents start firing the new signal Wednesday after their next policy sync.

**Tech stack:** Python 3.12, Anthropic SDK (already a project dep for the LLM scanner), SQLModel, FastAPI, HTMX. No new infra.

**Privacy/safety invariants:**
- LLM never sees customer data — only public threat-intel text and the existing CATALOG as a few-shot example.
- Daily call budget reuses existing `daily_call_budget` SettingsRecord.
- Approved signals go through `set_setting`-style audit trail; no silent activation.
- LLM-drafted regexes are validated (`re.compile`) at approval time, not at draft time, so bad drafts can be edited rather than hard-rejected.

---

## E1 · ProposedSignal storage + admin UI (this stage)

**Files:**
- New: `src/ccguard/server/db/models.py` — add `ProposedSignal` table
- New: `src/ccguard/server/services/proposed_signal_service.py` — CRUD + approve/reject
- New: `src/ccguard/server/web/templates/proposed_signals.html`
- New routes in `routes.py`: GET `/admin/proposed-signals`, POST `/admin/proposed-signals/{id}/approve`, POST `/admin/proposed-signals/{id}/reject`, POST `/admin/proposed-signals/draft-from-text` (manual paste; LLM call deferred to E2 — for now stores raw draft JSON the admin types in)
- Tests: unit + integration

**Schema:**
```python
class ProposedSignal(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    draft_json: str           # JSON of {id, attack_technique, pattern, description}
    source_kind: str          # "manual" | "mitre" | "atlas" | "atomic-red-team" | "lakera" | "cve"
    source_url: str | None
    source_title: str | None
    llm_rationale: str | None
    status: str               # "pending" | "approved" | "rejected"
    created_at: datetime
    reviewed_at: datetime | None
    reviewed_by: str | None   # admin user_id
    rejection_reason: str | None
```

**Approval contract:** writing status="approved" validates the draft's regex compiles, then writes `SettingsRecord["catalog.override.<id>"] = draft_json`. E4 picks that up via the policy sync.

---

## E2 · LLM drafter service

**Files:**
- New: `src/ccguard/server/services/signal_drafter.py`
- Route: `/admin/proposed-signals/draft-from-text` switches from raw-paste to LLM-drafted.
- Tests: mocked Anthropic responses; budget-exceeded path.

**Prompt template (sketch):**
```
You are extending a catalog of behavioral-detection regex signals for AI-agent
endpoints. Each signal has: id (kebab-namespaced like `cred.read.aws`),
attack_technique (MITRE T-id), pattern (Python re-compile-able regex matched
case-insensitively on lowercased "<command>\n<file_path>"), description.

Existing examples: <inline 4-5 catalog entries as JSON>

Given this threat-intel text, draft ONE Signal as JSON. If multiple distinct
signals are warranted, prefer the highest-value one and note the others in
"alternates". Output strict JSON only.

THREAT_TEXT: """<input>"""
```

Budget check uses existing `parse_budget` + a per-day counter (mirror `ScanService`).

---

## E3 · Source monitors

**Files:**
- New: `src/ccguard/server/services/source_monitors/` package
  - `base.py` — `class SourceMonitor: poll() -> list[SourceItem]`
  - `atomic_red_team.py` — GitHub releases API for redcanaryco/atomic-red-team
  - `mitre_attack.py` — RSS / GitHub releases of mitre/cti
  - `atlas.py` — MITRE ATLAS GitHub releases
  - `lakera_blog.py` — RSS
  - `cve_ai_filter.py` — NVD feed filtered by keyword set
- New: `discovery_service.tick(session)` — chained after `sequence_tick` in lifespan. Pulls each monitor, dedups against a `SourceFetchLog` table by URL, hands new items to the drafter, writes ProposedSignal rows.

Each monitor isolated so one broken source doesn't kill the others.

---

## E4 · Hot-reload to agents via policy sync

**Files:**
- Modify: `src/ccguard/schemas/policy.py` — extend with `signal_overrides: list[SignalOverrideIn]` (optional, default `[]`).
- Modify: server `/api/v1/policy` — include approved catalog overrides.
- Modify: `agent/signals/extractor.py` — `extract_signals(...)` reads the policy's overrides, compiles them once per policy revision (LRU on `policy.revision`), merges with baked CATALOG.
- Agent contract: an override with the same id as a baked signal **takes precedence** (admin can hot-fix a false-positive regex).
- Tests: schema round-trip; extractor with override; cache invalidation on revision bump.

---

## E5 · Optional: PR-back-to-catalog

For teams that want git history of approved signals: separate "Export to PR" button on the admin UI that calls `gh api` to open a PR adding the signal to `catalog.py`. Approved-in-DB AND in-code is allowed (the in-code version is the source of truth on next deploy; the override is the hot path).

Out of scope for this milestone — open a follow-up.

---

## Self-review

- **Why staged this way:** E1 is shippable on its own (admin can manually paste a draft and approve it; demonstrates the storage + UI). E2 adds LLM. E3 makes it autonomous. E4 closes the loop end-to-end. Each stage is independently demoable.
- **Failure modes thought through:** corrupt draft JSON, regex that doesn't compile, LLM budget exhaustion, source-fetch timeout, agent policy sync receiving an override pointing to a deleted ProposedSignal (override lives in SettingsRecord — survives independently).
- **Privacy:** LLM input is third-party threat-intel text. CATALOG examples are public. No customer telemetry ever crosses the boundary.
- **Cost:** LLM calls are gated by the same `daily_call_budget` as the existing scanner. Source monitors cache fetches.
