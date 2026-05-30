# Behavioral Detection — Stage 3: IOA Exfil-Sequence Detector

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a single `FindingRecord(rule_id="ioa.exfil_sequence")` per machine per UTC day when a `cred.read.*` signal is followed by an `egress.*` signal **on the same machine within T minutes** (spec §4.3). This is the primary low-FP detection — order matters, window matters, no aggregation surprise.

**Architecture:**

```
APScheduler tick (existing job)
  → anomaly_service.tick(s)        [existing]
  → risk_service.tick(s)           [Stage 2]
  → sequence_service.tick(s)       [NEW]
     for each machine with baseline_ready:
       events = ToolUseEvent in (now - lookback) where signals_json != "[]"
       pair = detect_exfil_sequence(events, window_minutes)
       if pair and no same-UTC-day "ioa.exfil_sequence" finding:
         emit FindingRecord("ioa.exfil_sequence", severity="high", payload=pair)
```

**Tech stack:** Python 3.12, stdlib `json`, SQLModel, pytest. No new deps. No schema migration.

**Out of scope (deferred per spec §6):** config-drift / `persist.agent_config` (needs inventory snapshot diff machinery — separate detector); explainability UI; suppression; `enforcement_mode` switch.

**Invariants:**
- **Privacy:** reads only `signals_json` (catalog IDs). Never raw input.
- **Severity:** `high` (vs `risk.elevated` = `warn`) — the sequence is a much sharper indicator.
- **Lookback:** 24h default — older than the typical sequence window so we never miss the "egress 10min after the cred read but tick lagged" case, but small enough to keep the working set tiny.
- **Window T:** default 15 minutes, tunable via `SettingsRecord["sequence.window_minutes"]`.
- **Same-machine only:** the SQL filter already enforces this.
- **No race:** same scheduler thread as the other two ticks. Same-UTC-day dedup mirrors risk + anomaly services.
- **Warm-up:** reuse `MachineBaseline.baseline_ready` (same posture as risk engine — cold machines skip).

---

### Task 1: Sequence constants + settings seed

**Files:**
- Create: `src/ccguard/server/services/sequence_constants.py`
- Modify: `src/ccguard/server/services/settings_service.py` — add `seed_sequence_settings`
- Modify: `src/ccguard/server/main.py` — call seeder in lifespan after `seed_risk_settings`
- Test: `tests/unit/test_sequence_constants.py`
- Test: `tests/integration/test_sequence_settings_seed.py`

- [ ] **Step 1: Failing tests** asserting the constants module exports and the seeder writes `sequence.window_minutes` + `sequence.lookback_hours`, preserves admin edits on re-seed.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement constants (`SEQUENCE_RULE_ID = "ioa.exfil_sequence"`, `DEFAULT_WINDOW_MINUTES = 15.0`, `DEFAULT_LOOKBACK_HOURS = 24.0`, `CRED_PREFIX = "cred.read."`, `EGRESS_PREFIX = "egress."`); add `seed_sequence_settings` mirroring `seed_risk_settings`; wire into lifespan.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(sequence): exfil-sequence constants + tunable settings seed`.

---

### Task 2: Pure detection kernel `detect_exfil_sequence`

`detect_exfil_sequence(events, window_minutes, cred_prefix, egress_prefix) -> ExfilMatch | None`. No I/O. Takes a list of `SequenceInputEvent(ts, signals)` and returns the first cred→egress pair where egress.ts is in `[cred.ts, cred.ts + window]`.

**Files:**
- Create: `src/ccguard/server/services/sequence_service.py`
- Test: `tests/unit/test_sequence_detector.py`

Test cases:
- empty → None
- cred only → None
- egress only → None
- cred → egress within window (5min later) → match, `elapsed_seconds == 300`
- egress → cred (reverse) → None
- cred → egress beyond window (20min later) → None
- cred and egress in same event (zero gap) → match, `elapsed_seconds == 0`
- two creds then one egress in window for the second → match against the **earlier** cred (first cred that can be paired)
- unsorted input → still works (kernel sorts by ts)

Implementation note: O(n²) is fine — per-machine lookback is bounded; n is small.

- [ ] Steps 1–5 (TDD + commit `feat(sequence): pure cred→egress detector kernel`).

---

### Task 3: `sequence_service.tick()` orchestrator

Mirrors `risk_service.tick` shape: per-machine loop, warm-up guard, same-UTC-day dedup, per-machine try/except, `FindingRecord` emission with payload `{trigger, egress, window_minutes, elapsed_seconds}`.

**Files:**
- Modify: `src/ccguard/server/services/sequence_service.py`
- Test: `tests/integration/test_sequence_tick.py`

Test cases:
- cold machine (no warm baseline) → no finding
- warm machine, only cred → no finding
- warm machine, cred + egress in window → 1 finding, severity `high`, payload contains both timestamps and `elapsed_seconds`, `rule_id == "ioa.exfil_sequence"`
- same-day dedup (run tick twice → 1 finding)
- two machines, only one matches → 1 finding tied to the right `machine_id`

- [ ] Steps 1–5 (TDD + commit `feat(sequence): per-machine tick with warm-up, dedup, high-severity finding`).

---

### Task 4: Wire into scheduler lifespan

Chain `sequence_tick` after `risk_tick` in `_tick_job_sync`, same Session, same log-line style.

**Files:**
- Modify: `src/ccguard/server/main.py`
- Test: `tests/integration/test_sequence_tick_lifespan.py`

Tests mirror Stage 2 lifespan test: a smoke composability test + a static guard that `main.py` references `sequence_service.tick` or `from ccguard.server.services.sequence_service import tick`.

- [ ] Steps 1–5 (TDD + commit `feat(sequence): chain sequence tick after risk tick in scheduler lifespan`).

---

### Task 5: End-to-end + full-suite regression

Drive the full path through the audit API.

**Files:**
- Test: `tests/integration/test_sequence_e2e.py`

E2E:
- Seed machine + warm baseline.
- POST two events via `/api/v1/audit`: first has `["cred.read.aws"]` at T-5min, second has `["egress.network_tool"]` at T.
- `sequence_service.tick(session)` → 1 finding, `rule_id == "ioa.exfil_sequence"`, severity `high`.

Then `uv run pytest --ignore=tests/e2e -q` to confirm no regressions.

- [ ] Steps 1–4 (TDD + commit `test(sequence): end-to-end cred-then-egress flow`).

---

## Self-Review (plan author)

- **Spec coverage:** Implements spec §4.3 sequence detector. Config-drift (`persist.agent_config`) is explicitly deferred — it needs inventory-snapshot-diff plumbing that doesn't exist yet and is its own design surface.
- **Privacy invariant preserved:** reads only `signals_json`. Payload carries IDs + timestamps + elapsed_seconds, no content.
- **Backward compat:** machines without signals → no events → no finding; cold machines skip; reverse-order or out-of-window events → no finding.
- **Severity choice:** `high` is correct per spec §3 (lowest-FP detection); operationally distinct from `risk.elevated`'s `warn` so the UI can render differently.
- **Tunability:** `sequence.window_minutes`, `sequence.lookback_hours` live in `SettingsRecord`. Catalog prefixes (`cred.read.` / `egress.`) are constants — changing them is a code change.
- **Concurrency:** single-writer (same scheduler thread); per-machine try/except; service-layer same-UTC-day dedup.
- **No new deps; no schema change.**
