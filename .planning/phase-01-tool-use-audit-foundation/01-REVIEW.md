---
phase: 01-tool-use-audit-foundation
reviewed: 2026-05-25T00:00:00Z
iteration: 2
depth: standard
files_reviewed: 6
files_reviewed_list:
  - src/ccguard/agent/audit_hook/flusher.py
  - src/ccguard/agent/audit_hook/buffer.py
  - src/ccguard/schemas/tool_use.py
  - src/ccguard/server/services/tool_use_service.py
  - tests/unit/test_audit_flusher.py
findings:
  critical: 0
  warning: 0
  info: 0
  total: 0
status: clean
resolutions:
  CR-01: resolved
  WR-01: resolved
  WR-02: resolved
  WR-03: resolved
  WR-04: resolved
  WR-05: resolved
---

# Phase 1: Code Review Report — Iteration 2

**Reviewed:** 2026-05-25
**Depth:** standard
**Files Reviewed:** 6 (fix-site re-check)
**Status:** clean

## Summary

Iteration-2 re-review confirms all six findings from the iteration-1 report are correctly resolved by commits `72aca66`, `48abd37`, `81f7b4b`, `13ee5b4`, `4c67aff`. No new BLOCKER or WARNING defects were introduced by the fix pass. The previously-flagged five INFO items remain as-is (style/minor — not re-litigated this iteration).

## Per-finding verification

### CR-01 — Atomic lock (commit 72aca66) — RESOLVED

- `flusher._acquire_lock` uses `os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)`. This is the canonical atomic create-or-fail primitive on POSIX; the kernel guarantees that at most one of two concurrent callers wins. Verified at `src/ccguard/agent/audit_hook/flusher.py:117-125`.
- Stale-lock recovery (`p.unlink()` followed by `os.open(O_EXCL)`) is **safe** against TOCTOU: if a third process races in and re-creates the lockfile in the gap between `unlink` and `os.open`, the `O_EXCL` create returns `FileExistsError`, which is caught (alongside the broader `OSError`) and converted to `return False`. The losing process simply skips the spawn — no duplicate flusher is produced.
- The `OSError` arm of the `except (FileExistsError, OSError)` is a slightly broader catch than strictly required (e.g., it swallows EPERM on a read-only directory), but in the spawn-gating hot path "fail closed → don't spawn" is the correct behavior, so this is acceptable.
- Tests `test_acquire_lock_creates_pidfile`, `test_acquire_lock_refuses_when_fresh`, and `test_acquire_lock_overrides_stale` cover all three branches.

Residual risk acknowledged in iter-1 resolution note (no server-side dedupe / batch nonce): unchanged, deliberately deferred. The atomic lock alone closes the proximate duplicate-flusher path that was the BLOCKER.

### WR-01 — Backoff schedule (commit 48abd37) — RESOLVED

- `_MAX_ATTEMPTS = 4`, `_BACKOFF_SECONDS = (1, 2, 4)`. The retry loop is `for attempt_idx in range(_MAX_ATTEMPTS): if attempt_idx > 0: time.sleep(_BACKOFF_SECONDS[attempt_idx - 1])`. Trace: idx=0 no-sleep + POST; idx=1 sleep(1) + POST; idx=2 sleep(2) + POST; idx=3 sleep(4) + POST. Four attempts, three sleeps, all three entries of `_BACKOFF_SECONDS` exercised — matches the module docstring at `flusher.py:20-22`.
- Bounds-check: `_BACKOFF_SECONDS[attempt_idx - 1]` is indexed up to `attempt_idx = _MAX_ATTEMPTS - 1 = 3`, i.e. `_BACKOFF_SECONDS[2]`. Tuple length is 3 → no IndexError. Tightly coupled invariant `len(_BACKOFF_SECONDS) >= _MAX_ATTEMPTS - 1` is currently satisfied; if a future change bumps `_MAX_ATTEMPTS` without extending the tuple, the loop will raise IndexError on the last retry attempt. Not flagging as a finding — minor risk only triggered by a future edit.
- Test `test_run_flush_loop_backs_off_on_failure` now asserts `call_count["n"] == flusher._MAX_ATTEMPTS` and `sleeps == [1, 2, 4]`. Direct verification.

### WR-02 — Per-batch continuation (commit 48abd37) — RESOLVED

- `ToolBufferDB.drain` now takes `after_id: int = 0` (`buffer.py:128-153`) and filters `WHERE id > ? ORDER BY id ASC LIMIT ?`. The `ORDER BY id ASC` is preserved, so `rows[-1]["id"]` is always the maximum id in the just-drained batch.
- `_run_flush_loop` (`flusher.py:236-295`) tracks `skip_after_id`; on persistent batch failure, sets `skip_after_id = rows[-1]["id"]` and re-enters the outer `while True` loop. Next `drain(_MAX_BATCH, after_id=skip_after_id)` returns the next batch beyond the failed one, or an empty list → loop exits cleanly. Failed rows remain in the buffer (no `delete_ids` call on failure), so the next flusher invocation retries them.
- Edge case verified: if **all** remaining batches fail, the loop terminates when `drain` returns `[]` after the last batch's `skip_after_id`. No infinite loop.
- Edge case verified: a batch that succeeds **after** a previously-skipped batch is correctly deleted via `buf.delete_ids([r["id"] for r in rows])`, with no resurrection of the skipped rows since they're identified by id, not position.
- Backpressure: `trim_to_cap(10_000)` still runs at the end regardless of `batch_succeeded`, so the DoS guard is preserved.

### WR-03 — `machine_id` upper bound (commit 81f7b4b) — RESOLVED

- `AuditBatchIn.machine_id: str = Field(min_length=1, max_length=128)` (`schemas/tool_use.py:69`). Pydantic v2 enforces this at validation time; FastAPI translates ValidationError to HTTP 422 automatically. Confirmed.
- `tool_name` already had `max_length=128` (pre-existing), `fingerprint` is regex-bounded (`^[0-9a-f]{16}$`), `events` is `max_length=200`. All untrusted string fields now bounded.
- The middleware-level total-request-body cap remains absent (called out in iter-1 resolution as deferred). Acceptable scope cut for this iteration — not a new finding.

### WR-04 — Lazy schema init (commit 13ee5b4) — RESOLVED

- `ToolBufferDB.__enter__` (`buffer.py:70-88`) probes `SELECT name FROM sqlite_master WHERE type='table' AND name='events'` and only calls `executescript(_SCHEMA)` when the table is missing. Implicit COMMIT in `executescript` is therefore avoided on the hot path after first connect.
- First-ever DB creation: `sqlite3.connect(str(self.path), ...)` creates the empty file, probe returns `None`, `executescript` runs both `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` — confirmed via test `_seed_buffer` which runs against a fresh `tmp_path`. Passes.
- Race between two concurrent first-ever connects: both probes might return `None` and both call `executescript`. `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` are idempotent at the SQL level. Even if SQLite's implicit COMMIT briefly contends, no error is raised. Safe.
- PRAGMA statements (`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`) still run on every connect, which is correct (PRAGMAs are per-connection state, not persisted to disk for `journal_mode`/`synchronous` they are sticky, but re-issuing them is a no-op or near-no-op).

### WR-05 — UTC enforcement (commit 4c67aff) — RESOLVED

- `ToolUseEventIn._enforce_utc` (`schemas/tool_use.py:42-58`) runs as a `mode="after"` field_validator. Pydantic v2 first parses the ISO-8601 string into a `datetime`, then the validator checks `v.tzinfo is None` → raises `ValueError("ts must be timezone-aware (UTC)")` → FastAPI converts to 422. Confirmed rejection path.
- Non-UTC offset normalization: `if v.utcoffset() != UTC.utcoffset(v): return v.astimezone(UTC)`. `UTC.utcoffset(v)` is `timedelta(0)`, so any non-zero offset triggers `astimezone(UTC)`, which produces an equivalent instant in UTC. The persisted `ts` is therefore always tz-aware UTC. The lexicographic hour-bucketing in `timeline_buckets` is now safe.
- Style nit (not a finding): `v.utcoffset() != UTC.utcoffset(v)` is functionally equivalent to `v.utcoffset() != timedelta(0)` and slightly more opaque, but `UTC` is already imported, so the cost is purely readability. Leaving as-is.
- `timeline_buckets` docstring (`tool_use_service.py:100-109`) now explicitly documents the UTC contract and references the validator that enforces it. The lexicographic comparison `ts >= :cutoff` against `start.isoformat()` (which is UTC-anchored) is correct given the enforced invariant.
- Agent-side: `hook_main` emits `datetime.now(UTC).isoformat()` which produces `…+00:00` — passes the validator without normalization. Existing tests continue to pass.

## Cross-cutting checks

- **No new SQL injection vectors.** `drain`'s new `after_id` parameter is bind-bound (`WHERE id > ?`). `timeline_buckets`'s parameterized WHERE construction is unchanged from iter-1 and still uses `bindparams`.
- **No new race conditions.** Lock acquisition is now strictly stronger than before. Buffer schema race on first connect is benign (idempotent DDL). Flusher per-batch retry advances `skip_after_id` monotonically — no risk of re-reading + re-POSTing the same rows within a single invocation.
- **No privacy regression.** `schemas/tool_use.py` still defines no `tool_input` field. Validator additions to `ts` do not introduce any new field traversal.
- **Test count.** Test file `test_audit_flusher.py` retains all prior test functions (13 visible top-level tests in this file alone); the iter-1 baseline of ≥356 non-e2e tests is preserved per the fix commits (no test deletions observed in the listed files).
- **No new dead code.** `_BACKOFF_SECONDS[2] = 4` is now exercised. `after_id=0` default in `drain` preserves backward-compat for any caller that doesn't pass it (none other than `_run_flush_loop` in this repo).

## Historical resolutions (preserved from iteration 1)

- CR-01 (BLOCKER): TOCTOU race in `_acquire_lock` → duplicate flusher → duplicate rows. Resolved by `72aca66` (atomic `O_CREAT|O_EXCL`).
- WR-01: Backoff schedule advertised 3 sleeps but executed 2. Resolved by `48abd37` (sleep-before-attempt restructure with `_MAX_ATTEMPTS=4`).
- WR-02: Flusher abandoned remaining batches after first-batch failure. Resolved by `48abd37` (`drain(after_id=…)` + `skip_after_id`).
- WR-03: `machine_id` unbounded. Resolved by `81f7b4b` (`max_length=128`).
- WR-04: `executescript` on every hook invocation. Resolved by `13ee5b4` (`sqlite_master` probe).
- WR-05: Lexicographic `ts` comparison vulnerable to non-UTC agents. Resolved by `4c67aff` (Pydantic `_enforce_utc` field validator).
- IN-01..IN-05: Not re-litigated in iteration 2; remain as previously documented INFO-level items.

---

_Reviewed: 2026-05-25_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Iteration: 2_
