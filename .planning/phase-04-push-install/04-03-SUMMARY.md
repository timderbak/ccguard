---
phase: 04-push-install
plan: 03
subsystem: agent
tags: [agent, push-install, atomic-io, rollback, snapshot, claude-md, mcp]
requires: [04-01]
provides:
  - ccguard.agent.atomic_io.atomic_write_bytes
  - ccguard.agent.push_install.apply
affects:
  - src/ccguard/agent/atomic_io.py
  - src/ccguard/agent/push_install.py
tech_stack:
  added: []
  patterns: [tempfile+os.replace, regex backref DOTALL, JSON merge, snapshot rollback]
key_files:
  created:
    - src/ccguard/agent/atomic_io.py
    - src/ccguard/agent/push_install.py
    - tests/unit/test_atomic_io.py
    - tests/unit/test_push_install_marker_merge.py
    - tests/unit/test_push_install_mcp_merge.py
    - tests/unit/test_push_install_rollback.py
  modified: []
decisions:
  - "D-2: snapshot scope = targeted files only; never whole-tree backup"
  - "D-3: orphan deletion SKIPPED — no managed-manifest.json in v0.2"
  - "D-4: ~/CLAUDE.md only; project-scope CLAUDE.md deferred"
  - "D-5: required_skills[].content written as-is (full file bytes)"
  - "D-7: managed MCP entries identified by `_managed_by: \"ccguard\"` field, NOT by key prefix"
metrics:
  duration_minutes: 12
  tasks_completed: 2
  files_changed: 6
  commits: 4
  tests_added: 20
  completed_date: 2026-05-26
---

# Phase 04 Plan 03: Agent push_install pipeline Summary

Implemented the agent-side apply engine: an atomic POSIX-write helper plus a
`push_install.apply()` function that snapshots target files, merges the four
mandatory policy sections (skills, agents, MCP, CLAUDE.md), and rolls back
byte-for-byte on any failure without propagating exceptions into the CLI.

## Public Surface

### atomic_io
```python
def atomic_write_bytes(path: Path, data: bytes) -> None
```
- Creates `path.parent` if missing.
- Uses `tempfile.NamedTemporaryFile(dir=path.parent, prefix=".ccguard-tmp-")` so
  the subsequent `os.replace` is an atomic rename within one filesystem.
- `flush()` + `os.fsync()` + `chmod 0o644` (normalizing tempfile's 0o600) + `os.replace`.
- On any exception the temp file is unlinked silently; nothing leaks into the
  parent directory.
- POSIX-only by project constraint.

### push_install
```python
def apply(
    policy: dict,
    *,
    home: Path | None = None,        # default: Path.home()
    ccguard_root: Path | None = None # default: home / ".ccguard"
) -> ApplyResult
```
`ApplyResult` shape (always a dict, never raises):
```python
{
    "result": "success" | "rollback",
    "applied_count": int,
    "snapshot_id": str | None,   # e.g. "20260526-120000" or "20260526-120000-1"
    "reason": str | None,        # "PermissionError: ..." on rollback
    "failed_file": str | None,   # absolute path of file that errored
}
```
Plan 04 (CLI integration) forwards this dict directly to the
`/api/v1/audit/policy-apply` endpoint built in plan 04-02.

## Marker Regex (CLAUDE.md merge)

```python
re.compile(
    rf"<!-- ccguard:managed start (?P<id>{re.escape(block_id)}) -->"
    r"\n(?P<body>.*?)\n"
    rf"<!-- ccguard:managed end (?P=id) -->",
    re.DOTALL,
)
```

Why backref `(?P<id>...)` + `(?P=id)`:
- The end marker is matched against the **same** id as the start marker, so a
  malformed file with `start alpha ... end beta` will NOT be treated as a
  valid `alpha` block (regression guard against cross-id contamination).
- Non-greedy `.*?` plus `re.DOTALL` lets the smallest body be captured even
  when multiple managed blocks live in the same file.

User content outside markers is preserved byte-for-byte (only the substring
matched by the regex is replaced; everything else is left untouched).

Per **D-3** orphan blocks (in file but absent from policy) are NOT removed —
no `managed-manifest.json` is created. Per **D-4** only `home / "CLAUDE.md"`
is touched; project-scope CLAUDE.md is explicitly out of scope for v0.2.

## `_managed_by` Merge Invariants (for plan 06 e2e)

`_merge_mcp_servers(existing_json, required)` guarantees:

1. **Removal predicate is field-based, not key-based (D-7):**
   An entry is removed iff `isinstance(v, dict) and v.get("_managed_by") == "ccguard"`.
   A user-created entry whose KEY happens to be `ccguard-tool` but lacks the
   field is **kept**.
2. **Injection:** every entry in `required` is written with
   `_managed_by: "ccguard"` set (overwriting if the policy already had it).
3. **`name` is the key, not a field:** the merger pops `name` from each
   required-entry dict and uses it as the `mcpServers` key.
4. **User entries are preserved verbatim** — value dicts are not deep-copied
   or re-serialized.
5. **Top-level fields besides `mcpServers` are preserved** (e.g. user-set
   `someUserField: 42` survives the merge).
6. **Missing or invalid `~/.claude.json`** is treated as `{}` (file is then
   created with `mcpServers` only).

These invariants are the contract plan 06 (e2e) and any future allow/deny
audit logic can rely on.

## Snapshot & Rollback

- Snapshot dir: `ccguard_root / "snapshots" / "{YYYYmmdd-HHMMSS}"`, with
  `-{n}` suffix if the timestamp collides at one-second resolution.
- Scope (D-2): only the explicit target paths (skills SKILL.md files, agents
  `*.md` files, `~/.claude.json`, `~/CLAUDE.md`). Never the whole
  `~/.claude/` tree.
- Rolling retention: after every apply (success OR rollback), all but the
  newest 5 snapshot directories are `shutil.rmtree`'d.
- On any exception in the apply body, `_restore()` writes every snapshotted
  file back to its original location via `atomic_write_bytes` and returns the
  rollback dict. **No exception escapes `apply()`** — this is enforced by a
  top-level `try/except Exception` (verified by
  `test_apply_never_raises`).

## Test Coverage

| File | Tests | Focus |
|------|-------|-------|
| test_atomic_io.py | 8 | bytes, parent dirs, overwrite, same-dir tmp, no leftovers, cleanup on replace failure, concurrent serialization, perms 0o644 |
| test_push_install_marker_merge.py | 6 | empty input, user-content preservation, D-3 orphan retention, append separator, backref-prevents-cross-id, multi-block |
| test_push_install_mcp_merge.py | 6 | managed-removal, D-7 key-prefix not removed, marker injection, extra-field preservation, missing-key fallback, top-level field preservation |
| test_push_install_rollback.py | 8 | round-trip 4 sections, snapshot dir creation, rollback restoration, never-raises, rolling-5, D-2 scope, no manifest, D-4 project untouched |

**Total: 20 new unit tests, all passing.** Full unit suite: **427 passed.**

## Verification Gates (all passing)

- `uv run pytest tests/unit/test_atomic_io.py tests/unit/test_push_install_*.py -x -q` → 20 passed
- `uv run pytest -q --ignore=tests/e2e --ignore=tests/integration` → 427 passed
- `grep -v '^#' src/ccguard/agent/push_install.py | grep -c "_managed_by"` → 5 (≥ 2 required)
- `grep -v '^#' src/ccguard/agent/push_install.py | grep -c "ccguard:managed"` → 4 (≥ 1 required)
- `grep -cE "^import (asyncio|requests|urllib3|httpx)" src/ccguard/agent/push_install.py src/ccguard/agent/atomic_io.py` → 0/0 (stdlib only)

## Deviations from Plan

None — plan executed exactly as written.

## Deferred Issues

The following integration/e2e tests fail but are **pre-existing failures
outside this plan's scope** (verified by stash-and-rerun against the parent
commit `2e6f0bd`):

- `tests/integration/test_policy_mandatory_routes.py` (8 tests) — requires
  server routes `/policy/mandatory` not yet implemented; plan **04-02**
  deliverable.
- `tests/e2e/test_end_to_end.py` (6 tests) + `test_web_e2e.py` (1 test) +
  `test_audit_smoke.py` (1 test) — require a live server; environmental.

Plan 04-03 explicitly scoped to `src/ccguard/agent/*` only, so these are
documented here for the verifier and the orchestrator but not addressed in
this plan.

## Commits

| Hash | Message |
|------|---------|
| 63bc740 | test(04-03): add failing tests for atomic_write_bytes helper |
| 237146f | feat(04-03): add atomic_write_bytes POSIX helper |
| 2e6f0bd | test(04-03): add failing tests for push_install.apply pipeline |
| 2659e71 | feat(04-03): add push_install.apply with snapshot+rollback |

## Self-Check: PASSED

All 7 declared files exist on disk; all 4 commit hashes resolve in `git log`.
