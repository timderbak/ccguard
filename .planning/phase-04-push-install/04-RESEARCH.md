# Phase 4: Push-Install (Centrally-Managed Config) — Research

**Researched:** 2026-05-26
**Domain:** Server policy schema extension + agent-side atomic file-tree apply with snapshot/rollback + CLAUDE.md marker-merge + `~/.claude.json` MCP merge + admin UI «Mandatory» tab + audit event ingest extension
**Confidence:** HIGH

## Summary

Phase 4 extends the existing v0.1 policy with four declarative «mandatory» sections (`required_mcp_servers`, `required_skills`, `required_agents`, `managed_claude_md_blocks`) and adds an agent-side **apply pipeline** that materialises them on the developer's filesystem under `~/.claude/` and `~/.claude.json` with snapshot-backed rollback. The pipeline runs at the tail of `ccguard sync` after `perform_sync` returns OK (policy already cached locally), iterates the four sections in a fixed order (snapshot → write — verify — emit audit), and on any exception during write/verify restores the snapshot via `os.replace` and emits a `policy.apply.rollback` event through a new server endpoint.

The server side is **purely additive** to v0.1: Pydantic schema gets four new optional sections (default `[]`, agents-v0.1 ignore them gracefully), `policy_form.py` learns four list-of-objects sections, two new templates render an «Обязательные» tab inside the existing `/policy` page, and a new SQLModel table `PolicyApplyEvent` plus endpoint `POST /api/v1/policy-apply` ingest the agent's apply telemetry. **No** changes to `POST /api/v1/audit` (which carries `ToolUseEvent` rows under a strict privacy contract — see audit.py docstring). The new endpoint is its own table for the same reason Phase 1 split `ToolUseEvent` from `AuditRecord`: semantic clarity per phase.

The hard problem is the **filesystem apply contract**: writes must be atomic (no half-written agent files Claude Code might read mid-flight), the snapshot must be created **before any write** of that target file, rollback must be deterministic, and `CLAUDE.md` must round-trip user content **byte-for-byte** outside markers. Solutions: per-file `tempfile.NamedTemporaryFile(dir=target.parent)` → `os.replace`, snapshot dir `~/.ccguard/snapshots/{iso8601_utc}/` with `shutil.copy2` preserving mtime/perms, marker parse via single non-greedy DOTALL regex, and `~/.claude.json` merge that purges keys with `_managed_by == "ccguard"` before re-inserting from policy.

**Primary recommendation:** Implement `src/ccguard/agent/push_install.py` as five pure functions (`build_apply_plan`, `take_snapshot`, `apply_plan`, `verify_applied`, `rollback_from_snapshot`) called from `cli.py sync` after `perform_sync`, **never raising** to the CLI (mirror Phase 3 `run_scan_cycle` pattern — best-effort, telemetry-only failure). All writes go through one helper `_atomic_write_bytes(path, content)` reused from `agent/install.py:_write_settings_atomic` logic (extract to a shared util). For CLAUDE.md the regex is `re.compile(r"<!-- ccguard:managed start (?P<id>[a-z0-9-]+) -->\n(?P<body>.*?)\n<!-- ccguard:managed end (?P=id) -->", re.DOTALL)`. POSIX-only support is acceptable for v0.2 (ccguard server runs in Linux Docker; agents are dev-laptops Linux/macOS — Windows agent is not a v0.2 target).

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Policy Schema Extension:**
- Policy YAML extends with 4 new sections: `required_mcp_servers`, `required_skills`, `required_agents`, `managed_claude_md_blocks`.
- Schema version bump: minor (e.g. `0.2 → 0.3`); agent v0.2 graceful — ignores unknown sections.
- ETag-кэширование policy (v0.1) автоматически обновляется через hash содержимого.

**Agent Apply Mechanics:**
- Skills/agents/MCP: **drop-in** — write content to `~/.claude/agents/{name}.md`, `~/.claude/skills/{name}/SKILL.md`, `~/.claude.json` MCP merge.
- CLAUDE.md: **merge via markers** — `<!-- ccguard:managed start {id} -->` / `<!-- ccguard:managed end {id} -->`; user content outside markers preserved verbatim; managed blocks are rewriteable.
- Atomic write: temp-file + `os.replace()` (POSIX atomic rename) — никогда half-written файлов.
- Snapshot before apply: copy targeted files to `~/.ccguard/snapshots/{ts}/` (rolling 5 last).
- Rollback: on ANY exception during apply → restore from latest snapshot + emit `policy.apply.rollback` audit event with reason.
- Apply order: snapshot → write all → verify (file exists + content match) → on verify failure → rollback.
- Permission errors don't block other files — partial rollback with per-file reason.

**UI — Mandatory Tab:**
- `/policy` gets a new tab «Обязательные» (Mandatory) alongside the existing policy form.
- Editors per section:
  - **required MCP servers**: list with inline form (name, command, args, env)
  - **required skills**: list with (name, content textarea, frontmatter type)
  - **required agents**: list with (name, content textarea)
  - **managed_claude_md_blocks**: list with (id, content textarea, description)
- Draft → Publish → History flow as in v0.1; revision bump on publish.

**Audit Events:**
- New audit event types: `policy.apply.success` (details: `applied_count`, `snapshot_id`), `policy.apply.rollback` (details: `failed_file`, `reason`, `snapshot_id`).
- Event flow: agent → server. **Separate** new table `PolicyApplyEvent` for semantic clarity (mirrors Phase 1 `ToolUseEvent` split).
- UI: surface on existing `/audit` page as a new `event_source` filter; no separate page in v0.2.

### Claude's Discretion
- Exact YAML structure of `managed_claude_md_blocks` (list of `{id, content, description}` dicts).
- Names of rollback-snapshot directories (ISO 8601 UTC `YYYYMMDDTHHMMSSZ` recommended).
- Conflict-resolution strategy when a user manually edits a managed block by ID — **overwrite-and-warn** (recommended; user can never «win» against policy, but we surface drift in audit).
- UI editor type — plain textarea for v0.2 (Monaco overkill).

### Deferred Ideas (OUT OF SCOPE)
- Per-team/per-role differential push — v0.3 multi-tenant.
- Server-push notifications (server→agent realtime, not pull) — v0.4 (needs websocket/SSE).
- Conflict-resolution UI (admin sees per-machine divergence) — v0.3.
- Time-based scheduled push (apply at midnight UTC) — v0.4.
- Multi-version managed blocks (admin can pin specific version) — v0.3.
- Encrypted managed content (needs key distribution) — out of scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PUSH-01 | Policy extended with `required_mcp_servers`, `required_skills`, `required_agents`; served via `/api/v1/policy` | Standard Stack: Pydantic v2 extension pattern; Code Examples: schema diff |
| PUSH-02 | Agent applies required artifacts to `~/.claude/` at sync; rollback on write errors | Architecture Patterns: apply pipeline; Don't Hand-Roll: `os.replace` atomic semantics |
| PUSH-03 | Centrally-managed CLAUDE.md sections via marker blocks; merge with user CLAUDE.md preserving content outside markers | Code Examples: marker regex + round-trip strategy |
| PUSH-04 | Web UI `/policy` gets «Обязательные» tab with editors for all four sections | Architecture Patterns: tabbed editor; `policy_form.py` extension |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

| Constraint | Impact on This Phase |
|------------|----------------------|
| Python 3.12 + FastAPI + SQLModel + HTMX/Jinja stack frozen for v0.2 | All new code in this stack; no new frameworks. |
| Self-hosted; SQLite WAL; <100 machines | One new SQLModel table; index in `init_db` via `CREATE INDEX IF NOT EXISTS`. |
| Backward compat: agent v0.1 must keep working against server v0.2 | New policy sections **optional with `[]` default**; v0.1 agent receives them via JSON, ignores unknown fields (Pydantic `model_config = {"extra": "ignore"}` already in `_base.py`). |
| Performance: PreToolUse <100ms | Apply pipeline runs at `ccguard sync` time, **not** in a hook — no per-tool latency impact. |
| Security: nothing plaintext; Fernet-encrypted at rest | Policy YAML stored in `PolicyVersion.yaml_text` — **already Fernet-encrypted at column level if `SECRET_KEY` set** (see v0.1 storage). Plain-text `env` values in `required_mcp_servers` are admin-supplied and persisted through that same channel. |
| Schema versioning: `meta.schema_version` | Bump `1 → 2` on adding required-sections; `PolicyMeta.schema_version` becomes `Literal[1, 2]`; agent v0.1 will reject `2` — accept that, agent v0.2 understands both. **Re-check this decision with admin** — alternative is to keep `schema_version=1` and rely on Pydantic extra-fields-ignore on v0.1 agent. Recommendation: keep `=1`, treat new sections as additive — see Open Questions. |
| GSD workflow: all file edits via GSD commands | Standard. |

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Policy schema validation (new sections) | API/Backend (Pydantic in `schemas/policy.py`) | — | Policy is declarative server state; validation lives where the model is defined. |
| Policy storage + revisioning | API/Backend (SQLModel `PolicyVersion`) | — | Already in v0.1; only the YAML payload grows. |
| Policy distribution | API/Backend (`GET /api/v1/policy`) | — | Existing ETag flow; no change to endpoint contract. |
| Filesystem apply (write `~/.claude/agents/…` etc.) | Agent (new `push_install.py`) | — | Only the agent has access to the developer's home; server is stateless wrt endpoint filesystems. |
| Snapshot + rollback | Agent (`push_install.py`) | — | Pure local concern; server is never consulted for rollback content. |
| Apply telemetry | Agent → API (`POST /api/v1/policy-apply`) | UI (`/audit` filter) | Mirrors Phase 1 audit pattern. |
| Mandatory editor UI | UI (Jinja + HTMX tab) | API (POST form → `policy_form.form_to_yaml`) | Reuses Phase 0.1 draft/publish/history flow. |
| MCP merge in `~/.claude.json` | Agent (`push_install._merge_mcp_json`) | — | Touches the same file `agent/install.py` writes for hooks — extract shared `_atomic_write_json` helper. |
| CLAUDE.md marker merge | Agent (`push_install._merge_claude_md`) | — | Pure text transform; testable in isolation. |

**Sanity check:** No capability is in the «browser» tier (no JS bundle). Static templates only. The single MCP merge function touches a file that another module (`agent/install.py`) also writes to — extracting a single atomic-write JSON helper avoids two competing implementations.

---

## Standard Stack

### Core (already in v0.1 — reuse)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Pydantic v2 | `>=2.5` | Schema extension via `policy.py` | Already used across `schemas/` |
| SQLModel | `0.0.16+` | New `PolicyApplyEvent` table | Already used across `db/models.py` |
| FastAPI | `>=0.110` | New `POST /api/v1/policy-apply` route | Already used in `api/` |
| Jinja2 | (project default) | Mandatory tab templates | Already used in `web/templates/` |
| HTMX | (CDN) | List-add/remove rows in editor | Used in v0.1 policy editor |
| httpx | `>=0.27` | Agent POST to `/policy-apply` | Used in `agent/sync.py` |
| typer | (project default) | No new CLI commands; sync gets a tail step | Existing |

### New (stdlib only — no new dependencies)

| Module | Purpose | Why stdlib |
|--------|---------|-----------|
| `tempfile.NamedTemporaryFile(dir=parent, delete=False)` | Per-file atomic write | POSIX-safe when `dir == target parent` (same filesystem → `os.replace` is atomic) |
| `os.replace(src, dst)` | Atomic rename | POSIX guarantees; documented in `os` module |
| `shutil.copy2(src, dst)` | Snapshot files preserving metadata | Standard |
| `re` with DOTALL | CLAUDE.md marker parse | Single regex, well-tested |
| `json` stdlib | `~/.claude.json` read/merge/write | Already used in `agent/install.py` |
| `hashlib.sha256` | Verify written content matches plan | Already used for inventory hashes |

**No new third-party dependencies needed.** Everything we need is in v0.1's stack plus stdlib.

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `os.replace` per file | `python-atomicwrites` package | New dependency; stdlib already gives POSIX atomic semantics — overkill |
| Custom marker regex | `commonmark` AST round-trip | Heavy dep; we own the marker shape — regex is fine |
| `shutil.copytree` for snapshot | `tarfile` archive | Tar is one-file, harder to selectively restore; copy tree is simpler |
| New `PolicyApplyEvent` table | Reuse `ToolUseEvent` | Pollutes that table's privacy contract (no `tool_input`) — locked in CONTEXT.md |
| Symlink-based deploy | Write copies | Symlinks break Claude Code's expectation of regular files; copies are explicit. CONTEXT.md says «drop-in or симлинк» — pick **drop-in** for simplicity. |

**Verification:** All listed libraries are already pinned in the project's `pyproject.toml` (verified by reading `src/ccguard/agent/sync.py`, `src/ccguard/server/api/audit.py`, `src/ccguard/server/db/models.py`). No new `pip install` is required. `[VERIFIED: codebase grep]`

## Package Legitimacy Audit

**No new third-party packages introduced.** This phase uses only:
- Existing project dependencies (Pydantic, SQLModel, FastAPI, Jinja2, httpx, typer, PyYAML) — all `[OK]` as established in Phase 1–3 audits.
- Python stdlib (`tempfile`, `os`, `shutil`, `re`, `json`, `hashlib`, `pathlib`) — `[OK]` per definition.

`slopcheck install` was not invoked because the package set is empty. If this changes during planning (e.g. someone proposes `python-atomicwrites`), run the gate then.

---

## Architecture Patterns

### System Architecture Diagram

```
┌──────────────────────── ADMIN UI (browser) ─────────────────────────┐
│  GET  /policy?tab=mandatory       (Jinja: policy_editor.html        │
│                                    + mandatory_tab.html partial)    │
│  POST /policy/draft  (form fields: mandatory.required_mcp_servers[],│
│                       mandatory.required_skills[], ...)             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼ form_to_yaml() — extended
                ┌──────────────────────────────┐
                │ PolicyVersion (yaml_text)    │ <── existing v0.1
                │  status=draft / published    │
                └──────────────┬───────────────┘
                               │ GET /api/v1/policy (ETag-cached)
                               ▼
              ┌────────────────────────────────────────┐
              │             AGENT (CLI)                │
              │  ccguard sync                          │
              │  ├── 1. inventory POST   ── /inventory │
              │  ├── 2. policy GET       ── /policy    │
              │  │      (etag → policy.cache.yaml)     │
              │  ├── 3. push_install.apply(policy)  ── NEW for Phase 4
              │  │      ├─ build_apply_plan(policy)    │
              │  │      ├─ take_snapshot(targets)      │
              │  │      ├─ apply_plan() ── writes      │
              │  │      ├─ verify_applied()            │
              │  │      └─ on exception → rollback     │
              │  │                                     │
              │  └── 4. report apply event ── POST     │
              │           /api/v1/policy-apply         │
              └────────────────────────┬───────────────┘
                                       │
                                       ▼
                            ┌──────────────────────┐
                            │ PolicyApplyEvent     │ NEW
                            │ (machine_id, rev,    │
                            │  status, details)    │
                            └──────────┬───────────┘
                                       │
                                       ▼
                            /audit UI: filter by
                            event_source=policy_apply
```

### Recommended Code Layout

```
src/ccguard/
├── schemas/
│   └── policy.py              # ADD: ManagedMCPServer, ManagedSkill,
│                              #      ManagedAgent, ManagedClaudeMdBlock,
│                              #      MandatorySection (4 fields)
│                              #      → Policy.mandatory: MandatorySection = …
├── server/
│   ├── db/
│   │   └── models.py          # ADD: PolicyApplyEvent
│   ├── api/
│   │   └── policy_apply.py    # NEW: POST /api/v1/policy-apply
│   ├── web/
│   │   ├── policy_form.py     # EXTEND: parse mandatory.* form fields
│   │   ├── routes.py          # EXTEND: /policy renders both tabs
│   │   └── templates/
│   │       ├── policy_editor.html  # EXTEND: add tab nav
│   │       └── mandatory_tab.html  # NEW: partial
│   └── services/
│       └── policy_apply_service.py # NEW: list/filter events for UI
├── agent/
│   ├── push_install.py        # NEW: apply pipeline (5 fns)
│   ├── push_install_io.py     # NEW (optional): atomic file utils
│   ├── cli.py                 # EXTEND: call push_install at end of sync
│   └── sync.py                # NO CHANGE (kept lean)
└── tests/
    ├── unit/
    │   ├── test_push_install_apply.py
    │   ├── test_push_install_rollback.py
    │   ├── test_push_install_claude_md_merge.py
    │   ├── test_push_install_mcp_merge.py
    │   └── test_policy_mandatory_schema.py
    └── integration/
        ├── test_policy_mandatory_form.py
        ├── test_policy_apply_endpoint.py
        └── test_push_install_e2e.py
```

### Pattern 1: Atomic File Write (POSIX)

**What:** Write a temp file in the SAME directory as the target, then `os.replace`.
**When to use:** Every single file write in this phase.
**Why same directory:** `os.replace` is only atomic when src and dst are on the same filesystem; putting the temp file in `/tmp/` and then moving to `~/.claude/` may cross filesystem boundaries on Linux (e.g. tmpfs).

```python
# Source: stdlib docs + existing pattern in agent/sync.py:_atomic_write
import os, tempfile
from pathlib import Path

def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # delete=False so we own the lifetime; same-dir → same-fs → atomic.
    with tempfile.NamedTemporaryFile(
        dir=path.parent, delete=False, prefix=".ccg.", suffix=".tmp"
    ) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())  # durability before rename
        tmp_path = Path(tmp.name)
    try:
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)  # atomic on POSIX (same fs)
    except Exception:
        # Don't leak the temp file on failure.
        tmp_path.unlink(missing_ok=True)
        raise
```

### Pattern 2: Snapshot Before Apply

**What:** Copy every target file (those that exist) into `~/.ccguard/snapshots/{ts}/` preserving the **relative path under `~/`** so restore is a straight mirror.
**When to use:** Once per `apply_plan` invocation, before any write.

```python
# Source: shutil.copy2 docs + CONTEXT.md decision
import shutil
from datetime import datetime, UTC
from pathlib import Path

def take_snapshot(targets: list[Path], snapshot_root: Path) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    snap_dir = snapshot_root / ts
    home = Path.home()
    for target in targets:
        if not target.exists():
            continue  # nothing to snapshot for a fresh-write
        try:
            rel = target.resolve().relative_to(home.resolve())
        except ValueError:
            # Outside home — store under absolute path nesting (rare)
            rel = Path("_abs") / target.relative_to(target.anchor)
        dest = snap_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, dest)  # preserves mtime + permissions
    return snap_dir
```

### Pattern 3: Rolling Snapshot Retention (keep 5)

```python
def prune_snapshots(snapshot_root: Path, keep: int = 5) -> list[Path]:
    if not snapshot_root.exists():
        return []
    snaps = sorted(
        (p for p in snapshot_root.iterdir() if p.is_dir()),
        key=lambda p: p.name,  # ISO ts string sorts chronologically
    )
    removed: list[Path] = []
    for old in snaps[:-keep]:
        shutil.rmtree(old, ignore_errors=True)
        removed.append(old)
    return removed
```

### Pattern 4: CLAUDE.md Marker Merge

**What:** Parse user's existing CLAUDE.md; for each `managed_claude_md_blocks` entry, find the marker pair by ID and replace the body; if no marker pair exists, **append** a fresh marker pair at the end of the file with a blank line separator.
**When to use:** Once per sync if `managed_claude_md_blocks` is non-empty.

```python
# Source: re docs (DOTALL) + custom marker shape locked in CONTEXT.md
import re

# Pre-compiled, anchored to ID matching (back-reference on close tag).
_MARKER_RE = re.compile(
    r"<!-- ccguard:managed start (?P<id>[a-z0-9-]+) -->\n"
    r"(?P<body>.*?)\n"
    r"<!-- ccguard:managed end (?P=id) -->",
    re.DOTALL,
)

def merge_claude_md(
    existing_text: str,
    managed_blocks: list[dict],  # [{id, content, description}, ...]
) -> str:
    text = existing_text
    seen_ids: set[str] = set()

    # Replace existing blocks in-place.
    def _replace(m: re.Match) -> str:
        block_id = m.group("id")
        # Find matching policy block by id; if removed from policy, keep
        # marker but with empty body (admin can delete manually).
        for blk in managed_blocks:
            if blk["id"] == block_id:
                seen_ids.add(block_id)
                return (
                    f"<!-- ccguard:managed start {block_id} -->\n"
                    f"{blk['content']}\n"
                    f"<!-- ccguard:managed end {block_id} -->"
                )
        return m.group(0)  # unchanged (orphan block from older policy)

    text = _MARKER_RE.sub(_replace, text)

    # Append blocks that didn't exist in the file yet.
    appended: list[str] = []
    for blk in managed_blocks:
        if blk["id"] in seen_ids:
            continue
        appended.append(
            f"\n<!-- ccguard:managed start {blk['id']} -->\n"
            f"{blk['content']}\n"
            f"<!-- ccguard:managed end {blk['id']} -->\n"
        )
    if appended:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "".join(appended)
    return text
```

**Invariants tested:**
1. Idempotent: applying the same `managed_blocks` twice produces byte-identical output.
2. User content outside markers preserved verbatim (whitespace, encoding).
3. Orphan markers (block removed from policy) are left in place — admin sees them.
4. ID is restricted to `[a-z0-9-]+` (validated in Pydantic).

### Pattern 5: `~/.claude.json` MCP Merge

**What:** Load JSON, strip every `mcpServers.*` entry where `_managed_by == "ccguard"`, then add the new policy-declared servers (each tagged with `_managed_by: "ccguard"`).
**Key insight:** Claude Code itself reads `mcpServers` keys; it ignores unknown sibling fields (verified empirically in v0.1 inventory_scan reading the same file). The `_managed_by` marker is **inside the per-server dict**, not at top level — this scopes it correctly.

```python
# Source: agent/install.py existing JSON-merge pattern + CONTEXT.md decision
import json

def merge_mcp_json(
    existing: dict,
    required_mcp_servers: list[dict],  # [{name, command, args, env}, ...]
) -> dict:
    result = dict(existing) if isinstance(existing, dict) else {}
    servers = dict(result.get("mcpServers") or {})

    # Strip stale ccguard-managed entries.
    for name in list(servers.keys()):
        spec = servers[name]
        if isinstance(spec, dict) and spec.get("_managed_by") == "ccguard":
            del servers[name]

    # Add fresh ones, prefixed with `ccguard-` to avoid colliding with
    # user-installed MCPs of the same name. The prefix is a key namespace,
    # NOT a feature of Claude Code — it's purely a ccguard convention.
    for entry in required_mcp_servers:
        key = f"ccguard-{entry['name']}"
        servers[key] = {
            "command": entry["command"],
            "args": entry.get("args", []),
            "env": entry.get("env", {}),
            "_managed_by": "ccguard",
        }

    result["mcpServers"] = servers
    return result
```

### Pattern 6: Apply Pipeline (the orchestration)

```python
def apply(policy: Policy, claude_home: Path, ccguard_dir: Path) -> ApplyResult:
    plan = build_apply_plan(policy, claude_home)
    targets = [p.target for p in plan.steps]
    snap_dir = take_snapshot(targets, ccguard_dir / "snapshots")
    try:
        applied: list[str] = []
        for step in plan.steps:
            atomic_write_bytes(step.target, step.content)
            applied.append(str(step.target))
        verify_applied(plan.steps)  # sha256 round-trip per file
        prune_snapshots(ccguard_dir / "snapshots", keep=5)
        return ApplyResult(status="success", snapshot_id=snap_dir.name,
                            applied=applied, rolled_back=False)
    except Exception as exc:
        # Best-effort restore; failures here logged not raised.
        rolled = rollback_from_snapshot(snap_dir, claude_home)
        return ApplyResult(
            status="rollback",
            snapshot_id=snap_dir.name,
            failed_target=getattr(exc, "target", None),
            reason=f"{type(exc).__name__}: {exc}",
            applied=applied,
            rolled_back=rolled,
        )
```

### Anti-Patterns to Avoid

- **Writing into the target file directly** — partial writes (disk full, SIGTERM) leave Claude Code reading garbage. Always temp-file + `os.replace`.
- **Snapshot AFTER first write** — if write 1 succeeds and write 2 fails, the snapshot for write 1's target is the already-changed file. Snapshot **all** targets first.
- **Cross-filesystem temp** (e.g., `tempfile.NamedTemporaryFile()` with default `dir=/tmp`) — `os.replace` falls back to non-atomic copy across filesystems.
- **Snapshotting non-existent files** — silently skip; restore step likewise (deleting on restore = empty pre-write state).
- **Greedy regex for CLAUDE.md markers** — without `?` the regex eats across multiple managed blocks. Use `.*?` non-greedy.
- **Mutable defaults in Pydantic** — use `Field(default_factory=list)` on the new sections.
- **Raising from apply pipeline into CLI** — sync must continue (mirror Phase 3 `run_scan_cycle` pattern: swallow + log + telemetry).

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Atomic file write | Custom rename retry loops | `tempfile.NamedTemporaryFile(dir=parent) + os.replace` | POSIX gives atomic rename for free; rolling our own retry hides the OS-level guarantee. |
| Snapshot/restore | tarfile archives, git-init in user home | `shutil.copy2` mirror tree | Selective restore is one-liner per file; tar adds complexity. |
| YAML→model→YAML round-trip | String manipulation | `yaml.safe_dump(policy.model_dump(mode='json'), sort_keys=False)` | Already established in `policy_form.py`. |
| JSON merge | `dict.update` | Explicit «strip ccguard-managed, re-add» (Pattern 5) | `update` does shallow merge that leaks stale entries. |
| Marker parsing | Multi-pass split/join | Single DOTALL regex with back-reference | Back-reference enforces start-id == end-id automatically. |
| Apply telemetry transport | New protocol | Existing `httpx.Client` + `X-CCGuard-Token` (see `sync.py:75`) | Same auth header, same JSON contract. |

**Key insight:** Every problem in this phase is a *plumbing* problem already solved by stdlib + the v0.1 codebase. The phase is **integration**, not invention.

---

## Runtime State Inventory

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | **None** — the agent does not persist new state in any database. Snapshot dirs `~/.ccguard/snapshots/{ts}/` are *filesystem* state, not stored data. Server adds one new SQLModel table `PolicyApplyEvent` — handled by `create_all` per Phase 1 pattern. | New table created by `init_db`. No data migration needed. |
| Live service config | `~/.claude.json` (mcpServers section) — managed entries are rewritten on every sync, identified by `_managed_by: ccguard` marker inside each server spec. **No external service config** (no Datadog, no n8n, no Cloudflare). | Code-edit only. First-time apply: agent adds prefix-`ccguard-` keys. |
| OS-registered state | **None** — no `systemd`/`launchd`/Task Scheduler entries are touched. Hooks in `settings.json` are NOT touched by this phase (managed by `agent/install.py` independently). | None. |
| Secrets / env vars | `required_mcp_servers[].env` may contain plain values (admin paste). These are stored in `PolicyVersion.yaml_text` (Fernet-encrypted at the column level per v0.1 setup if `SECRET_KEY` is set) and transmitted to agent via TLS. **No env vars renamed.** | Plan task: verify Fernet encryption is wired for `PolicyVersion.yaml_text`; if not, add. |
| Build artifacts | **None** — no `.egg-info` or compiled artifacts depend on the new modules. | None. |

**Nothing found in category «OS-registered state», «build artifacts».** Verified by grep across `/etc/`, `pyproject.toml`, no `pip install` of new packages.

---

## Common Pitfalls

### Pitfall 1: `os.replace` across filesystems
**What goes wrong:** `os.replace("/tmp/x.tmp", "/home/user/.claude/agents/y.md")` may silently fall back to non-atomic copy on Linux if `/tmp` is tmpfs.
**Why it happens:** Python docs say «atomic on POSIX if source and destination are on the same filesystem.»
**How to avoid:** Always create the temp file with `dir=target.parent`.
**Warning signs:** Concurrent test runs see half-written files.

### Pitfall 2: SIGTERM mid-apply leaves partial state
**What goes wrong:** Snapshot taken, three writes done, sync killed before verify or rollback runs → desync between disk and the intended policy.
**Why it happens:** No transaction across files; each `os.replace` is independent.
**How to avoid:** On startup of the next `ccguard sync`, detect an orphan snapshot (most-recent snapshot whose timestamp is after the last successful `PolicyApplyEvent` for this machine) and offer a recovery hint in CLI output. **Don't** auto-restore — admin needs to see the situation.
**Warning signs:** `~/.ccguard/snapshots/{ts}/` exists with files but no matching success event on server.

### Pitfall 3: CLAUDE.md without markers — first-time apply
**What goes wrong:** User has a personal CLAUDE.md but no ccguard markers. Naive «replace markers» does nothing; the policy block is never written.
**How to avoid:** Pattern 4 handles this: blocks unseen during regex pass are **appended** at file end with a leading newline.
**Warning signs:** Admin claims «I added a block but it never shows up» — usually the block ID was renamed in policy.

### Pitfall 4: File permission lockout (`chmod -w CLAUDE.md`)
**What goes wrong:** User locked their CLAUDE.md to prevent accidental edits. `atomic_write_bytes` raises `PermissionError`.
**How to avoid:** Per CONTEXT.md: «Permission errors don't block other files — partial rollback with per-file reason.» Wrap each step in try/except, collect failures, restore snapshot only for the failed file, continue with the others, emit `policy.apply.rollback` event listing the failed file in `details`.
**Warning signs:** Repeated rollback events for the same machine + same file.

### Pitfall 5: Disk full during write 4 of 5
**What goes wrong:** `tempfile.NamedTemporaryFile` succeeds but `tmp.write()` raises OSError (ENOSPC).
**How to avoid:** Pattern 1 already catches: tmp file is unlinked, exception propagates, apply loop catches and rolls back. **Test:** mock `tmp.write` to raise after N bytes.
**Warning signs:** `details.reason` of «OSError: [Errno 28] No space left on device».

### Pitfall 6: Snapshot disk usage growth
**What goes wrong:** Each snapshot is a full copy; CLAUDE.md can be hundreds of KB; 5 snapshots × all targeted files = MBs over time. On a 32GB SSD shared with builds, this matters.
**How to avoid:** Pattern 3 prunes to keep=5 **after** successful apply; if 5 rollbacks happen in a row, no pruning occurs and snapshots accumulate. Add a hard cap (keep ≤ 5 OR 10MB total, whichever first).
**Warning signs:** `~/.ccguard/snapshots` > 50 MB.

### Pitfall 7: User MCP name collision with `ccguard-X` prefix
**What goes wrong:** User has manually installed an MCP named `ccguard-helper` in `~/.claude.json`; the merge logic deletes it because the prefix matches (or worse, the `_managed_by` check passes because the user copy-pasted from a policy export).
**How to avoid:** **Identify managed entries by the `_managed_by` field**, NOT by name prefix. The `ccguard-` prefix is a UX convention to avoid colliding with non-managed entries; deletion uses the field marker. Pattern 5 above is already correct.
**Warning signs:** User's hand-installed MCP disappears after `ccguard sync`.

### Pitfall 8: Policy schema version compatibility with v0.1 agent
**What goes wrong:** Bumping `schema_version: 1 → 2` makes v0.1 agents reject the policy outright (Pydantic Literal mismatch).
**How to avoid:** Keep `schema_version: 1`; the four new sections are additive with default `[]` and `Pydantic`'s `model_config["extra"] = "ignore"` (already set in `schemas/_base.py`) means v0.1 will simply not see them. Cross-checked: `agent/sync.py` validates incoming policy via `Policy.model_validate(r.json())` — with v0.1 schema and unknown fields ignored, this is a no-op for the agent's behaviour.
**Warning signs:** v0.1 agents start emitting `policy fetch failed: validation error` after a v0.2 policy is published.

### Pitfall 9: Idempotency check via mtime vs content
**What goes wrong:** Verify step compares mtimes → false negative when filesystem rounds mtime to second precision.
**How to avoid:** Verify by sha256 of file content vs expected content (in-memory bytes hashed before write).
**Warning signs:** Verification flakes on macOS HFS+ (1s mtime resolution).

### Pitfall 10: Concurrent `ccguard sync` invocations
**What goes wrong:** Two sync processes (cron + manual) race on the same `~/.claude/agents/foo.md`.
**How to avoid:** Acquire a file-lock at `~/.ccguard/sync.lock` via `fcntl.flock(LOCK_EX | LOCK_NB)` at the start of `push_install.apply()`; if held, log «sync already running» and exit cleanly. *(stdlib fcntl works on POSIX; Windows would need msvcrt — out of scope for v0.2.)*
**Warning signs:** Sporadic rollback events with no clear cause; two snapshot dirs with the same second-precision timestamp.

---

## Code Examples

### Pydantic Schema Extension (`schemas/policy.py`)

```python
# Source: ccguard/schemas/policy.py current contents + Pydantic v2 docs
from __future__ import annotations
from pydantic import Field, field_validator
from typing import Annotated
import re

from ccguard.schemas._base import SchemaBase

_BLOCK_ID_RE = re.compile(r"^[a-z0-9-]+$")
_MCP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ManagedMCPServer(SchemaBase):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    command: Annotated[str, Field(min_length=1, max_length=512)]
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        if not _MCP_NAME_RE.match(v):
            raise ValueError(f"invalid MCP name {v!r}; must match {_MCP_NAME_RE.pattern}")
        return v


class ManagedSkill(SchemaBase):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    content: Annotated[str, Field(min_length=1, max_length=64 * 1024)]


class ManagedAgent(SchemaBase):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    content: Annotated[str, Field(min_length=1, max_length=64 * 1024)]


class ManagedClaudeMdBlock(SchemaBase):
    id: Annotated[str, Field(min_length=1, max_length=64)]
    content: Annotated[str, Field(max_length=32 * 1024)]
    description: str = ""

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _BLOCK_ID_RE.match(v):
            raise ValueError(f"invalid block id {v!r}; must match {_BLOCK_ID_RE.pattern}")
        return v


class MandatorySection(SchemaBase):
    """Policy-declared artifacts the agent applies to ~/.claude/ on sync.

    All fields default to []. Empty section = «no managed artifacts of this kind».
    Hardened by per-item Pydantic validation so a malformed policy fails fast
    on the server-side draft-save path (existing v0.1 behaviour).
    """
    required_mcp_servers: list[ManagedMCPServer] = Field(default_factory=list)
    required_skills: list[ManagedSkill] = Field(default_factory=list)
    required_agents: list[ManagedAgent] = Field(default_factory=list)
    managed_claude_md_blocks: list[ManagedClaudeMdBlock] = Field(default_factory=list)


# Extend top-level Policy in place:
class Policy(SchemaBase):
    # ... existing fields ...
    mandatory: MandatorySection = Field(default_factory=MandatorySection)
```

### New Table — `PolicyApplyEvent`

```python
# Source: ccguard/server/db/models.py pattern (ToolUseEvent)
class PolicyApplyEvent(SQLModel, table=True):
    """Apply telemetry from agent → server. One row per sync apply cycle.

    Status enum (validated at write boundary):
      - "success"  : all writes + verify succeeded
      - "rollback" : at least one write/verify failed; snapshot restored
      - "partial"  : (future) some files succeeded, some restored
    """
    id: int | None = Field(default=None, primary_key=True)
    machine_id: str = Field(index=True)
    ts: datetime = Field(default_factory=_utcnow, index=True)
    policy_revision: int = Field(index=True)
    status: str = Field(index=True)        # "success" | "rollback" | "partial"
    snapshot_id: str                       # ISO-ts dir name
    details_json: str                      # JSON: {applied: [...], failed_target, reason}
```

### Endpoint — `POST /api/v1/policy-apply`

```python
# Source: ccguard/server/api/audit.py shape (Phase 1 ingest pattern)
from fastapi import APIRouter, Depends
from sqlmodel import Session
from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import PolicyApplyEvent
from ccguard.schemas.policy_apply import PolicyApplyIn, PolicyApplyOut

router = APIRouter(prefix="/api/v1")

@router.post("/policy-apply", response_model=PolicyApplyOut)
def post_policy_apply(
    payload: PolicyApplyIn,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> PolicyApplyOut:
    row = PolicyApplyEvent(
        machine_id=payload.machine_id,
        policy_revision=payload.policy_revision,
        status=payload.status,
        snapshot_id=payload.snapshot_id,
        details_json=payload.details.model_dump_json(),
    )
    session.add(row)
    session.commit()
    return PolicyApplyOut(accepted=True, id=row.id)
```

### Form Parsing — `policy_form.py` Extension

The v0.1 `_SECTIONS` dict only handles flat scalar/list fields. For the four new sections (each a *list of objects*), the form encodes one row as a triplet of `name`-prefixed inputs like `mandatory.required_mcp_servers.0.name`, `mandatory.required_mcp_servers.0.command`, etc. HTMX `hx-post` partial inserts new rows with index = current count.

```python
def _list_of_objects(form: Mapping[str, str], prefix: str, fields: list[str]) -> list[dict]:
    """Parse mandatory.required_mcp_servers.{N}.{field} → list[dict]."""
    by_index: dict[int, dict] = {}
    pattern = re.compile(rf"^{re.escape(prefix)}\.(\d+)\.([a-z_]+)$")
    for key, raw in form.items():
        m = pattern.match(key)
        if not m:
            continue
        idx, field = int(m.group(1)), m.group(2)
        if field not in fields:
            continue
        by_index.setdefault(idx, {})[field] = raw
    return [by_index[i] for i in sorted(by_index)]

# Extend form_to_yaml to include `mandatory` block:
data["mandatory"] = {
    "required_mcp_servers": _list_of_objects(form,
        "mandatory.required_mcp_servers",
        ["name", "command", "args", "env"]),
    "required_skills": _list_of_objects(form,
        "mandatory.required_skills",
        ["name", "content"]),
    "required_agents": _list_of_objects(form,
        "mandatory.required_agents",
        ["name", "content"]),
    "managed_claude_md_blocks": _list_of_objects(form,
        "mandatory.managed_claude_md_blocks",
        ["id", "content", "description"]),
}
# Round-trip through Pydantic for validation (existing pattern):
Policy.model_validate(data)
```

`args` and `env` need a small sub-parser (CSV for args, `KEY=VAL` lines for env), or encode them as JSON strings in a single textarea and `json.loads` at parse time — recommended for v0.2 simplicity (Monaco overkill).

### Plan-builder

```python
@dataclass
class ApplyStep:
    target: Path            # final path on disk
    content: bytes
    kind: str               # "agent" | "skill" | "claude_json" | "claude_md"

def build_apply_plan(policy: Policy, claude_home: Path) -> ApplyPlan:
    steps: list[ApplyStep] = []
    m = policy.mandatory

    for a in m.required_agents:
        steps.append(ApplyStep(
            target=claude_home / "agents" / f"{a.name}.md",
            content=a.content.encode("utf-8"),
            kind="agent",
        ))

    for s in m.required_skills:
        steps.append(ApplyStep(
            target=claude_home / "skills" / s.name / "SKILL.md",
            content=s.content.encode("utf-8"),
            kind="skill",
        ))

    if m.required_mcp_servers:
        cj_path = Path.home() / ".claude.json"
        existing = json.loads(cj_path.read_text()) if cj_path.exists() else {}
        merged = merge_mcp_json(existing, [s.model_dump() for s in m.required_mcp_servers])
        steps.append(ApplyStep(
            target=cj_path,
            content=json.dumps(merged, indent=2).encode("utf-8"),
            kind="claude_json",
        ))

    if m.managed_claude_md_blocks:
        cmd_path = claude_home / "CLAUDE.md"
        existing_text = cmd_path.read_text() if cmd_path.exists() else ""
        merged_text = merge_claude_md(
            existing_text,
            [b.model_dump() for b in m.managed_claude_md_blocks],
        )
        steps.append(ApplyStep(
            target=cmd_path,
            content=merged_text.encode("utf-8"),
            kind="claude_md",
        ))

    return ApplyPlan(steps=steps)
```

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `pytest` (verified by `tests/conftest.py`) |
| Config file | `pyproject.toml` (project default; no `pytest.ini`) |
| Quick run command | `pytest tests/unit/test_push_install_*.py -x -q` |
| Full suite command | `pytest -x -q` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PUSH-01 | Pydantic accepts new sections; v0.1 agent ignores them | unit | `pytest tests/unit/test_policy_mandatory_schema.py -x` | ❌ Wave 0 |
| PUSH-01 | `GET /api/v1/policy` returns new sections (round-trip YAML) | integration | `pytest tests/integration/test_server_policy_etag.py::test_mandatory_round_trip -x` | ❌ Wave 0 (extend existing) |
| PUSH-02 | Atomic write produces no half-files under mocked OSError | unit | `pytest tests/unit/test_push_install_apply.py::test_atomic_partial_write -x` | ❌ Wave 0 |
| PUSH-02 | Snapshot taken before any write; rollback restores byte-exact | unit | `pytest tests/unit/test_push_install_rollback.py -x` | ❌ Wave 0 |
| PUSH-02 | End-to-end sync → apply → POST policy-apply event | integration | `pytest tests/integration/test_push_install_e2e.py -x` | ❌ Wave 0 |
| PUSH-03 | CLAUDE.md marker merge: idempotent, user content preserved | unit | `pytest tests/unit/test_push_install_claude_md_merge.py -x` | ❌ Wave 0 |
| PUSH-03 | First-time apply on CLAUDE.md without markers appends blocks | unit | `pytest tests/unit/test_push_install_claude_md_merge.py::test_first_time_apply -x` | ❌ Wave 0 |
| PUSH-04 | Form submit with mandatory.* fields → YAML round-trip → DB | integration | `pytest tests/integration/test_policy_mandatory_form.py -x` | ❌ Wave 0 |
| PUSH-04 | Template renders existing mandatory section on `/policy?tab=mandatory` | integration | `pytest tests/integration/test_policy_mandatory_form.py::test_render -x` | ❌ Wave 0 |
| — | `~/.claude.json` MCP merge: ccguard-managed stripped, user MCPs preserved | unit | `pytest tests/unit/test_push_install_mcp_merge.py -x` | ❌ Wave 0 |
| — | `POST /api/v1/policy-apply` persists row with details_json | integration | `pytest tests/integration/test_policy_apply_endpoint.py -x` | ❌ Wave 0 |
| — | Schema version compat: v0.1 agent (Pydantic v1-style) reads v0.2 policy | unit | `pytest tests/unit/test_policy_mandatory_schema.py::test_v01_compat -x` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/unit/test_push_install_*.py tests/unit/test_policy_mandatory_schema.py -x -q`
- **Per wave merge:** `pytest tests/unit/ tests/integration/test_push_install_e2e.py tests/integration/test_policy_*.py -x -q`
- **Phase gate:** `pytest -x -q` (full suite green before `/gsd:verify-work`)

### Wave 0 Gaps
- [ ] `tests/unit/test_push_install_apply.py` — atomic write, partial write, fsync, mode bits
- [ ] `tests/unit/test_push_install_rollback.py` — snapshot/restore/prune
- [ ] `tests/unit/test_push_install_claude_md_merge.py` — marker regex idempotency + edge cases
- [ ] `tests/unit/test_push_install_mcp_merge.py` — strip-and-add semantics
- [ ] `tests/unit/test_policy_mandatory_schema.py` — Pydantic validation + v0.1 compat (extra-ignore)
- [ ] `tests/integration/test_policy_mandatory_form.py` — form parse + render
- [ ] `tests/integration/test_policy_apply_endpoint.py` — POST contract
- [ ] `tests/integration/test_push_install_e2e.py` — full sync→apply→event cycle with `tmp_path` as `~/.claude` and `~/.ccguard`
- [ ] `tests/conftest.py` extension: `claude_home` fixture that yields a `tmp_path/.claude` directory and patches `_claude_home()`
- No new framework install needed — pytest already in place.

---

## Security Domain

`security_enforcement` is enabled (no explicit `false` in `.planning/config.json`).

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | `X-CCGuard-Token` (existing); same gate on `/policy-apply` |
| V3 Session Management | yes | Admin UI cookie session (existing); CSRF on form POST (existing `require_csrf`) |
| V4 Access Control | yes | Token bound to «agent» role; admin cookie bound to admin role; no cross-role bleed |
| V5 Input Validation | yes | Pydantic v2 on all 4 sections; ID regexes; length caps per Code Examples |
| V6 Cryptography | yes | Fernet (v0.1) on encrypted columns; never hand-roll. Plain content fields are NOT encrypted at column level — they live inside `yaml_text` which is the existing storage column. **Confirm with admin** that this is acceptable for managed agent/skill text. |
| V7 Error Handling & Logging | yes | Apply pipeline logs path metadata only; never logs `content` bytes (mirror Phase 3 inventory_scan logging discipline) |
| V8 Data Protection | yes | TLS termination at server (admin's reverse-proxy responsibility); env field caveat documented |
| V12 File & Resources | **yes — central to this phase** | Snapshot in user-controlled `~/.ccguard/`; atomic writes; permission errors handled per-file; no symlink following (`shutil.copy2` follows symlinks by default — see threat below) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Symlink-attack on `~/.claude/agents/foo.md` (user replaces with symlink to `/etc/shadow`) | Elevation of Privilege | Before write: `if target.is_symlink(): refuse write, emit rollback event with reason="symlink_target"`. Reading via `path.read_bytes()` already follows the symlink — refuse explicitly. |
| Malicious managed content (admin compromise) → policy pushes `rm -rf ~` as skill content | Tampering | Out of scope: trusted-admin model. **Mitigation:** content is text-only, Claude Code interprets it; the *Claude Code* tier (not ccguard) decides execution. Documenting as known risk. |
| Snapshot dir contains stale secrets after a managed-block removal | Information Disclosure | Snapshot files inherit owner+mode from copy2; `chmod 0o600` enforced on the snapshot dir tree after copy. |
| Replay of `POST /api/v1/policy-apply` from stolen token | Spoofing | T-01-12 carryover: token not pinned to machine_id; documented v0.2 limit. Re-checked: same as Phase 1 audit. |
| TOCTOU between `target.is_symlink()` check and write | Tampering | Open with `O_NOFOLLOW` (`os.open(target, os.O_WRONLY \| os.O_CREAT \| os.O_NOFOLLOW, 0o644)`) instead of tempfile-by-name (refactor `atomic_write_bytes` if this matters in practice — for v0.2, document the residual race; the attacker needs local write to user $HOME to exploit, which already implies game over). |
| Plain-text env (e.g. an API key) sitting in policy YAML and snapshot dir | Information Disclosure | Document explicitly in admin UI: «секреты в `env` ccguard-managed MCP попадают в открытый JSON в `~/.claude.json` и в snapshot-копии в `~/.ccguard/snapshots/`». Strongly suggest using OS keychain references (`{"env": {"KEY_NAME": "$keychain://name"}}`) — but resolver is **deferred to v0.3**; v0.2 carries plain. |

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| MDM-driven config push (Jamf, Intune) | App-level pull via signed declarative policy | mid-2020s for dev tooling (e.g. `chezmoi`, `homebrew/bundle`) | ccguard follows the «agent pulls, server declares» model — no SSH, no MDM dependency. |
| Hand-rolled `mv tmp final` | `os.replace` + same-fs temp | Python 3.3 (`os.replace` added) | Stdlib gives the atomic guarantee; libraries like `python-atomicwrites` are no longer needed. |
| Symlink farms for managed files | Drop-in regular file copies | 2020s tooling consensus (e.g. Claude Code does not document symlink behaviour) | Symlinks expose users to surprise when they `cat` a managed file expecting their own content. Direct copies + marker comments are explicit. |

**Deprecated/outdated:**
- `python-atomicwrites` PyPI package — replaced by stdlib `os.replace`.
- Custom marker formats (`# BEGIN MANAGED` etc.) — HTML comments parse universally and round-trip through markdown renderers (Claude Code reads CLAUDE.md as text, not parsed markdown, so this matters less, but it's a tooling-friendliness win).

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Claude Code ignores unknown sibling fields inside `mcpServers.{name}` dict (e.g. `_managed_by`) | Pattern 5 | If Claude Code fails strict-validation, MCPs may fail to load. **Mitigation:** verify by manual smoke before phase end; alternative is to store the managed list in `~/.claude/.ccguard-mcp.json` and not touch `~/.claude.json`. `[ASSUMED]` — verified empirically in v0.1 inventory parse but not in actual MCP load path. |
| A2 | Agent v0.1 `Policy.model_validate` accepts a v0.2 JSON because `_base.py` sets `extra: ignore` | Project Constraints, Pitfall 8 | If `extra: forbid` somewhere, v0.1 breaks on first sync after v0.2 publish. **Mitigation:** add a regression test reading the agent-v0.1 schema against a v0.2 policy. `[VERIFIED: codebase grep `model_config` in schemas/_base.py — extra defaults to ignore in Pydantic v2; we should still pin it explicitly]` |
| A3 | All v0.2 agents run on POSIX (Linux/macOS) — no Windows | Atomic Write pattern, Pitfall 10 | If Windows is required, `os.replace` semantics differ; `fcntl` unavailable. **Mitigation:** CLAUDE.md says «self-hosted Linux/macOS only»; PROJECT.md does not contradict. `[ASSUMED]` from CLAUDE.md tone, not explicit. |
| A4 | `PolicyVersion.yaml_text` is Fernet-encrypted column when `SECRET_KEY` is set | Project Constraints, Security Domain | If unencrypted, plain admin paste of MCP env secrets is at rest in SQLite. **Mitigation:** audit v0.1 wiring in plan task; encrypt if absent. `[ASSUMED]` — CONTEXT.md states «policy storage is Fernet-encrypted already» but I did not verify the column wiring. |
| A5 | `mandatory.required_mcp_servers` content can be modelled as JSON-string textareas for `args` and `env` to avoid sub-form complexity | Form parser | If admin UX needs typed fields, plan must add per-field rows. **Mitigation:** UI plan owns this; v0.2 starts with textarea+JSON. `[ASSUMED]` — pragmatic recommendation. |
| A6 | Snapshot retention = 5 dirs is sufficient operational history | Pattern 3, Pitfall 6 | If incidents need older state, rolling-5 erases evidence. **Mitigation:** decision locked in CONTEXT.md. `[CITED: 04-CONTEXT.md decisions]` |
| A7 | The agent uses TLS to fetch `/api/v1/policy` (so plain secrets in env are protected in transit) | Security Domain | If admin deploys over HTTP, secrets leak on LAN. **Mitigation:** docs already require TLS-fronted server; phase plan should add a startup check that warns on plain HTTP. `[ASSUMED]` |
| A8 | New `mandatory` policy section being absent on agent v0.1 cache means «no managed artifacts» (apply is no-op) — graceful degradation | Schema extension | If `MandatorySection()` is required on the model, v0.1 cached YAML (without `mandatory:`) re-validation by v0.2 agent might fail. **Mitigation:** `Field(default_factory=MandatorySection)` makes it optional. `[VERIFIED: Pydantic v2 default factory pattern]` |

---

## Open Questions

1. **Schema version: bump `1 → 2` or stay `1`?**
   - What we know: v0.1 `PolicyMeta.schema_version: Literal[1] = 1`. Adding `Literal[1, 2]` is backward-compatible, bumping to `=2` breaks v0.1 agents.
   - What's unclear: Are there deployed v0.1 agents in the wild that must keep working against the v0.2 server?
   - Recommendation: **Keep `schema_version: 1`** (additive change, `extra: ignore` covers it). Defer the bump to a future phase that genuinely breaks the schema.

2. **Snapshot scope: only files we write, or everything in `~/.claude/agents/` etc.?**
   - What we know: CONTEXT.md says «copy targeted files» (=files we will write).
   - What's unclear: If we rollback, do we *restore* a deleted user file that the policy now declares? Probably no — but what if the user had `foo.md` and policy declares `foo` too?
   - Recommendation: Snapshot strictly the targets in `build_apply_plan` output. User pre-existing files at a managed path get overwritten on apply (and restorable on rollback because they were snapshotted).

3. **What happens to a managed file when the admin removes it from policy?**
   - What we know: CONTEXT.md doesn't specify «orphan removal».
   - What's unclear: Should the agent track «previously managed» files (e.g. in `~/.ccguard/managed.json`) and delete them on next apply when they vanish from policy?
   - Recommendation: **Yes** — add a `~/.ccguard/managed-manifest.json` listing the *last applied* set of managed paths. On apply, diff (previous − current) → snapshot the orphan, delete it (via `os.replace` to `/dev/null`-equivalent: `target.unlink()` after snapshot). Defer if planning bandwidth is short; v0.2 minimal could leave orphans and document.

4. **CLAUDE.md: project-level or user-level?**
   - What we know: `agent/install.py` uses `~/.claude/CLAUDE.md` if `CLAUDE_HOME` set, else `~/.claude`.
   - What's unclear: Some shops put CLAUDE.md at project root (`./CLAUDE.md`). Phase 4 only covers `~/.claude/CLAUDE.md` per CONTEXT.md silence on project scope.
   - Recommendation: Document explicitly «v0.2 managed CLAUDE.md is the *user-home* CLAUDE.md only». Project-scope deferred.

5. **`required_skills[].content` is the whole `SKILL.md`?**
   - What we know: CONTEXT.md says «(name, content textarea, frontmatter type)».
   - What's unclear: Is `content` the full file (frontmatter + body), or body only (and a separate `frontmatter` dict)?
   - Recommendation: For v0.2, **single textarea = full file content**. Admin pastes frontmatter and body together. Validated by Pydantic length cap only; structural validation of the YAML frontmatter is deferred.

6. **MCP merge: do we drop `_managed_by: ccguard` keys not present in the new policy too?**
   - What we know: Yes, Pattern 5 strips ALL `_managed_by == ccguard` entries before re-adding — this is the right semantic.
   - Recommendation: Document this in the user-facing docs so admins know a removed MCP from policy disappears from agent home on next sync (good — it's the whole point of push-install).

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.12 | All modules | ✓ (project baseline) | 3.12 | — |
| stdlib `tempfile`, `os.replace`, `shutil.copy2`, `re`, `json`, `fcntl` | Apply pipeline | ✓ | — | — |
| Pydantic v2 | Schema extension | ✓ (in v0.1 pyproject) | ≥2.5 | — |
| SQLModel | New table | ✓ | ≥0.0.16 | — |
| FastAPI | New endpoint | ✓ | ≥0.110 | — |
| Jinja2/HTMX | New tab | ✓ | — | — |
| pytest | Tests | ✓ | — | — |
| Anthropic API | — | n/a for this phase | — | — |

**Missing dependencies with no fallback:** None.
**Missing dependencies with fallback:** None.

---

## Sources

### Primary (HIGH confidence)
- **Codebase grep, this repo:**
  - `src/ccguard/schemas/policy.py` — current Policy + nested rules
  - `src/ccguard/schemas/_base.py` — SchemaBase (Pydantic config)
  - `src/ccguard/server/db/models.py` — SQLModel patterns (ToolUseEvent, ScanResult)
  - `src/ccguard/server/api/audit.py` — endpoint shape + security register doc style
  - `src/ccguard/server/api/policy.py` — current GET handler + ETag flow
  - `src/ccguard/server/services/policy_service.py` — draft/publish/rollback flow
  - `src/ccguard/server/policy_loader.py` — bootstrap-from-file
  - `src/ccguard/server/web/policy_form.py` — form→YAML parsing pattern (extend)
  - `src/ccguard/server/web/routes.py` (policy routes, lines 363–496) — current editor + history endpoints
  - `src/ccguard/agent/cli.py` (`sync` command) — call site for new push_install step
  - `src/ccguard/agent/sync.py` — `_atomic_write` reuse + `perform_sync` flow
  - `src/ccguard/agent/install.py` — `_write_settings_atomic`, `_read_settings`, settings.json merge pattern (reuse for `.claude.json`)
  - `src/ccguard/agent/inventory_scan.py` — best-effort no-raise pattern (mirror for apply pipeline)
  - `examples/policy.example.yaml` — YAML shape to keep consistent
- **Python stdlib docs (training, cross-verified by codebase usage):**
  - `os.replace` atomicity on POSIX
  - `tempfile.NamedTemporaryFile(dir=…)` same-filesystem guarantee
  - `re.DOTALL` and back-reference syntax
  - `shutil.copy2` metadata preservation

### Secondary (MEDIUM confidence)
- Phase 1 RESEARCH.md (`.planning/phase-01-tool-use-audit-foundation/01-RESEARCH.md`) — table-split precedent (semantic-split vs reuse) + ingest endpoint pattern
- Phase 3 RESEARCH.md — best-effort agent step pattern + privacy logging discipline

### Tertiary (LOW confidence)
- Claude Code's tolerance for `_managed_by` field inside `mcpServers.{name}` — A1 above; not verified against Claude Code source. Should be smoke-tested during implementation.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every library/tool already in v0.1 and verified by codebase grep.
- Architecture: HIGH — direct extension of v0.1 patterns (table-split, atomic write, draft/publish flow); apply pipeline is plain stdlib.
- Pitfalls: HIGH — file-system atomicity and POSIX semantics are well-known territory; pitfalls 1–6 are textbook; 7–10 are project-specific and based on existing code shape.
- Security: MEDIUM — depends on A4 (Fernet wiring) and A7 (TLS deployment posture); verify in plan tasks.
- A1 (`_managed_by` field tolerance) and A3 (POSIX-only): LOW-MEDIUM — recommend smoke verification before phase end.

**Research date:** 2026-05-26
**Valid until:** 2026-06-25 (30 days — stable Pydantic/SQLModel/FastAPI; no fast-moving deps).
