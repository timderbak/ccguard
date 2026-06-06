# Hooks TOFU Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Symmetric counterpart to MCP rug pull — detect drift in Claude Code hook shim files via TOFU baseline (event_name + matcher + command_string + sha256 of shim file content). Bootstrap-banner workflow eliminates noise on first sync.

**Architecture:** Agent reads + hashes shim file content; server maintains `HookBaseline` table per machine with composite fingerprint; `hook_baseline_service.update_and_detect` runs on every inventory POST and emits findings for new/drifted/unreadable cases; machine_detail UI gets bootstrap banner + drift cards + status badges that mirror the existing MCP rug-pull pattern.

**Tech Stack:** Python 3.12, FastAPI, SQLModel, SQLite WAL, HTMX + Jinja2, pytest. Branch: `feat/hooks-tofu-baseline` off master.

**Spec:** `docs/superpowers/specs/2026-06-01-hooks-tofu-baseline-design.md`

---

## File Structure

**Created:**
- `src/ccguard/server/services/hook_baseline_service.py` — fingerprint + detection + accept-flow
- `src/ccguard/server/web/templates/components/_hook_baseline_banner.html` — bootstrap banner partial
- `src/ccguard/server/web/templates/components/_hook_drift_cards.html` — drift findings partial
- `tests/unit/test_hook_fingerprint.py`
- `tests/unit/test_hook_baseline_service.py`
- `tests/unit/test_hook_baseline_accept_flow.py`
- `tests/unit/test_hook_scan_file_hash.py`
- `tests/integration/test_machine_detail_hook_baseline_ui.py`
- `tests/integration/test_inventory_emits_hook_findings.py`

**Modified:**
- `src/ccguard/schemas/inventory.py` — extend `HookEntry`
- `src/ccguard/agent/scan/hooks.py` — extract shim path, compute file hash
- `src/ccguard/server/db/models.py` — add `HookBaseline` table
- `src/ccguard/server/db/session.py` — DDL migration for the new table
- `src/ccguard/server/api/inventory.py` — wire `hook_baseline_service.update_and_detect`
- `src/ccguard/server/web/routes.py` — 3 new POST endpoints + machine_detail context
- `src/ccguard/server/web/templates/machine_detail.html` — include the two new partials + status badges
- `tests/_snapshots/machine_detail_with_risk.html` — regenerated under `CCGUARD_UPDATE_SNAPSHOTS=1`

---

## Task 0: Branch + venv

**Files:** none — preflight only.

- [ ] **Step 1: Switch to branch**

```bash
git checkout master
git pull origin master
git checkout -b feat/hooks-tofu-baseline
```

- [ ] **Step 2: Verify venv active and pytest works**

```bash
source .venv/bin/activate
pytest --version
```

Expected: `pytest 9.x.x` printed.

- [ ] **Step 3: Establish baseline of failing tests**

```bash
pytest tests/ --ignore=tests/e2e -q 2>&1 | tail -5
```

Expected: `1194 passed, 1 failed` (the failure is the pre-existing flaky `test_audit_1000_events_render_table_and_timeline` — not something we introduce). Anything else means we should investigate before starting.

---

## Task 1: Extend `HookEntry` schema with file-content fields

**Files:**
- Modify: `src/ccguard/schemas/inventory.py`
- Test: `tests/unit/test_hook_scan_file_hash.py` (new file, but most assertions land in Task 2)

- [ ] **Step 1: Write the failing test**

Append to (create) `tests/unit/test_hook_scan_file_hash.py`:

```python
"""Verify HookEntry carries file_path, file_content_hash, file_unreadable_reason."""

from ccguard.schemas.inventory import HookEntry


def test_hook_entry_accepts_new_file_fields():
    entry = HookEntry(
        event_name="PreToolUse",
        matcher="Bash",
        command="/usr/local/bin/python /opt/script.py",
        source="/root/.claude/settings.json",
        is_ccguard_owned=False,
        file_path="/opt/script.py",
        file_content_hash="abc123def456",
        file_unreadable_reason=None,
    )
    assert entry.file_path == "/opt/script.py"
    assert entry.file_content_hash == "abc123def456"
    assert entry.file_unreadable_reason is None


def test_hook_entry_defaults_new_fields_to_none():
    entry = HookEntry(event_name="PreToolUse")
    assert entry.file_path is None
    assert entry.file_content_hash is None
    assert entry.file_unreadable_reason is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_hook_scan_file_hash.py -v
```

Expected: `ValidationError: Extra inputs are not permitted` (because pydantic strict mode rejects unknown fields).

- [ ] **Step 3: Add fields to `HookEntry`**

In `src/ccguard/schemas/inventory.py`, find the `class HookEntry(...)` block and append three Optional fields after the existing ones (preserve every existing field — they were added in the prior UX fix commit):

```python
class HookEntry(BaseModel):
    # ... existing fields (event_name, matcher, command, source, is_ccguard_owned) ...

    file_path: str | None = None
    file_content_hash: str | None = None
    file_unreadable_reason: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_hook_scan_file_hash.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/schemas/inventory.py tests/unit/test_hook_scan_file_hash.py
git commit -m "feat(schema): HookEntry gets file_path/file_content_hash/file_unreadable_reason"
```

---

## Task 2: Agent scanner — extract shim path and hash content

**Files:**
- Modify: `src/ccguard/agent/scan/hooks.py`
- Test: `tests/unit/test_hook_scan_file_hash.py`

- [ ] **Step 1: Write the failing tests (append)**

Append to `tests/unit/test_hook_scan_file_hash.py`:

```python
import hashlib
from pathlib import Path

from ccguard.agent.scan.hooks import _extract_shim_path, _hash_shim_file


def test_extract_shim_path_picks_script_arg():
    # "python /opt/script.py --flag" → "/opt/script.py"
    assert _extract_shim_path("/usr/local/bin/python /opt/script.py --flag") == "/opt/script.py"


def test_extract_shim_path_returns_none_for_inline_bash():
    # "bash -c 'echo hi'" → no real file
    assert _extract_shim_path("bash -c 'echo hi'") is None


def test_extract_shim_path_handles_quoted_paths():
    assert _extract_shim_path('python "/opt/some space/script.py"') == "/opt/some space/script.py"


def test_extract_shim_path_returns_first_existing_path_token(tmp_path):
    script = tmp_path / "shim.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    cmd = f"sh {script} arg1"
    assert _extract_shim_path(cmd) == str(script)


def test_hash_shim_file_returns_sha256_first_32(tmp_path):
    f = tmp_path / "x.py"
    f.write_bytes(b"hello world\n")
    expected = hashlib.sha256(b"hello world\n").hexdigest()[:32]
    h, reason = _hash_shim_file(str(f))
    assert h == expected
    assert reason is None


def test_hash_shim_file_missing(tmp_path):
    h, reason = _hash_shim_file(str(tmp_path / "nope.py"))
    assert h is None
    assert reason == "missing"


def test_hash_shim_file_too_large(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * (300 * 1024))  # > 256 KB cap
    h, reason = _hash_shim_file(str(f))
    assert h is None
    assert reason == "too_large"


def test_hash_shim_file_permission_denied(tmp_path, monkeypatch):
    import builtins
    f = tmp_path / "locked.py"
    f.write_text("x")

    real_open = builtins.open
    def fake_open(path, *args, **kwargs):
        if str(path) == str(f):
            raise PermissionError("denied")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", fake_open)

    h, reason = _hash_shim_file(str(f))
    assert h is None
    assert reason == "permission_denied"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/unit/test_hook_scan_file_hash.py -v
```

Expected: `ImportError: cannot import name '_extract_shim_path' ...` on the first new test.

- [ ] **Step 3: Implement helpers in `src/ccguard/agent/scan/hooks.py`**

Add near the top of the file (after existing imports):

```python
import hashlib
import shlex
from pathlib import Path

_SHIM_HASH_BYTE_CAP = 256 * 1024  # 256 KB


def _extract_shim_path(command: str) -> str | None:
    """Return the first non-flag token in `command` that refers to an existing file.

    Used to locate the shim/script that the hook actually executes so we can
    fingerprint its content. Returns None when nothing in the command looks
    like a file path on disk (inline `bash -c`, builtins, etc).
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    for tok in tokens:
        if tok.startswith("-"):
            continue
        # Only accept tokens that name a real file. Avoids false positives like
        # "bash", "python", "node" (which exist on $PATH but aren't shims).
        if "/" in tok and Path(tok).is_file():
            return tok
    return None


def _hash_shim_file(path: str) -> tuple[str | None, str | None]:
    """Return (sha256_hex32, reason_or_None).

    reason ∈ {"missing", "permission_denied", "too_large"} when hash is None.
    """
    try:
        p = Path(path)
        if not p.exists():
            return None, "missing"
        size = p.stat().st_size
        if size > _SHIM_HASH_BYTE_CAP:
            return None, "too_large"
        with open(p, "rb") as f:
            data = f.read(_SHIM_HASH_BYTE_CAP)
    except PermissionError:
        return None, "permission_denied"
    except OSError:
        return None, "missing"
    return hashlib.sha256(data).hexdigest()[:32], None
```

- [ ] **Step 4: Wire helpers into existing hook-parsing code path**

Find the place in `src/ccguard/agent/scan/hooks.py` where `HookEntry(...)` is constructed (added in the UX-fix commit). At the construction site, before `HookEntry(...)`, compute:

```python
shim_path = _extract_shim_path(command) if command else None
file_hash: str | None = None
unreadable: str | None = None
if shim_path is not None:
    file_hash, unreadable = _hash_shim_file(shim_path)
```

Then pass `file_path=shim_path, file_content_hash=file_hash, file_unreadable_reason=unreadable` to the `HookEntry(...)` call.

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/unit/test_hook_scan_file_hash.py -v
```

Expected: 9 passed.

- [ ] **Step 6: Run the existing hook-scan test suite to confirm no regression**

```bash
pytest tests/unit/test_hook_scan_extracts_details.py tests/unit/test_settings_sources_inventory.py -v
```

Expected: all green (these existed before and exercise the same module).

- [ ] **Step 7: Commit**

```bash
git add src/ccguard/agent/scan/hooks.py tests/unit/test_hook_scan_file_hash.py
git commit -m "feat(agent): scanner extracts shim path + sha256(file_content)"
```

---

## Task 3: Server model `HookBaseline` + DDL

**Files:**
- Modify: `src/ccguard/server/db/models.py`
- Modify: `src/ccguard/server/db/session.py`
- Test: `tests/unit/test_hook_baseline_service.py` (kicks off; only schema-level checks here)

- [ ] **Step 1: Write the failing test (new file)**

Create `tests/unit/test_hook_baseline_service.py`:

```python
"""HookBaseline model + DDL + fingerprint smoke tests."""

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from ccguard.server.db.models import HookBaseline
from ccguard.server.db.session import init_db


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite://", echo=False, connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as s:
        yield s


def test_hook_baseline_row_round_trip(session):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row = HookBaseline(
        machine_id=1,
        event_name="PreToolUse",
        matcher="Bash",
        command_string="python /opt/script.py",
        file_path="/opt/script.py",
        file_content_hash="aaaa",
        fingerprint="ffff",
        status="pending",
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(row)
    session.commit()
    got = session.exec(select(HookBaseline)).one()
    assert got.machine_id == 1
    assert got.status == "pending"
    assert got.fingerprint == "ffff"
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest tests/unit/test_hook_baseline_service.py::test_hook_baseline_row_round_trip -v
```

Expected: `ImportError: cannot import name 'HookBaseline' from 'ccguard.server.db.models'`.

- [ ] **Step 3: Add the model**

Append to `src/ccguard/server/db/models.py` (after the existing `MCPServerBaseline` definition for symmetry — find it as a reference):

```python
class HookBaseline(SQLModel, table=True):
    """TOFU baseline for Claude Code hooks per machine.

    A row = one "slot" in settings.json (unique by machine + event + matcher + command).
    fingerprint = sha256(event_name + matcher + command_string + file_content_hash).
    status transitions: pending → active (admin accept) → accepted_drift (on re-accept).
    """

    __tablename__ = "hook_baselines"

    id: int | None = Field(default=None, primary_key=True)
    machine_id: int = Field(index=True, foreign_key="machines.id")

    event_name: str = Field(index=True)
    matcher: str = Field(default="")
    command_string: str

    file_path: str | None = None
    file_content_hash: str | None = None
    fingerprint: str = Field(index=True)

    status: str = Field(default="pending")  # pending|active|accepted_drift|missing|removed

    first_seen_at: datetime
    last_seen_at: datetime
    accepted_at: datetime | None = None
    accepted_by: str | None = None
```

(`Field`, `SQLModel`, `datetime` are already imported in this file — verify before saving.)

- [ ] **Step 4: Add DDL composite UNIQUE in `db/session.py`**

In `src/ccguard/server/db/session.py`, find the place where the `mcp_server_baselines` composite index/uniqueness is created via `op.execute("CREATE ... IF NOT EXISTS ...")` or similar in `init_db`. Add immediately below it:

```python
conn.exec_driver_sql(
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_hook_baseline_slot "
    "ON hook_baselines (machine_id, event_name, matcher, command_string)"
)
```

If the pattern in `init_db` uses a different idiom (e.g. SQLAlchemy `Index`), follow the existing form. The intent: composite UNIQUE on `(machine_id, event_name, matcher, command_string)`.

- [ ] **Step 5: Run test to verify it passes**

```bash
pytest tests/unit/test_hook_baseline_service.py::test_hook_baseline_row_round_trip -v
```

Expected: 1 passed.

- [ ] **Step 6: Run the full prior suite to confirm no breakage from DDL**

```bash
pytest tests/ --ignore=tests/e2e -q 2>&1 | tail -3
```

Expected: same count as baseline (Task 0 step 3) plus 1 (new passing test).

- [ ] **Step 7: Commit**

```bash
git add src/ccguard/server/db/models.py src/ccguard/server/db/session.py tests/unit/test_hook_baseline_service.py
git commit -m "feat(db): HookBaseline model + composite UNIQUE on slot"
```

---

## Task 4: `compute_fingerprint` helper

**Files:**
- Create: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_fingerprint.py`

- [ ] **Step 1: Write the failing tests (new file)**

Create `tests/unit/test_hook_fingerprint.py`:

```python
"""compute_fingerprint: deterministic four-field sha256 with None-as-empty."""

from ccguard.server.services.hook_baseline_service import compute_fingerprint


def test_fingerprint_is_deterministic():
    fp1 = compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "abc")
    fp2 = compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "abc")
    assert fp1 == fp2
    assert len(fp1) == 64  # full sha256 hex


def test_fingerprint_changes_when_event_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", "abc")
    b = compute_fingerprint("PostToolUse", "Bash", "cmd", "abc")
    assert a != b


def test_fingerprint_changes_when_matcher_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", "abc")
    b = compute_fingerprint("PreToolUse", "Write", "cmd", "abc")
    assert a != b


def test_fingerprint_changes_when_command_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd1", "abc")
    b = compute_fingerprint("PreToolUse", "Bash", "cmd2", "abc")
    assert a != b


def test_fingerprint_changes_when_file_content_hash_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", "old")
    b = compute_fingerprint("PreToolUse", "Bash", "cmd", "new")
    assert a != b


def test_fingerprint_none_file_hash_is_stable():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", None)
    b = compute_fingerprint("PreToolUse", "Bash", "cmd", None)
    assert a == b
    # None must NOT equal empty file_hash "" — they're semantically distinct
    # (None = couldn't read, "" = inline cmd with no file). Spec § Граничные случаи.
    c = compute_fingerprint("PreToolUse", "Bash", "cmd", "")
    assert a != c
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest tests/unit/test_hook_fingerprint.py -v
```

Expected: `ModuleNotFoundError: No module named 'ccguard.server.services.hook_baseline_service'`.

- [ ] **Step 3: Create the service file with `compute_fingerprint`**

Create `src/ccguard/server/services/hook_baseline_service.py`:

```python
"""TOFU baseline + drift detection for Claude Code hooks.

Sibling of `mcp_baseline_service`; same overall pattern (composite fingerprint,
slot-based lookup, accept-flow), different identity composition.

Design: docs/superpowers/specs/2026-06-01-hooks-tofu-baseline-design.md
"""

from __future__ import annotations

import hashlib

# Sentinel that lets us distinguish "no file content hash (couldn't read /
# inline command)" from "explicit empty content hash". The empty-string case
# is reserved for inline shell commands; None means we have no information.
_NONE_SENTINEL = "\x00NONE\x00"


def compute_fingerprint(
    event_name: str,
    matcher: str,
    command_string: str,
    file_content_hash: str | None,
) -> str:
    """Composite sha256 hex (64 chars).

    Four pipe-separated components: event_name, matcher, command_string,
    and either the file_content_hash or a sentinel meaning "no hash available".

    The sentinel makes None and "" distinct so an inline `bash -c` hook
    (file_content_hash == "" by convention) won't share a fingerprint with
    a hook whose shim couldn't be read (file_content_hash is None).
    """
    fh = _NONE_SENTINEL if file_content_hash is None else file_content_hash
    raw = f"{event_name}|{matcher}|{command_string}|{fh}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/unit/test_hook_fingerprint.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_fingerprint.py
git commit -m "feat(service): compute_fingerprint for HookBaseline (4-field composite)"
```

---

## Task 5: `update_and_detect` — no-change case

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_service.py`

- [ ] **Step 1: Write the failing test (append)**

Append to `tests/unit/test_hook_baseline_service.py`:

```python
from ccguard.schemas.inventory import HookEntry
from ccguard.server.services.hook_baseline_service import update_and_detect


def _entry(event="PreToolUse", matcher="Bash", command="python /opt/x.py",
           file_path="/opt/x.py", file_hash="aaaa") -> HookEntry:
    return HookEntry(
        event_name=event, matcher=matcher, command=command,
        source="/root/.claude/settings.json", is_ccguard_owned=False,
        file_path=file_path, file_content_hash=file_hash,
        file_unreadable_reason=None,
    )


def test_update_and_detect_no_change_bumps_last_seen(session):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    e = _entry()
    # First call: creates row in pending.
    findings = update_and_detect(session, machine_id=1, current_hooks=[e])
    session.commit()
    assert findings == []
    row = session.exec(select(HookBaseline)).one()
    first_seen = row.last_seen_at
    assert row.status == "pending"

    # Manually promote to active (simulating admin accept) so the next call
    # is in steady state.
    row.status = "active"
    session.add(row)
    session.commit()

    # Second call with the same entry — should NOT create a new row, should
    # NOT emit any finding, just bump last_seen_at.
    import time
    time.sleep(0.01)
    findings2 = update_and_detect(session, machine_id=1, current_hooks=[e])
    session.commit()
    assert findings2 == []
    rows = session.exec(select(HookBaseline)).all()
    assert len(rows) == 1
    assert rows[0].last_seen_at > first_seen
    assert rows[0].status == "active"
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest tests/unit/test_hook_baseline_service.py::test_update_and_detect_no_change_bumps_last_seen -v
```

Expected: `ImportError: cannot import name 'update_and_detect' ...`.

- [ ] **Step 3: Implement `update_and_detect` skeleton + no-change path**

Append to `src/ccguard/server/services/hook_baseline_service.py`:

```python
from datetime import datetime, timezone

from sqlmodel import Session, select

from ccguard.schemas.inventory import HookEntry
from ccguard.server.db.models import FindingRecord, HookBaseline


def _now() -> datetime:
    # Repo convention: naive UTC datetime (see other services).
    return datetime.now(timezone.utc).replace(tzinfo=None)


def update_and_detect(
    session: Session,
    machine_id: int,
    current_hooks: list[HookEntry],
) -> list[FindingRecord]:
    """Reconcile current sync against HookBaseline; return Findings (uncommitted).

    Caller commits as part of the inventory POST transaction.
    """
    now = _now()
    findings: list[FindingRecord] = []
    seen_slot_keys: set[tuple[str, str, str]] = set()

    for hk in current_hooks:
        event = hk.event_name
        matcher = hk.matcher or ""
        command = hk.command or ""
        slot_key = (event, matcher, command)
        seen_slot_keys.add(slot_key)
        new_fp = compute_fingerprint(event, matcher, command, hk.file_content_hash)

        existing: HookBaseline | None = session.exec(
            select(HookBaseline).where(
                HookBaseline.machine_id == machine_id,
                HookBaseline.event_name == event,
                HookBaseline.matcher == matcher,
                HookBaseline.command_string == command,
            )
        ).one_or_none()

        if existing is not None and existing.fingerprint == new_fp:
            existing.last_seen_at = now
            if existing.status == "missing":
                existing.status = "active"  # came back; no finding.
            session.add(existing)
            continue

        # Below: other branches added by Tasks 6–10.
        # No-change path is the only one wired up here.

    return findings
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_hook_baseline_service.py::test_update_and_detect_no_change_bumps_last_seen -v
```

Expected: 1 passed.

The existing `test_hook_baseline_row_round_trip` test must still pass — re-run to be sure:

```bash
pytest tests/unit/test_hook_baseline_service.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_service.py
git commit -m "feat(service): update_and_detect — no-change path bumps last_seen"
```

---

## Task 6: `update_and_detect` — new-hook (bootstrap + post-bootstrap)

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_service.py`

- [ ] **Step 1: Write the failing tests (append)**

```python
def test_first_sync_creates_pending_no_findings(session):
    """Bootstrap: machine has no prior baseline → all hooks become pending,
    no hook.new findings (would drown user in noise on initial join)."""
    findings = update_and_detect(session, machine_id=1, current_hooks=[
        _entry(matcher="Bash"),
        _entry(matcher="Write|Edit"),
    ])
    session.commit()

    assert findings == []
    rows = session.exec(select(HookBaseline)).all()
    assert len(rows) == 2
    assert all(r.status == "pending" for r in rows)


def test_post_bootstrap_new_hook_emits_warn_finding(session):
    """Once at least one baseline is active on this machine, every later new
    slot raises a warn-level hook.new finding."""
    # Seed: one active baseline already in place.
    seed = HookBaseline(
        machine_id=1, event_name="PreToolUse", matcher="Bash",
        command_string="seeded-cmd", file_path=None, file_content_hash=None,
        fingerprint=compute_fingerprint("PreToolUse", "Bash", "seeded-cmd", None),
        status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id=1, current_hooks=[
        _entry(),  # default matcher=Bash, command="python /opt/x.py" — new slot
    ])
    session.commit()

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "hook.new"
    assert f.severity == "warn"
    # Slot is recorded as active for new-post-bootstrap (admin already accepted
    # earlier baselines; we treat the new hook as a real observation, not a
    # second bootstrap).
    new_row = session.exec(
        select(HookBaseline).where(HookBaseline.command_string == "python /opt/x.py")
    ).one()
    assert new_row.status == "pending"  # still pending until admin clicks accept
```

Also add a tiny helper near the top of the test file (under the existing `_entry` helper):

```python
def _now_for_test() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
```

(`datetime`/`timezone` are already imported by Task 3.)

- [ ] **Step 2: Run to verify failure**

```bash
pytest tests/unit/test_hook_baseline_service.py::test_first_sync_creates_pending_no_findings tests/unit/test_hook_baseline_service.py::test_post_bootstrap_new_hook_emits_warn_finding -v
```

Expected: both fail (`AssertionError`/missing rows; `_now_for_test` is local to tests so it's fine).

- [ ] **Step 3: Extend `update_and_detect` — handle new slot**

In `src/ccguard/server/services/hook_baseline_service.py`, inside the `update_and_detect` for-loop, replace the `# Below: other branches ...` placeholder with:

```python
        if existing is None:
            # New slot. Check whether *any* active row already exists for this
            # machine — that's our "post-bootstrap" trigger.
            has_active = session.exec(
                select(HookBaseline).where(
                    HookBaseline.machine_id == machine_id,
                    HookBaseline.status == "active",
                ).limit(1)
            ).one_or_none() is not None

            row = HookBaseline(
                machine_id=machine_id,
                event_name=event, matcher=matcher,
                command_string=command,
                file_path=hk.file_path,
                file_content_hash=hk.file_content_hash,
                fingerprint=new_fp,
                status="pending",
                first_seen_at=now, last_seen_at=now,
            )
            session.add(row)

            if has_active:
                findings.append(FindingRecord(
                    machine_id=machine_id,
                    rule_id="hook.new",
                    severity="warn",
                    title=f"Появился новый хук {event} ({matcher or '*'})",
                    description=(
                        f"Новый хук в {hk.source or 'settings.json'}: команда "
                        f"`{command[:200]}`. Источник не подтверждён как baseline. "
                        "Если ты сам ставил — нажми «Принять baseline» в UI. "
                        "Если нет — удали и пересинхронизируй."
                    ),
                    discovered_at=now,
                    payload_json={
                        "event_name": event, "matcher": matcher,
                        "command": command[:500], "source": hk.source,
                        "file_path": hk.file_path,
                    },
                ))
            continue

        # Existing slot but fingerprint mismatched → drift cases (Tasks 7–10).
```

(The exact `FindingRecord` kwargs depend on the existing model — match what `mcp_baseline_service.update_and_detect` uses. If `payload_json` isn't the field name there, use whatever it actually is. Use `MCPServerBaseline`-related code as the reference shape.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/unit/test_hook_baseline_service.py -v
```

Expected: all 4 tests in the file pass.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_service.py
git commit -m "feat(service): update_and_detect — new-hook detection (bootstrap-aware)"
```

---

## Task 7: `update_and_detect` — content drift = block

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_service.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_content_drift_emits_block_finding(session):
    """Same slot, file_content_hash changed → block-severity finding."""
    fp_old = compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "OLDHASH")
    seed = HookBaseline(
        machine_id=1, event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/x.py", file_path="/opt/x.py",
        file_content_hash="OLDHASH", fingerprint=fp_old, status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id=1, current_hooks=[
        _entry(file_hash="NEWHASH"),  # same slot, different file content
    ])
    session.commit()

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "hook.rug_pull.content"
    assert f.severity == "block"
    # Old hash + new hash both in payload so UI can show the diff.
    assert "OLDHASH" in str(f.payload_json) and "NEWHASH" in str(f.payload_json)
    # Row stays put (slot didn't move) but fingerprint refreshed to new value.
    row = session.exec(select(HookBaseline)).one()
    assert row.fingerprint == compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "NEWHASH")
    assert row.file_content_hash == "NEWHASH"
    assert row.status == "active"  # status doesn't auto-flip; finding does the alerting
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest tests/unit/test_hook_baseline_service.py::test_content_drift_emits_block_finding -v
```

Expected: 0 findings asserted, fails on `assert len(findings) == 1`.

- [ ] **Step 3: Extend `update_and_detect` — content drift branch**

After the `if existing is None: ... continue` block and the comment about drift cases, append:

```python
        # Existing slot, fingerprint mismatched. Decide which drift it is.
        old_content = existing.file_content_hash
        old_command = existing.command_string  # same as `command` by definition of slot lookup
        del old_command  # unused — drift here is content-only since slot matched

        if (existing.file_content_hash or "") != (hk.file_content_hash or ""):
            findings.append(FindingRecord(
                machine_id=machine_id,
                rule_id="hook.rug_pull.content",
                severity="block",
                title=f"Содержимое хука изменилось без обновления settings.json",
                description=(
                    f"Скрипт {hk.file_path or '<inline>'} для хука {event} "
                    f"({matcher or '*'}) поменялся. Это классический supply chain "
                    "rug pull: команда та же, но payload новый. Проверь источник "
                    "плагина. Если ты сам обновлял — нажми «Принять новый baseline»."
                ),
                discovered_at=now,
                payload_json={
                    "event_name": event, "matcher": matcher,
                    "command": command[:500], "file_path": hk.file_path,
                    "old_file_content_hash": old_content,
                    "new_file_content_hash": hk.file_content_hash,
                },
            ))

        # Refresh row in-place. fingerprint/content updated; status keeps the
        # same value so the admin's prior trust state is preserved.
        existing.file_content_hash = hk.file_content_hash
        existing.fingerprint = new_fp
        existing.last_seen_at = now
        existing.file_path = hk.file_path
        session.add(existing)
        continue
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_hook_baseline_service.py::test_content_drift_emits_block_finding -v
```

Expected: 1 passed.

Re-run whole file:

```bash
pytest tests/unit/test_hook_baseline_service.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_service.py
git commit -m "feat(service): content drift = hook.rug_pull.content block finding"
```

---

## Task 8: `update_and_detect` — command drift = warn

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_service.py`

Note: command drift is detected at the slot-lookup level. The previous slot has a different `command_string`, so the lookup misses → falls into "new slot" branch from Task 6. We need to also check: is there an existing row on `(machine_id, event_name, matcher)` with a *different* `command_string`? If yes, it's command drift, not a brand-new hook.

- [ ] **Step 1: Write the failing test (append)**

```python
def test_command_drift_emits_warn_finding(session):
    """Same event+matcher slot, command_string changed → warn finding (visible
    config change, less stealthy than content drift)."""
    fp_old = compute_fingerprint("PreToolUse", "Bash", "python /opt/old.py", "X")
    seed = HookBaseline(
        machine_id=1, event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/old.py", file_path="/opt/old.py",
        file_content_hash="X", fingerprint=fp_old, status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id=1, current_hooks=[
        _entry(command="python /opt/new.py", file_path="/opt/new.py", file_hash="X"),
    ])
    session.commit()

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "hook.rug_pull.command"
    assert f.severity == "warn"
    # We do NOT also emit hook.new — command drift supersedes.
    # And we DON'T leave an orphan row at the old command_string.
    rows = session.exec(select(HookBaseline)).all()
    assert len(rows) == 1
    assert rows[0].command_string == "python /opt/new.py"
    assert rows[0].status == "active"
```

- [ ] **Step 2: Run to verify failure**

Expected: emits `hook.new` warn (from Task 6 path) instead of `hook.rug_pull.command`, and leaves the old row intact → assertion errors.

- [ ] **Step 3: Extend `update_and_detect` — command drift detection**

This needs to run *before* the "new slot" branch in Task 6. Insert it after the `if existing is not None and existing.fingerprint == new_fp:` block and *before* the `if existing is None:` block:

```python
        if existing is None:
            # Look for an existing baseline on the same (event, matcher) but
            # with a different command_string. That's command drift, not a
            # brand-new hook — Claude Code allows only one hook per slot, so
            # any matcher+event swap means the old command was replaced.
            same_slot_other_cmd = session.exec(
                select(HookBaseline).where(
                    HookBaseline.machine_id == machine_id,
                    HookBaseline.event_name == event,
                    HookBaseline.matcher == matcher,
                    HookBaseline.command_string != command,
                    HookBaseline.status.in_(["active", "accepted_drift", "pending"]),
                )
            ).first()

            if same_slot_other_cmd is not None:
                # Command drift: update the existing row in-place rather than
                # creating a new one.
                findings.append(FindingRecord(
                    machine_id=machine_id,
                    rule_id="hook.rug_pull.command",
                    severity="warn",
                    title=f"Команда хука {event} ({matcher or '*'}) изменилась",
                    description=(
                        f"Было: `{same_slot_other_cmd.command_string[:200]}`\n"
                        f"Стало: `{command[:200]}`\n"
                        "Кто-то менял settings.json вручную или прошла переустановка "
                        "плагина. Это видимое изменение — менее изящная атака, но "
                        "проверь источник."
                    ),
                    discovered_at=now,
                    payload_json={
                        "event_name": event, "matcher": matcher,
                        "old_command": same_slot_other_cmd.command_string,
                        "new_command": command,
                        "file_path": hk.file_path,
                    },
                ))
                same_slot_other_cmd.command_string = command
                same_slot_other_cmd.file_path = hk.file_path
                same_slot_other_cmd.file_content_hash = hk.file_content_hash
                same_slot_other_cmd.fingerprint = new_fp
                same_slot_other_cmd.last_seen_at = now
                session.add(same_slot_other_cmd)
                continue

            # No prior baseline on this (event, matcher) — truly new slot.
            # ... (Task 6's body continues here unchanged) ...
```

Make sure the Task 6 body for new-slot creation now lives inside this final `else` branch (no prior baseline for this matcher/event).

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/unit/test_hook_baseline_service.py -v
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_service.py
git commit -m "feat(service): command drift = hook.rug_pull.command warn finding"
```

---

## Task 9: `update_and_detect` — removed hook (silent missing)

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_service.py`

- [ ] **Step 1: Write the failing test**

```python
def test_removed_hook_marks_status_missing_no_finding(session):
    """Hook that was in last sync but not in this sync → status=missing, no
    finding (v1 behavior; spec § Lifecycle)."""
    seed = HookBaseline(
        machine_id=1, event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/x.py", file_path="/opt/x.py",
        file_content_hash="X",
        fingerprint=compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "X"),
        status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    findings = update_and_detect(session, machine_id=1, current_hooks=[])
    session.commit()

    assert findings == []
    row = session.exec(select(HookBaseline)).one()
    assert row.status == "missing"
```

- [ ] **Step 2: Run to verify failure**

Expected: `row.status == "active"`, fails the last assertion.

- [ ] **Step 3: Extend `update_and_detect` — mark removed after the loop**

Append after the for-loop in `update_and_detect`, before `return findings`:

```python
    # Mark any baseline rows that were NOT seen in this sync as "missing".
    # (Removal is silent in v1; we keep the row so admin can see history.)
    all_rows = session.exec(
        select(HookBaseline).where(HookBaseline.machine_id == machine_id)
    ).all()
    for r in all_rows:
        slot_key = (r.event_name, r.matcher, r.command_string)
        if slot_key not in seen_slot_keys and r.status != "missing":
            r.status = "missing"
            session.add(r)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/unit/test_hook_baseline_service.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_service.py
git commit -m "feat(service): removed hooks marked status=missing (silent v1)"
```

---

## Task 10: `update_and_detect` — unreadable file

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_service.py`

- [ ] **Step 1: Write the failing test**

```python
def test_file_became_unreadable_emits_warn(session):
    """If we had a content_hash and now we don't (permission denied / file
    moved), raise a hook.unreadable warn so admin sees they can't trust this
    hook's drift detection anymore."""
    seed = HookBaseline(
        machine_id=1, event_name="PreToolUse", matcher="Bash",
        command_string="python /opt/x.py", file_path="/opt/x.py",
        file_content_hash="HAD_HASH",
        fingerprint=compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "HAD_HASH"),
        status="active",
        first_seen_at=_now_for_test(), last_seen_at=_now_for_test(),
    )
    session.add(seed); session.commit()

    e = HookEntry(
        event_name="PreToolUse", matcher="Bash",
        command="python /opt/x.py", source="/root/.claude/settings.json",
        is_ccguard_owned=False, file_path="/opt/x.py",
        file_content_hash=None, file_unreadable_reason="permission_denied",
    )

    findings = update_and_detect(session, machine_id=1, current_hooks=[e])
    session.commit()

    assert len(findings) == 1
    assert findings[0].rule_id == "hook.unreadable"
    assert findings[0].severity == "warn"
```

- [ ] **Step 2: Run to verify failure**

Expected: probably triggers a content drift (block) instead of unreadable (warn).

- [ ] **Step 3: Refine content-drift branch — split out unreadable case**

In `update_and_detect`, find the content-drift block from Task 7. Replace the unconditional `hook.rug_pull.content` emission with this guarded version:

```python
        if (existing.file_content_hash or "") != (hk.file_content_hash or ""):
            had_hash_lost_it = existing.file_content_hash and hk.file_content_hash is None
            if had_hash_lost_it:
                findings.append(FindingRecord(
                    machine_id=machine_id,
                    rule_id="hook.unreadable",
                    severity="warn",
                    title="Не могу прочитать файл шима",
                    description=(
                        f"Файл {hk.file_path or '<unknown>'} раньше читался, "
                        "теперь нет: "
                        f"{hk.file_unreadable_reason or 'неизвестная причина'}. "
                        "Drift detection для этого хука сейчас не работает — "
                        "проверь права или путь."
                    ),
                    discovered_at=now,
                    payload_json={
                        "event_name": event, "matcher": matcher,
                        "command": command[:500], "file_path": hk.file_path,
                        "reason": hk.file_unreadable_reason,
                    },
                ))
            else:
                findings.append(FindingRecord(
                    machine_id=machine_id,
                    rule_id="hook.rug_pull.content",
                    severity="block",
                    title=f"Содержимое хука изменилось без обновления settings.json",
                    description=(
                        f"Скрипт {hk.file_path or '<inline>'} для хука {event} "
                        f"({matcher or '*'}) поменялся. Это классический supply chain "
                        "rug pull: команда та же, но payload новый."
                    ),
                    discovered_at=now,
                    payload_json={
                        "event_name": event, "matcher": matcher,
                        "command": command[:500], "file_path": hk.file_path,
                        "old_file_content_hash": existing.file_content_hash,
                        "new_file_content_hash": hk.file_content_hash,
                    },
                ))
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/unit/test_hook_baseline_service.py -v
```

Expected: all 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_service.py
git commit -m "feat(service): hook.unreadable warn when content_hash disappears"
```

---

## Task 11: `accept_baseline` (single)

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_accept_flow.py` (new file)

- [ ] **Step 1: Write the failing tests (new file)**

Create `tests/unit/test_hook_baseline_accept_flow.py`:

```python
"""accept_baseline / accept_all_pending / reject_and_mark."""

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, create_engine, select

from ccguard.server.db.models import HookBaseline
from ccguard.server.db.session import init_db
from ccguard.server.services.hook_baseline_service import (
    accept_baseline,
    accept_all_pending,
    reject_and_mark,
    compute_fingerprint,
)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite://", echo=False, connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as s:
        yield s


def _row(session, status="pending", command="cmd"):
    r = HookBaseline(
        machine_id=1, event_name="PreToolUse", matcher="Bash",
        command_string=command, file_path=None, file_content_hash=None,
        fingerprint=compute_fingerprint("PreToolUse", "Bash", command, None),
        status=status, first_seen_at=_now(), last_seen_at=_now(),
    )
    session.add(r); session.commit(); session.refresh(r)
    return r


def test_accept_baseline_pending_to_active(session):
    r = _row(session, status="pending")
    accept_baseline(session, machine_id=1, baseline_id=r.id, accepting_user="admin")
    session.commit()
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "active"
    assert fresh.accepted_by == "admin"
    assert fresh.accepted_at is not None


def test_accept_baseline_accepted_drift_to_active(session):
    """Re-accept after drift returns row to active and clears the drift flag."""
    r = _row(session, status="accepted_drift")
    accept_baseline(session, machine_id=1, baseline_id=r.id, accepting_user="admin")
    session.commit()
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "active"


def test_accept_baseline_wrong_machine_raises(session):
    r = _row(session, status="pending")
    with pytest.raises(LookupError):
        accept_baseline(session, machine_id=999, baseline_id=r.id, accepting_user="admin")
```

- [ ] **Step 2: Run to verify failure**

Expected: `ImportError: cannot import name 'accept_baseline' ...`.

- [ ] **Step 3: Implement `accept_baseline`**

Append to `src/ccguard/server/services/hook_baseline_service.py`:

```python
def accept_baseline(
    session: Session,
    machine_id: int,
    baseline_id: int,
    accepting_user: str,
) -> HookBaseline:
    """Promote a pending/accepted_drift row to active and record who accepted.

    Raises LookupError if the row doesn't exist or belongs to another machine
    (defense in depth against URL-tampering POSTs)."""
    row = session.exec(
        select(HookBaseline).where(
            HookBaseline.id == baseline_id,
            HookBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(f"HookBaseline id={baseline_id} for machine={machine_id} not found")
    row.status = "active"
    row.accepted_at = _now()
    row.accepted_by = accepting_user
    session.add(row)
    return row
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/unit/test_hook_baseline_accept_flow.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_accept_flow.py
git commit -m "feat(service): accept_baseline promotes pending → active"
```

---

## Task 12: `accept_all_pending` (bulk for bootstrap)

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_accept_flow.py`

- [ ] **Step 1: Write the failing tests (append)**

```python
def test_accept_all_pending_promotes_only_pending(session):
    p1 = _row(session, status="pending", command="cmd1")
    p2 = _row(session, status="pending", command="cmd2")
    a = _row(session, status="active", command="cmd3")
    m = _row(session, status="missing", command="cmd4")

    promoted = accept_all_pending(session, machine_id=1, accepting_user="admin")
    session.commit()

    assert promoted == 2
    rows = {r.command_string: r for r in session.exec(select(HookBaseline)).all()}
    assert rows["cmd1"].status == "active" and rows["cmd1"].accepted_by == "admin"
    assert rows["cmd2"].status == "active"
    assert rows["cmd3"].status == "active"  # unchanged
    assert rows["cmd4"].status == "missing"  # unchanged


def test_accept_all_pending_scoped_to_machine(session):
    other = _row(session, status="pending", command="other-cmd")
    other.machine_id = 2
    session.add(other); session.commit()
    p_mine = _row(session, status="pending", command="my-cmd")

    promoted = accept_all_pending(session, machine_id=1, accepting_user="admin")
    session.commit()

    assert promoted == 1
    rows = {r.command_string: r for r in session.exec(select(HookBaseline)).all()}
    assert rows["my-cmd"].status == "active"
    assert rows["other-cmd"].status == "pending"
```

- [ ] **Step 2: Run to verify failure**

Expected: `ImportError`.

- [ ] **Step 3: Implement**

Append to the service:

```python
def accept_all_pending(
    session: Session,
    machine_id: int,
    accepting_user: str,
) -> int:
    """Promote every pending row for this machine to active. Returns count."""
    rows = session.exec(
        select(HookBaseline).where(
            HookBaseline.machine_id == machine_id,
            HookBaseline.status == "pending",
        )
    ).all()
    now = _now()
    for r in rows:
        r.status = "active"
        r.accepted_at = now
        r.accepted_by = accepting_user
        session.add(r)
    return len(rows)
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/unit/test_hook_baseline_accept_flow.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_accept_flow.py
git commit -m "feat(service): accept_all_pending bulk-promotes bootstrap rows"
```

---

## Task 13: `reject_and_mark`

**Files:**
- Modify: `src/ccguard/server/services/hook_baseline_service.py`
- Test: `tests/unit/test_hook_baseline_accept_flow.py`

- [ ] **Step 1: Write the failing test**

```python
def test_reject_and_mark_sets_status_removed(session):
    r = _row(session, status="pending")
    reject_and_mark(session, machine_id=1, baseline_id=r.id)
    session.commit()
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "removed"


def test_reject_and_mark_wrong_machine_raises(session):
    r = _row(session, status="pending")
    with pytest.raises(LookupError):
        reject_and_mark(session, machine_id=999, baseline_id=r.id)
```

- [ ] **Step 2: Run to verify failure**

Expected: `ImportError`.

- [ ] **Step 3: Implement**

```python
def reject_and_mark(
    session: Session,
    machine_id: int,
    baseline_id: int,
) -> HookBaseline:
    """Mark the baseline as removed (admin opted out of trusting it). The hook
    in settings.json is NOT auto-removed — that's the admin's job."""
    row = session.exec(
        select(HookBaseline).where(
            HookBaseline.id == baseline_id,
            HookBaseline.machine_id == machine_id,
        )
    ).one_or_none()
    if row is None:
        raise LookupError(f"HookBaseline id={baseline_id} for machine={machine_id} not found")
    row.status = "removed"
    session.add(row)
    return row
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/unit/test_hook_baseline_accept_flow.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/hook_baseline_service.py tests/unit/test_hook_baseline_accept_flow.py
git commit -m "feat(service): reject_and_mark sets status=removed"
```

---

## Task 14: Wire `update_and_detect` into `POST /api/v1/inventory`

**Files:**
- Modify: `src/ccguard/server/api/inventory.py`
- Test: `tests/integration/test_inventory_emits_hook_findings.py` (new)

- [ ] **Step 1: Write the failing integration test (new file)**

Create `tests/integration/test_inventory_emits_hook_findings.py`. Use the existing integration test pattern — the `mcp_baseline` integration tests are the closest cousin (`tests/integration/test_mcp_rug_pull_flow.py`); copy its `_test_client_with_token` / `_post_inventory` helpers if they exist, otherwise import them. The test body:

```python
"""POST /api/v1/inventory with hook payloads → HookBaseline rows + FindingRecord."""

from datetime import datetime, timezone

from sqlmodel import select

from ccguard.server.db.models import FindingRecord, HookBaseline


def test_first_inventory_creates_pending_baselines_no_findings(
    test_client_with_agent_token,  # whatever fixture name the existing flow tests use
):
    client, token, session = test_client_with_agent_token

    payload = {
        "schema_version": 1,
        "machine_id": "machine-A",
        "agent_version": "0.1.0",
        "hooks": [
            {
                "event_name": "PreToolUse", "matcher": "Bash",
                "command": "python /opt/x.py",
                "source": "/root/.claude/settings.json",
                "is_ccguard_owned": False,
                "file_path": "/opt/x.py",
                "file_content_hash": "AAA",
                "file_unreadable_reason": None,
            },
        ],
        # ... include other required InventoryReport fields (mcp_servers, skills, etc.) ...
    }
    r = client.post("/api/v1/inventory", json=payload, headers={"X-CCGuard-Token": token})
    assert r.status_code == 200

    baselines = session.exec(select(HookBaseline)).all()
    assert len(baselines) == 1
    assert baselines[0].status == "pending"

    findings = session.exec(select(FindingRecord).where(FindingRecord.rule_id.like("hook.%"))).all()
    assert findings == []  # bootstrap is silent


def test_second_inventory_with_content_drift_emits_block(
    test_client_with_agent_token,
):
    client, token, session = test_client_with_agent_token

    base_hooks = [{
        "event_name": "PreToolUse", "matcher": "Bash",
        "command": "python /opt/x.py",
        "source": "/root/.claude/settings.json",
        "is_ccguard_owned": False,
        "file_path": "/opt/x.py", "file_content_hash": "AAA",
        "file_unreadable_reason": None,
    }]
    base_payload = {"schema_version": 1, "machine_id": "machine-B",
                    "agent_version": "0.1.0", "hooks": base_hooks}

    # first sync → pending; promote to active manually (simulate admin accept)
    client.post("/api/v1/inventory", json=base_payload, headers={"X-CCGuard-Token": token})
    row = session.exec(select(HookBaseline)).one()
    row.status = "active"; session.add(row); session.commit()

    # second sync, same slot, different content hash
    drift_payload = dict(base_payload)
    drift_payload["hooks"] = [dict(base_hooks[0], file_content_hash="BBB")]
    client.post("/api/v1/inventory", json=drift_payload, headers={"X-CCGuard-Token": token})

    findings = session.exec(
        select(FindingRecord).where(FindingRecord.rule_id == "hook.rug_pull.content")
    ).all()
    assert len(findings) == 1
    assert findings[0].severity == "block"
```

(The exact fixture name and payload shape must match the existing inventory integration tests — open `tests/integration/test_mcp_rug_pull_flow.py` for the canonical example and adapt.)

- [ ] **Step 2: Run to verify failure**

```bash
pytest tests/integration/test_inventory_emits_hook_findings.py -v
```

Expected: fails — server doesn't yet call `hook_baseline_service.update_and_detect`.

- [ ] **Step 3: Wire the call into the inventory handler**

In `src/ccguard/server/api/inventory.py`, find the POST handler. There should already be a call to `mcp_baseline_service.update_and_detect` (added in commit `cb897bb`). Right next to it, add:

```python
from ccguard.server.services import hook_baseline_service

# ... inside the handler, after mcp_baseline_service.update_and_detect(...) ...

hook_findings = hook_baseline_service.update_and_detect(
    session,
    machine_id=machine.id,
    current_hooks=report.hooks,
)
for f in hook_findings:
    session.add(f)
```

(Match the surrounding pattern — if the file uses lazy commit at the end, do the same. If `report.hooks` isn't the exact attribute name, look at where the existing handler accesses hooks — it should already iterate them for some other purpose.)

- [ ] **Step 4: Run integration tests to verify they pass**

```bash
pytest tests/integration/test_inventory_emits_hook_findings.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Run the whole suite to confirm no regression**

```bash
pytest tests/ --ignore=tests/e2e -q 2>&1 | tail -3
```

Expected: baseline count + new tests, 1 pre-existing flaky failure.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/api/inventory.py tests/integration/test_inventory_emits_hook_findings.py
git commit -m "feat(api): inventory POST runs hook_baseline_service.update_and_detect"
```

---

## Task 15: Web routes — accept / accept-all-pending / reject

**Files:**
- Modify: `src/ccguard/server/web/routes.py`
- Test: `tests/integration/test_machine_detail_hook_baseline_ui.py` (route smoke; UI in Task 16+)

- [ ] **Step 1: Write the failing route tests (new file)**

Create `tests/integration/test_machine_detail_hook_baseline_ui.py`:

```python
"""Web routes for hook baseline accept/reject. UI rendering tests come later."""

from sqlmodel import select

from ccguard.server.db.models import HookBaseline


def _seed_baseline(session, status="pending", machine_id=1, **kw):
    from datetime import datetime, timezone
    from ccguard.server.services.hook_baseline_service import compute_fingerprint
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row = HookBaseline(
        machine_id=machine_id, event_name="PreToolUse", matcher="Bash",
        command_string=kw.get("command", "cmd"),
        file_path=None, file_content_hash=None,
        fingerprint=compute_fingerprint("PreToolUse", "Bash", kw.get("command", "cmd"), None),
        status=status, first_seen_at=now, last_seen_at=now,
    )
    session.add(row); session.commit(); session.refresh(row)
    return row


def test_accept_single_route_promotes_to_active(authed_admin_client_with_machine):
    """Use whatever existing fixture spins up an admin-logged-in TestClient
    with a machine row. Look in tests/integration/test_machine_detail_mcp_diff.py
    for the canonical pattern."""
    client, session, machine = authed_admin_client_with_machine
    r = _seed_baseline(session, status="pending", machine_id=machine.id)
    csrf = _get_csrf(client, f"/machines/{machine.id}")  # helper from existing tests

    resp = client.post(
        f"/machines/{machine.id}/hook-baseline/{r.id}/accept",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/machines/{machine.id}"
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "active"


def test_accept_all_pending_route(authed_admin_client_with_machine):
    client, session, machine = authed_admin_client_with_machine
    _seed_baseline(session, status="pending", machine_id=machine.id, command="a")
    _seed_baseline(session, status="pending", machine_id=machine.id, command="b")
    csrf = _get_csrf(client, f"/machines/{machine.id}")

    resp = client.post(
        f"/machines/{machine.id}/hook-baseline/accept-all-pending",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    rows = session.exec(select(HookBaseline)).all()
    assert all(r.status == "active" for r in rows)


def test_reject_route(authed_admin_client_with_machine):
    client, session, machine = authed_admin_client_with_machine
    r = _seed_baseline(session, status="pending", machine_id=machine.id)
    csrf = _get_csrf(client, f"/machines/{machine.id}")

    resp = client.post(
        f"/machines/{machine.id}/hook-baseline/{r.id}/reject",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    fresh = session.exec(select(HookBaseline)).one()
    assert fresh.status == "removed"
```

(`authed_admin_client_with_machine` and `_get_csrf` are conventions from the existing integration tests — open `tests/integration/test_machine_detail_mcp_diff.py` and copy the patterns. If those tests use a different fixture name, use the actual name from the codebase.)

- [ ] **Step 2: Run to verify failure**

Expected: 404 on the new routes.

- [ ] **Step 3: Add the routes**

In `src/ccguard/server/web/routes.py`, find the section where `mcp-baseline/accept` route lives (added in commit `cb897bb` — search for `mcp-baseline`). Add immediately below it:

```python
from ccguard.server.services import hook_baseline_service


@router.post("/machines/{machine_id}/hook-baseline/{baseline_id}/accept")
def hook_baseline_accept(
    machine_id: str,
    baseline_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: SessionPayload = Depends(require_session),
    _csrf: None = Depends(require_csrf),
) -> Response:
    machine = _resolve_machine_or_404(session, machine_id)
    try:
        hook_baseline_service.accept_baseline(
            session, machine_id=machine.id, baseline_id=baseline_id,
            accepting_user=user.user_id,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="baseline not found")
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/hook-baseline/accept-all-pending")
def hook_baseline_accept_all(
    machine_id: str,
    session: Session = Depends(get_session),
    user: SessionPayload = Depends(require_session),
    _csrf: None = Depends(require_csrf),
) -> Response:
    machine = _resolve_machine_or_404(session, machine_id)
    hook_baseline_service.accept_all_pending(
        session, machine_id=machine.id, accepting_user=user.user_id,
    )
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/hook-baseline/{baseline_id}/reject")
def hook_baseline_reject(
    machine_id: str,
    baseline_id: int,
    session: Session = Depends(get_session),
    user: SessionPayload = Depends(require_session),
    _csrf: None = Depends(require_csrf),
) -> Response:
    machine = _resolve_machine_or_404(session, machine_id)
    try:
        hook_baseline_service.reject_and_mark(
            session, machine_id=machine.id, baseline_id=baseline_id,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="baseline not found")
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)
```

(`_resolve_machine_or_404`, `SessionPayload`, `require_session`, `require_csrf` should already be in scope — look at how the MCP accept route uses them. If `user.user_id` is actually named differently — match the existing pattern.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/integration/test_machine_detail_hook_baseline_ui.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/web/routes.py tests/integration/test_machine_detail_hook_baseline_ui.py
git commit -m "feat(web): hook-baseline accept / accept-all / reject routes"
```

---

## Task 16: UI — bootstrap banner partial

**Files:**
- Create: `src/ccguard/server/web/templates/components/_hook_baseline_banner.html`
- Modify: `src/ccguard/server/web/routes.py` (machine_detail handler — pass new context)
- Modify: `src/ccguard/server/web/templates/machine_detail.html` (include partial)
- Test: `tests/integration/test_machine_detail_hook_baseline_ui.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_bootstrap_banner_shows_when_pending_exists(authed_admin_client_with_machine):
    client, session, machine = authed_admin_client_with_machine
    _seed_baseline(session, status="pending", machine_id=machine.id, command="a")
    _seed_baseline(session, status="pending", machine_id=machine.id, command="b")

    r = client.get(f"/machines/{machine.id}")
    assert r.status_code == 200
    assert "Найдено 2 хуков" in r.text or "Найдено 2 хука" in r.text
    assert f'action="/machines/{machine.id}/hook-baseline/accept-all-pending"' in r.text


def test_bootstrap_banner_hidden_when_no_pending(authed_admin_client_with_machine):
    client, session, machine = authed_admin_client_with_machine
    _seed_baseline(session, status="active", machine_id=machine.id, command="a")

    r = client.get(f"/machines/{machine.id}")
    assert r.status_code == 200
    assert "Найдено" not in r.text or "хук" not in r.text.split("Найдено", 1)[1][:100]
    assert "accept-all-pending" not in r.text
```

- [ ] **Step 2: Run to verify failure**

Expected: banner not rendered → assertions fail.

- [ ] **Step 3: Create the partial**

Create `src/ccguard/server/web/templates/components/_hook_baseline_banner.html`:

```html
{% if pending_hook_count and pending_hook_count > 0 %}
<section class="rounded border border-amber-700 bg-amber-50 p-4 my-4">
    <h3 class="text-base font-semibold text-amber-900">
        Найдено {{ pending_hook_count }} {{ pending_hook_count | hook_word }} без подтверждённого baseline
    </h3>
    <p class="text-sm text-amber-900 mt-1">
        Подтверди baseline, чтобы ccguard ловил drift в дальнейшем,
        или удали хук в settings.json вручную.
    </p>
    <form method="POST"
          action="/machines/{{ machine.machine_id }}/hook-baseline/accept-all-pending"
          class="mt-3 inline-block">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit"
                class="px-3 py-1 bg-amber-700 text-white text-sm rounded hover:bg-amber-800">
            Подтвердить все ({{ pending_hook_count }})
        </button>
    </form>
    <a href="#hooks-section" class="ml-2 text-sm text-amber-900 underline">
        Просмотреть по одному
    </a>
</section>
{% endif %}
```

Add the `hook_word` Jinja filter (the Russian plural) — open `src/ccguard/server/web/templates/__init__.py` or wherever filters are registered (`render.py` or similar):

```python
def _hook_word(n: int) -> str:
    """хук / хука / хуков (Russian plural)."""
    n = abs(n) % 100
    if 11 <= n <= 14:
        return "хуков"
    n10 = n % 10
    if n10 == 1:
        return "хук"
    if 2 <= n10 <= 4:
        return "хука"
    return "хуков"

# Then register:
env.filters["hook_word"] = _hook_word
```

If filter registration lives somewhere else (e.g. directly on `Jinja2Templates`), follow the existing local pattern.

- [ ] **Step 4: Wire context + include into `machine_detail`**

In `src/ccguard/server/web/routes.py`, find the `machine_detail` handler. Before the `return templates.TemplateResponse(...)` line, add:

```python
from sqlmodel import func

pending_hook_count = session.exec(
    select(func.count(HookBaseline.id)).where(
        HookBaseline.machine_id == machine.id,
        HookBaseline.status == "pending",
    )
).one()
```

(Import `HookBaseline` and `func` at top of file if not already.) Pass `pending_hook_count=pending_hook_count` in the template context dict.

In `src/ccguard/server/web/templates/machine_detail.html`, before the existing «Хуки» block, add:

```jinja
{% include "components/_hook_baseline_banner.html" %}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/integration/test_machine_detail_hook_baseline_ui.py -v
```

Expected: 5 passed (3 from Task 15 + 2 new).

Re-run the full suite — the `machine_detail` golden snapshot will break:

```bash
pytest tests/ --ignore=tests/e2e -q 2>&1 | tail -5
```

If `tests/integration/test_render_snapshots.py::test_machine_detail_with_risk` fails, regenerate the snapshot:

```bash
CCGUARD_UPDATE_SNAPSHOTS=1 pytest tests/integration/test_render_snapshots.py::test_machine_detail_with_risk -v
```

Inspect `git diff tests/_snapshots/machine_detail_with_risk.html` — expect added banner markup, no other changes. Re-run without env var to confirm.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/templates/components/_hook_baseline_banner.html \
        src/ccguard/server/web/templates/machine_detail.html \
        src/ccguard/server/web/routes.py \
        tests/integration/test_machine_detail_hook_baseline_ui.py \
        tests/_snapshots/machine_detail_with_risk.html \
        src/ccguard/server/web/render.py  # or wherever you added the hook_word filter
git commit -m "feat(ui): bootstrap banner for pending hook baselines"
```

---

## Task 17: UI — drift findings partial

**Files:**
- Create: `src/ccguard/server/web/templates/components/_hook_drift_cards.html`
- Modify: `src/ccguard/server/web/routes.py` (pass `hook_drift_cards` context)
- Modify: `src/ccguard/server/web/templates/machine_detail.html` (include partial)
- Test: `tests/integration/test_machine_detail_hook_baseline_ui.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_content_drift_finding_renders_with_accept_button(authed_admin_client_with_machine):
    """Simulate content drift: seed an active baseline + drift finding +
    confirm UI shows it with diff and accept-new-baseline button."""
    from datetime import datetime, timezone
    from ccguard.server.db.models import FindingRecord

    client, session, machine = authed_admin_client_with_machine
    r = _seed_baseline(session, status="active", machine_id=machine.id, command="cmd")

    f = FindingRecord(
        machine_id=machine.id,
        rule_id="hook.rug_pull.content",
        severity="block",
        title="Содержимое хука изменилось",
        description="long description",
        discovered_at=datetime.now(timezone.utc).replace(tzinfo=None),
        payload_json={
            "event_name": "PreToolUse", "matcher": "Bash",
            "old_file_content_hash": "OLDXXX",
            "new_file_content_hash": "NEWYYY",
            "file_path": "/opt/x.py",
        },
    )
    session.add(f); session.commit()

    resp = client.get(f"/machines/{machine.id}")
    assert resp.status_code == 200
    assert "Содержимое хука изменилось" in resp.text
    assert "OLDXXX" in resp.text and "NEWYYY" in resp.text
    assert f'action="/machines/{machine.id}/hook-baseline/{r.id}/accept"' in resp.text
```

- [ ] **Step 2: Run to verify failure**

Expected: drift card not rendered.

- [ ] **Step 3: Create the partial**

Create `src/ccguard/server/web/templates/components/_hook_drift_cards.html`:

```jinja
{% for card in hook_drift_cards %}
<article class="border rounded p-4 my-3 {% if card.severity == 'block' %}border-red-700 bg-red-50{% else %}border-amber-700 bg-amber-50{% endif %}">
    <header class="flex items-center justify-between">
        <h4 class="font-semibold {% if card.severity == 'block' %}text-red-900{% else %}text-amber-900{% endif %}">
            {{ card.title }}
        </h4>
        <span class="text-xs uppercase tracking-wider px-2 py-0.5 rounded {% if card.severity == 'block' %}bg-red-700 text-white{% else %}bg-amber-700 text-white{% endif %}">
            {{ card.severity }}
        </span>
    </header>
    <p class="text-sm mt-2">{{ card.description }}</p>

    {% if card.payload.old_file_content_hash or card.payload.new_file_content_hash %}
    <div class="mt-3 text-xs font-mono">
        <div>было: <span class="text-red-700">{{ card.payload.old_file_content_hash or '—' }}</span></div>
        <div>стало: <span class="text-green-700">{{ card.payload.new_file_content_hash or '—' }}</span></div>
        {% if card.payload.file_path %}<div>файл: {{ card.payload.file_path }}</div>{% endif %}
    </div>
    {% endif %}

    {% if card.payload.old_command or card.payload.new_command %}
    <div class="mt-3 text-xs font-mono">
        <div>было: <span class="text-red-700">{{ card.payload.old_command }}</span></div>
        <div>стало: <span class="text-green-700">{{ card.payload.new_command }}</span></div>
    </div>
    {% endif %}

    {% if card.baseline_id %}
    <form method="POST" action="/machines/{{ machine.machine_id }}/hook-baseline/{{ card.baseline_id }}/accept" class="inline-block mt-3 mr-2">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit" class="px-3 py-1 bg-emerald-700 text-white text-sm rounded hover:bg-emerald-800">
            Принять новый baseline
        </button>
    </form>
    <form method="POST" action="/machines/{{ machine.machine_id }}/hook-baseline/{{ card.baseline_id }}/reject" class="inline-block mt-3">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit" class="px-3 py-1 bg-gray-200 text-gray-900 text-sm rounded hover:bg-gray-300">
            Откатить и удалить из baseline
        </button>
    </form>
    {% endif %}
</article>
{% endfor %}
```

- [ ] **Step 4: Build the `hook_drift_cards` context in `routes.py`**

In the `machine_detail` handler, before the `return`, add (next to where MCP rug-pull cards are assembled):

```python
hook_drift_findings = session.exec(
    select(FindingRecord)
    .where(
        FindingRecord.machine_id == machine.id,
        FindingRecord.rule_id.in_([
            "hook.rug_pull.content",
            "hook.rug_pull.command",
            "hook.unreadable",
            "hook.new",
        ]),
    )
    .order_by(FindingRecord.discovered_at.desc())
    .limit(30)
).all()

hook_drift_cards = []
for f in hook_drift_findings:
    payload = f.payload_json or {}
    # Locate the matching baseline row (one slot per finding).
    bl = session.exec(
        select(HookBaseline).where(
            HookBaseline.machine_id == machine.id,
            HookBaseline.event_name == payload.get("event_name"),
            HookBaseline.matcher == (payload.get("matcher") or ""),
        ).order_by(HookBaseline.last_seen_at.desc())
    ).first()
    hook_drift_cards.append({
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "payload": payload,
        "baseline_id": bl.id if bl else None,
    })
```

Pass `hook_drift_cards=hook_drift_cards` into the template context.

In `machine_detail.html`, include the partial **above** the existing «Хуки» block (or wherever drift cards make most sense; symmetric with `_mcp_rug_pull_cards.html` placement):

```jinja
{% include "components/_hook_drift_cards.html" %}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/integration/test_machine_detail_hook_baseline_ui.py -v
```

Expected: 6 passed.

Snapshot regen if needed:

```bash
CCGUARD_UPDATE_SNAPSHOTS=1 pytest tests/integration/test_render_snapshots.py::test_machine_detail_with_risk -v
```

Inspect diff — expected to be additive only.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/templates/components/_hook_drift_cards.html \
        src/ccguard/server/web/templates/machine_detail.html \
        src/ccguard/server/web/routes.py \
        tests/integration/test_machine_detail_hook_baseline_ui.py \
        tests/_snapshots/machine_detail_with_risk.html
git commit -m "feat(ui): hook drift cards on machine_detail with accept/reject buttons"
```

---

## Task 18: UI — status badges in existing «Хуки» block

**Files:**
- Modify: `src/ccguard/server/web/templates/machine_detail.html`
- Modify: `src/ccguard/server/web/routes.py` (annotate each hook with its baseline status)
- Test: `tests/integration/test_machine_detail_hook_baseline_ui.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_hook_card_shows_baseline_status(authed_admin_client_with_machine):
    client, session, machine = authed_admin_client_with_machine
    _seed_baseline(session, status="pending", machine_id=machine.id, command="python /opt/x.py")
    # ...and the matching inventory snapshot — re-use the integration fixture
    # that already seeds machine.inventory_snapshot. Inspect the existing
    # test_machine_detail_inventory_ux.py for the exact helper name.
    ...

    resp = client.get(f"/machines/{machine.id}")
    assert "pending review" in resp.text  # status badge text
```

(Adapt to whatever inventory-seeding helper is in `test_machine_detail_inventory_ux.py`.)

- [ ] **Step 2: Run to verify failure**

Expected: status badge not present in HTML.

- [ ] **Step 3: Annotate hooks with status in the handler**

In `machine_detail` handler in `routes.py`, where hooks are passed to the template, build a quick `(event, matcher, command) → status` lookup from `HookBaseline` rows and attach it to each hook entry:

```python
baselines_by_slot = {
    (b.event_name, b.matcher, b.command_string): b.status
    for b in session.exec(
        select(HookBaseline).where(HookBaseline.machine_id == machine.id)
    ).all()
}

annotated_hooks = []
for h in inventory.hooks:
    status = baselines_by_slot.get((h.event_name, h.matcher or "", h.command or ""), None)
    annotated_hooks.append({"entry": h, "baseline_status": status})
```

Pass `annotated_hooks` instead of (or alongside) raw `inventory.hooks` to the template.

- [ ] **Step 4: Render badge in the hook card**

In `machine_detail.html`, find the existing hook card markup (added in the UX fix). Inside it, near the existing "ccguard" / "unknown" badge, add:

```jinja
{% set s = item.baseline_status %}
{% if s %}
<span class="ml-2 text-xs px-2 py-0.5 rounded
    {% if s == 'active' %}bg-emerald-200 text-emerald-900
    {% elif s == 'pending' %}bg-amber-200 text-amber-900
    {% elif s == 'accepted_drift' %}bg-sky-200 text-sky-900
    {% elif s == 'missing' %}bg-gray-200 text-gray-700
    {% else %}bg-gray-200 text-gray-700{% endif %}">
    {% if s == 'pending' %}pending review
    {% elif s == 'active' %}активный baseline
    {% elif s == 'accepted_drift' %}принят drift
    {% elif s == 'missing' %}missing
    {% else %}{{ s }}{% endif %}
</span>
{% endif %}
```

(Adapt iteration: the existing hook block iterates `inventory.hooks` — change to iterate `annotated_hooks` and access `item.entry.event_name` etc.)

- [ ] **Step 5: Run tests + snapshot**

```bash
pytest tests/integration/test_machine_detail_hook_baseline_ui.py -v
pytest tests/integration/test_machine_detail_inventory_ux.py -v  # regression guard from UX fix
```

Expected: all pass. Update snapshot if needed:

```bash
CCGUARD_UPDATE_SNAPSHOTS=1 pytest tests/integration/test_render_snapshots.py::test_machine_detail_with_risk -v
```

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/templates/machine_detail.html \
        src/ccguard/server/web/routes.py \
        tests/integration/test_machine_detail_hook_baseline_ui.py \
        tests/_snapshots/machine_detail_with_risk.html
git commit -m "feat(ui): baseline status badge on each hook card"
```

---

## Task 19: Final full-suite check + redeploy plan

**Files:** none changed — verification only.

- [ ] **Step 1: Run the whole suite**

```bash
pytest tests/ --ignore=tests/e2e -q 2>&1 | tail -5
```

Expected: baseline + new tests, 1 pre-existing flake. If anything else regressed, fix it in a follow-up commit before merging.

- [ ] **Step 2: Manual smoke against local TestClient**

(Optional but recommended.) Start the dev server, hit `/machines/<id>`, confirm bootstrap banner shows for a fresh machine with pending hooks, accept-all works, then simulate drift via direct DB edit and confirm a block card appears.

```bash
source .venv/bin/activate
ccguard-server &
# in another terminal:
curl -sS http://localhost:8080/health
# open /admin in browser, log in, click around the machine page
```

- [ ] **Step 3: Merge to master**

```bash
git checkout master
git merge --no-ff feat/hooks-tofu-baseline -m "Merge feat/hooks-tofu-baseline: TOFU baseline + drift detection for Claude Code hooks"
```

- [ ] **Step 4: Push**

```bash
git push origin master
```

- [ ] **Step 5: Redeploy production VPS (78.17.68.120)**

```bash
tar --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' \
    --exclude='.git' --exclude='*.pyc' --exclude='tests/_snapshots' \
    -czf /tmp/ccguard-hooks-tofu.tar.gz .

scp /tmp/ccguard-hooks-tofu.tar.gz root@78.17.68.120:/opt/ccguard/

ssh root@78.17.68.120 'set -e
cd /opt/ccguard
tar -xzf ccguard-hooks-tofu.tar.gz --exclude=.env --exclude=data --exclude=config
rm ccguard-hooks-tofu.tar.gz
docker compose -f docker/docker-compose.remote.yml --env-file .env up -d --build
/opt/ccguard-agent-venv/bin/pip install --quiet --upgrade /opt/ccguard
systemctl restart ccguard-daemon
sleep 8
curl -sS http://localhost:8080/health'
```

Expected: `{"status":"ok","db":"ok"}`.

- [ ] **Step 6: Trigger sync on both fleet machines**

VPS:

```bash
ssh root@78.17.68.120 'source /opt/ccguard-agent-venv/bin/activate && ccguard sync 2>&1 | tail -10'
```

Local mac:

```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.ccguard.daemon.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ccguard.daemon.plist
/Users/timderbak/dev/ccguard/.venv/bin/ccguard sync 2>&1 | tail -10
```

- [ ] **Step 7: Open machine_detail in the browser**

```
https://ccguard.swagasecurity.com/machines/<bink3ctw...>
```

Expected: bootstrap banner with «Найдено N хуков», `Подтвердить все` button, status=`pending review` badge on every hook card. Click `Подтвердить все` → banner disappears, all hooks now show `активный baseline`.

---

## Self-review (run inline after writing)

**1. Spec coverage check:**
- Identity fingerprint (4-field composite) → Task 4 ✓
- Lifecycle (pending/active/accepted_drift/missing/removed) → status transitions in Tasks 6, 7, 9, 11, 12, 13 ✓
- 6 detection cases (no-change/new/content drift/command drift/removed/unreadable) → Tasks 5-10 ✓
- Bootstrap silent on first sync → Task 6 (post-bootstrap trigger) ✓
- Bootstrap banner → Task 16 ✓
- Drift cards with accept/reject → Task 17 ✓
- Status badges on hooks → Task 18 ✓
- Agent file hash collection → Task 2 ✓
- Server schema + DDL → Task 3 ✓
- Backward compat (Optional fields) → Task 1 (defaults to None) ✓
- ccguard-owned upgrade trade-off — *spec § Edge cases marks this as known; no task is "fix it" because v1 ships with manual accept-after-upgrade*. ✓

**2. Placeholders:** No "TBD"/"TODO" / "Add appropriate ...". Code blocks are concrete. Task 18 step 1 has `...` placeholders that reference an inventory-seeding helper — the executor must look at the existing UX-fix integration test to copy that helper; this is annotated explicitly, not hidden.

**3. Type consistency:** `HookBaseline` field names (`event_name`, `matcher`, `command_string`, `file_content_hash`, `fingerprint`, `status`) are used identically across Tasks 3–18. `compute_fingerprint(event_name, matcher, command_string, file_content_hash)` signature matches every call site. `accept_baseline / accept_all_pending / reject_and_mark` signatures consistent between Tasks 11–15.

**4. Risk: snapshot test brittleness.** Tasks 16, 17, 18 each touch `machine_detail.html`. The `test_machine_detail_with_risk` golden snapshot will require regeneration in each of those tasks. Documented inline.
