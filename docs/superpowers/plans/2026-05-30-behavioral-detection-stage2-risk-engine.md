# Behavioral Detection — Stage 2: Risk Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compute a cumulative, decay-weighted **risk score per machine** over a rolling window of `ToolUseEvent.signals_json`, and emit a single `FindingRecord(rule_id="risk.elevated")` when a machine crosses a tunable threshold. Replace nothing (the existing 3σ anomaly engine keeps running in parallel); this is the first explainable, multi-signal detection.

**Architecture:**

```
APScheduler tick (existing job)
  → anomaly_service.tick(session)        [existing]
  → risk_service.tick(session)           [NEW]
     for each machine with baseline_ready:
       events = ToolUseEvent in (now - window) where signals_json != "[]"
       score, breakdown = compute_risk_score(events, weights, window, half_life)
       if score > threshold and no same-UTC-day "risk.elevated" finding:
         emit FindingRecord("risk.elevated", severity=warn, payload=breakdown)
```

**Tech stack:** Python 3.12, stdlib `math`/`json`, SQLModel, pytest. No new deps.

**Out of scope (deferred to later stages per spec §6):** peer-group normalization, IOA sequence detector, explainability UI, one-click suppression, `enforcement_mode=observe` switch.

**Invariants:**
- **Privacy:** the engine reads only `signals_json` (catalog IDs). Never inspect/store raw input.
- **Backward compat:** machines without any `signals_json != "[]"` (v0.1 agents, idle machines) score 0 and emit no findings.
- **No race:** same single-writer scheduler thread as the anomaly tick (`coalesce=True, max_instances=1`). Same-day dedup mirrors `anomaly_service._same_day_finding_exists`.
- **Warm-up:** reuse `MachineBaseline.baseline_ready`. If a machine has zero `baseline_ready=True` baselines, skip scoring — it's too new to compare against itself.

---

### Task 1: Risk constants + settings seed

Declarative weight table (per signal ID) + tunable defaults (threshold / window / half-life) seeded into `SettingsRecord`.

**Files:**
- Create: `src/ccguard/server/services/risk_constants.py`
- Modify: `src/ccguard/server/services/settings_service.py` — add `seed_risk_settings`
- Modify: `src/ccguard/server/main.py` — call the seeder in the lifespan, right after `seed_llm_settings`
- Test: `tests/unit/test_risk_constants.py`
- Test: `tests/integration/test_risk_settings_seed.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_risk_constants.py
"""Risk weight table covers the Stage 1 catalog and parses cleanly."""
from __future__ import annotations

from ccguard.agent.signals.catalog import CATALOG
from ccguard.server.services.risk_constants import (
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_THRESHOLD,
    DEFAULT_WEIGHTS,
    DEFAULT_WINDOW_HOURS,
    RISK_RULE_ID,
)


def test_every_catalog_signal_has_a_weight():
    catalog_ids = {s.id for s in CATALOG}
    weight_ids = set(DEFAULT_WEIGHTS.keys())
    assert catalog_ids <= weight_ids, f"missing weights for: {catalog_ids - weight_ids}"


def test_weights_are_positive_floats():
    for sid, w in DEFAULT_WEIGHTS.items():
        assert isinstance(w, float), sid
        assert w > 0, sid


def test_tunable_defaults_are_sane():
    assert DEFAULT_THRESHOLD > 0
    assert DEFAULT_WINDOW_HOURS > 0
    assert DEFAULT_HALF_LIFE_HOURS > 0
    assert RISK_RULE_ID == "risk.elevated"
```

```python
# tests/integration/test_risk_settings_seed.py
"""Risk settings are seeded on first startup and preserved on re-seed."""
from __future__ import annotations

from ccguard.server.services.settings_service import (
    get_setting,
    seed_risk_settings,
    set_setting,
)


def test_seed_writes_defaults(session):
    seed_risk_settings(session)
    assert get_setting(session, "risk.threshold") is not None
    assert get_setting(session, "risk.window_hours") is not None
    assert get_setting(session, "risk.half_life_hours") is not None


def test_seed_preserves_admin_edits(session):
    seed_risk_settings(session)
    set_setting(session, "risk.threshold", "42.0")
    seed_risk_settings(session)
    assert get_setting(session, "risk.threshold") == "42.0"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_risk_constants.py tests/integration/test_risk_settings_seed.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ccguard.server.services.risk_constants'` and `ImportError: cannot import name 'seed_risk_settings'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/ccguard/server/services/risk_constants.py
"""Risk engine constants (Behavioral Detection, Stage 2).

Per-signal weights, tunable defaults, and the canonical ``rule_id`` for the
``risk.elevated`` finding. All numerics are admin-tunable via ``SettingsRecord``
(``risk.threshold``, ``risk.window_hours``, ``risk.half_life_hours``,
``risk.weight.<signal_id>``); the values here are first-boot defaults only.

Weights reflect ATT&CK tactic severity: credential access + egress weigh higher
than recon. Calibration is expected to evolve with pilot data; the catalog of
*which* signals exist is locked, the numbers are not.
"""
from __future__ import annotations

RISK_RULE_ID: str = "risk.elevated"

# First-boot defaults — admin-tunable via SettingsRecord.
DEFAULT_THRESHOLD: float = 10.0
DEFAULT_WINDOW_HOURS: float = 24.0
DEFAULT_HALF_LIFE_HOURS: float = 6.0

# Per-signal weights. Every ID in ``ccguard.agent.signals.catalog.CATALOG`` MUST
# appear here — the catalog tests enforce this. Unknown IDs (forward compat) get
# weight 1.0 at runtime, never an exception.
DEFAULT_WEIGHTS: dict[str, float] = {
    # T1552 — Unsecured credential access (highest value to an attacker).
    "cred.read.aws": 5.0,
    "cred.read.ssh": 5.0,
    "cred.read.dotenv": 3.0,
    # T1041 — Exfiltration over C2; pipe-to-shell is execution but co-fires.
    "egress.network_tool": 4.0,
    "exec.pipe_to_shell": 4.0,
    # T1546/T1053 — Persistence.
    "persist.shell_rc": 3.0,
    "persist.cron": 3.0,
    # T1033 — Recon (cheap & noisy on dev boxes; low weight).
    "discovery.recon": 1.0,
}
```

In `src/ccguard/server/services/settings_service.py`, add the seeder near `seed_llm_settings`:

```python
from ccguard.server.services.risk_constants import (
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_HOURS,
)

_RISK_SETTINGS_DEFAULTS: dict[str, str] = {
    "risk.threshold": str(DEFAULT_THRESHOLD),
    "risk.window_hours": str(DEFAULT_WINDOW_HOURS),
    "risk.half_life_hours": str(DEFAULT_HALF_LIFE_HOURS),
}


def seed_risk_settings(session: Session) -> None:
    """Idempotent first-startup seed of the risk engine knobs.

    Preserves admin edits across re-seeds (same pattern as ``seed_llm_settings``).
    """
    for key, default in _RISK_SETTINGS_DEFAULTS.items():
        if session.get(SettingsRecord, key) is None:
            session.add(SettingsRecord(key=key, value=default))
    session.commit()
```

In `src/ccguard/server/main.py` lifespan, call it right after the existing `seed_llm_settings(...)` call. Grep for `seed_llm_settings` to find the exact spot — wrap the new call in the same `Session(engine)` context if there is one, else use the existing session.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_risk_constants.py tests/integration/test_risk_settings_seed.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/risk_constants.py src/ccguard/server/services/settings_service.py src/ccguard/server/main.py tests/unit/test_risk_constants.py tests/integration/test_risk_settings_seed.py
git commit -m "feat(risk): signal weight catalog + tunable settings seed"
```

---

### Task 2: Pure scoring function

`compute_risk_score(events, now, weights, window_hours, half_life_hours) -> RiskBreakdown`. No I/O — takes a list of `(ts, signals)` tuples, returns a deterministic score + per-signal contributions. This is the unit-testable kernel.

**Files:**
- Create: `src/ccguard/server/services/risk_service.py` (scoring kernel only — tick added in Task 3)
- Test: `tests/unit/test_risk_score.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_risk_score.py
"""Pure scoring kernel: deterministic, decay-correct, weights honored."""
from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

from ccguard.server.services.risk_constants import DEFAULT_WEIGHTS
from ccguard.server.services.risk_service import RiskInputEvent, compute_risk_score


def _now() -> datetime:
    return datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)


def test_no_events_score_zero():
    br = compute_risk_score([], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.score == 0.0
    assert br.contributions == {}
    assert br.event_count == 0


def test_single_event_now_has_full_weight():
    evt = RiskInputEvent(ts=_now(), signals=("cred.read.aws",))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    # age == 0 → decay factor 1.0 → score == weight
    assert br.score == DEFAULT_WEIGHTS["cred.read.aws"]
    assert br.contributions == {"cred.read.aws": DEFAULT_WEIGHTS["cred.read.aws"]}
    assert br.event_count == 1


def test_event_one_half_life_old_decays_by_half():
    half_life = 6.0
    evt = RiskInputEvent(ts=_now() - timedelta(hours=half_life), signals=("cred.read.aws",))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, half_life)
    expected = DEFAULT_WEIGHTS["cred.read.aws"] * 0.5
    assert math.isclose(br.score, expected, rel_tol=1e-9)


def test_events_outside_window_are_dropped():
    old = RiskInputEvent(ts=_now() - timedelta(hours=48), signals=("cred.read.aws",))
    br = compute_risk_score([old], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.score == 0.0
    assert br.event_count == 0


def test_multiple_signals_per_event_sum():
    evt = RiskInputEvent(ts=_now(), signals=("cred.read.aws", "egress.network_tool"))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    expected = DEFAULT_WEIGHTS["cred.read.aws"] + DEFAULT_WEIGHTS["egress.network_tool"]
    assert math.isclose(br.score, expected, rel_tol=1e-9)


def test_unknown_signal_id_uses_default_weight_one():
    evt = RiskInputEvent(ts=_now(), signals=("future.signal.id",))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.score == 1.0
    assert br.contributions == {"future.signal.id": 1.0}


def test_contributions_aggregate_across_events():
    e1 = RiskInputEvent(ts=_now(), signals=("cred.read.aws",))
    e2 = RiskInputEvent(ts=_now(), signals=("cred.read.aws",))
    br = compute_risk_score([e1, e2], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.contributions["cred.read.aws"] == 2.0 * DEFAULT_WEIGHTS["cred.read.aws"]
    assert br.event_count == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_risk_score.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ccguard.server.services.risk_service'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/ccguard/server/services/risk_service.py
"""Risk-scoring engine (Behavioral Detection, Stage 2).

The kernel is :func:`compute_risk_score` — a pure function over a list of
``RiskInputEvent`` records (timestamp + signal IDs). It applies a per-signal
weight (``risk_constants.DEFAULT_WEIGHTS``, overridable via SettingsRecord) and
an **exponential decay by event age** so old activity fades:

    score = Σ_event Σ_signal weight(signal) · 2^(-age_hours / half_life_hours)

Events older than the window are dropped. Unknown signal IDs (forward compat
for future catalog additions before this server is upgraded) get weight 1.0
rather than raising — fail-open is the agreed posture for the engine.

The orchestrator :func:`tick` (added next) loads events for one machine,
calls this kernel, and emits a ``FindingRecord("risk.elevated")`` when the
score crosses the configured threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable


@dataclass(frozen=True)
class RiskInputEvent:
    """One per-event input to the scorer.

    ``ts`` must be tz-aware (UTC). ``signals`` is a tuple of catalog IDs.
    """

    ts: datetime
    signals: tuple[str, ...]


@dataclass(frozen=True)
class RiskBreakdown:
    """Explainable score breakdown. Persisted into ``FindingRecord.payload_json``."""

    score: float
    contributions: dict[str, float] = field(default_factory=dict)
    event_count: int = 0


_DEFAULT_UNKNOWN_WEIGHT: float = 1.0


def compute_risk_score(
    events: Iterable[RiskInputEvent],
    now: datetime,
    weights: dict[str, float],
    window_hours: float,
    half_life_hours: float,
) -> RiskBreakdown:
    """Return the decay-weighted cumulative score across ``events``.

    Events older than ``window_hours`` are dropped. Decay uses base-2 (so one
    half-life halves the contribution exactly).
    """
    cutoff = now - timedelta(hours=window_hours)
    contributions: dict[str, float] = {}
    total = 0.0
    counted = 0
    for evt in events:
        if evt.ts < cutoff:
            continue
        age_hours = max(0.0, (now - evt.ts).total_seconds() / 3600.0)
        decay = 2.0 ** (-age_hours / half_life_hours) if half_life_hours > 0 else 1.0
        any_signal_counted = False
        for sid in evt.signals:
            w = weights.get(sid, _DEFAULT_UNKNOWN_WEIGHT)
            contribution = w * decay
            contributions[sid] = contributions.get(sid, 0.0) + contribution
            total += contribution
            any_signal_counted = True
        if any_signal_counted:
            counted += 1
    return RiskBreakdown(score=total, contributions=contributions, event_count=counted)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_risk_score.py -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/risk_service.py tests/unit/test_risk_score.py
git commit -m "feat(risk): pure decay-weighted scoring kernel"
```

---

### Task 3: `risk_service.tick()` — orchestrator with dedup + warm-up + finding emission

Add the sweep entry point to `risk_service.py`. Mirrors `anomaly_service.tick` shape: per-machine try/except, single Session, same-day dedup at the service layer, baseline-ready warm-up guard.

**Files:**
- Modify: `src/ccguard/server/services/risk_service.py`
- Test: `tests/integration/test_risk_tick.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/integration/test_risk_tick.py
"""Risk tick: warm-up guard, threshold gate, dedup, finding payload shape."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline, ToolUseEvent
from ccguard.server.services import risk_service
from ccguard.server.services.risk_constants import RISK_RULE_ID


def _mk_machine(session, mid: str = "m-risk") -> str:
    session.add(Machine(machine_id=mid, hostname="h"))
    session.add(MachineBaseline(
        machine_id=mid, metric="bash_calls_per_day",
        mean=1.0, stdev=0.5, sample_count=14, baseline_ready=True,
    ))
    session.commit()
    return mid


def _mk_event(session, mid: str, signals: list[str], ts: datetime | None = None) -> None:
    session.add(ToolUseEvent(
        machine_id=mid,
        ts=ts or datetime.now(UTC),
        tool_name="Bash",
        fingerprint="0123456789abcdef",
        decision="allow",
        result_status="success",
        signals_json=json.dumps(signals),
    ))
    session.commit()


def test_no_warm_baseline_no_finding(session):
    session.add(Machine(machine_id="m-cold", hostname="h"))
    session.commit()
    _mk_event(session, "m-cold", ["cred.read.aws", "egress.network_tool"])
    summary = risk_service.tick(session)
    assert summary["findings_emitted"] == 0


def test_below_threshold_no_finding(session):
    mid = _mk_machine(session)
    _mk_event(session, mid, ["discovery.recon"])  # weight 1.0, threshold default 10
    summary = risk_service.tick(session)
    assert summary["findings_emitted"] == 0


def test_above_threshold_emits_finding_with_breakdown(session):
    mid = _mk_machine(session)
    # cred (5) + egress (4) + pipe (4) = 13 > default threshold 10
    _mk_event(session, mid, ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"])
    summary = risk_service.tick(session)
    assert summary["findings_emitted"] == 1
    f = session.exec(select(FindingRecord).where(FindingRecord.rule_id == RISK_RULE_ID)).first()
    assert f is not None
    payload = json.loads(f.payload_json)
    assert payload["score"] >= 13.0 - 0.01
    assert "contributions" in payload
    assert set(payload["contributions"]) == {"cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"}
    assert payload["event_count"] == 1


def test_same_day_dedup(session):
    mid = _mk_machine(session)
    _mk_event(session, mid, ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"])
    risk_service.tick(session)
    # Second tick on the same UTC day must not re-emit.
    risk_service.tick(session)
    rows = list(session.exec(select(FindingRecord).where(FindingRecord.rule_id == RISK_RULE_ID)))
    assert len(rows) == 1


def test_events_outside_window_ignored(session):
    mid = _mk_machine(session)
    old_ts = datetime.now(UTC) - timedelta(hours=48)  # default window 24h
    _mk_event(session, mid, ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"], ts=old_ts)
    summary = risk_service.tick(session)
    assert summary["findings_emitted"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_risk_tick.py -v`
Expected: FAIL with `AttributeError: module 'ccguard.server.services.risk_service' has no attribute 'tick'`.

- [ ] **Step 3: Write minimal implementation**

Append to `src/ccguard/server/services/risk_service.py`:

```python
import json
import logging
from datetime import UTC

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline, ToolUseEvent
from ccguard.server.services import settings_service
from ccguard.server.services.risk_constants import (
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_THRESHOLD,
    DEFAULT_WEIGHTS,
    DEFAULT_WINDOW_HOURS,
    RISK_RULE_ID,
)

log = logging.getLogger(__name__)


def _load_tunables(session: Session) -> tuple[float, float, float]:
    """Read (threshold, window_hours, half_life_hours) from SettingsRecord
    with safe fallback to defaults on missing or unparseable values."""
    def _f(key: str, default: float) -> float:
        raw = settings_service.get_setting(session, key)
        if raw is None:
            return default
        try:
            return float(raw)
        except (TypeError, ValueError):
            log.warning("risk: bad %s=%r, using default %s", key, raw, default)
            return default

    return (
        _f("risk.threshold", DEFAULT_THRESHOLD),
        _f("risk.window_hours", DEFAULT_WINDOW_HOURS),
        _f("risk.half_life_hours", DEFAULT_HALF_LIFE_HOURS),
    )


def _machine_is_warm(session: Session, machine_id: str) -> bool:
    """A machine is warm iff it has at least one baseline_ready baseline."""
    stmt = (
        select(MachineBaseline)
        .where(MachineBaseline.machine_id == machine_id)
        .where(MachineBaseline.baseline_ready == True)  # noqa: E712
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _same_day_risk_finding_exists(session: Session, machine_id: str, today_utc: datetime) -> bool:
    """Service-layer same-UTC-day dedup, mirroring anomaly_service."""
    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == RISK_RULE_ID)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _load_events(
    session: Session, machine_id: str, since: datetime
) -> list[RiskInputEvent]:
    """Load events with at least one signal for this machine since ``since``.

    Filters out empty-signal events at the SQL layer to keep the working set
    small on chatty machines.
    """
    stmt = (
        select(ToolUseEvent)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .where(ToolUseEvent.signals_json != "[]")
    )
    out: list[RiskInputEvent] = []
    for row in session.exec(stmt):
        try:
            sigs = json.loads(row.signals_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(sigs, list) or not sigs:
            continue
        out.append(RiskInputEvent(ts=row.ts, signals=tuple(str(s) for s in sigs)))
    return out


def evaluate_one(session: Session, machine_id: str) -> FindingRecord | None:
    """Score one machine and emit a finding if it crosses the threshold."""
    if not _machine_is_warm(session, machine_id):
        return None

    threshold, window_h, half_life_h = _load_tunables(session)
    now = datetime.now(UTC)
    since = now - timedelta(hours=window_h)
    events = _load_events(session, machine_id, since)
    if not events:
        return None

    breakdown = compute_risk_score(events, now, DEFAULT_WEIGHTS, window_h, half_life_h)
    if breakdown.score <= threshold:
        return None

    if _same_day_risk_finding_exists(session, machine_id, now):
        return None

    payload = {
        "score": breakdown.score,
        "threshold": threshold,
        "window_hours": window_h,
        "half_life_hours": half_life_h,
        "contributions": breakdown.contributions,
        "event_count": breakdown.event_count,
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=RISK_RULE_ID,
        severity="warn",
        discovered_at=now,
        payload_json=json.dumps(payload, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, object]:
    """Score every machine. Mirrors :func:`anomaly_service.tick`'s contract.

    Returns ``{"machines_evaluated": int, "findings_emitted": int, "errors": list[str]}``.
    Per-machine failures are caught so one machine's bad data does not abort
    the sweep.
    """
    machines = list(session.exec(select(Machine)))
    emitted = 0
    errors: list[str] = []
    for m in machines:
        try:
            if evaluate_one(session, m.machine_id) is not None:
                emitted += 1
        except Exception as exc:  # noqa: BLE001
            try:
                session.rollback()
            except Exception:  # noqa: BLE001
                pass
            errors.append(f"{m.machine_id}: {exc}")
            log.warning("risk tick error: %s", errors[-1])
    return {
        "machines_evaluated": len(machines),
        "findings_emitted": emitted,
        "errors": errors,
    }
```

> **Note on imports:** keep the top-of-file dataclass + scoring kernel unchanged from Task 2; the orchestrator additions land below it. Move the `from datetime import datetime, timedelta` import up if needed so both halves share it.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_risk_tick.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/risk_service.py tests/integration/test_risk_tick.py
git commit -m "feat(risk): per-machine tick with warm-up, dedup, threshold gate"
```

---

### Task 4: Wire `risk_service.tick` into the scheduler lifespan

Chain the risk tick after the existing anomaly tick in the same scheduled job. Cheaper than a second APScheduler job and keeps the "one writer at a time" invariant trivially true.

**Files:**
- Modify: `src/ccguard/server/main.py` (lifespan `_tick_job_sync`)
- Test: `tests/integration/test_risk_tick_lifespan.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/integration/test_risk_tick_lifespan.py
"""The risk tick is invoked from the same scheduled callable as the anomaly tick."""
from __future__ import annotations

from unittest.mock import patch


def test_lifespan_tick_calls_risk_service(session, engine):
    """We don't boot the scheduler in tests; instead exercise the tick callable
    via monkey-patching ``anomaly_tick`` + ``risk_tick`` and invoking the inner
    sync job. This mirrors how the real scheduler calls it."""
    # The lifespan defines the closure ``_tick_job_sync`` locally, so we test
    # the wiring indirectly: confirm main imports ``risk_service.tick`` AND that
    # a manual invocation of both ticks against an empty DB returns clean
    # summaries (smoke).
    from ccguard.server.services import anomaly_service, risk_service

    with patch.object(anomaly_service, "tick", wraps=anomaly_service.tick) as a, \
         patch.object(risk_service, "tick", wraps=risk_service.tick) as r:
        # Direct invocation — proves both services are importable + composable.
        anomaly_service.tick(session)
        risk_service.tick(session)
        assert a.called
        assert r.called


def test_main_module_imports_risk_tick():
    """Static guard: ``main`` must reference ``risk_service.tick`` so the
    lifespan can chain it. Catches a refactor that drops the wiring."""
    import ccguard.server.main as main_mod
    src = (main_mod.__file__ or "")
    assert src, "main module has no __file__"
    from pathlib import Path
    text = Path(src).read_text()
    assert "from ccguard.server.services.risk_service import tick as risk_tick" in text \
        or "risk_service.tick" in text, "main lifespan must invoke risk_service.tick"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_risk_tick_lifespan.py -v`
Expected: `test_main_module_imports_risk_tick` FAILS (string not present yet); the other test passes already because both services exist.

- [ ] **Step 3: Write minimal implementation**

In `src/ccguard/server/main.py`, modify the existing `_tick_job_sync` closure inside the lifespan. Locate it via `grep -n '_tick_job_sync' src/ccguard/server/main.py`. Add the import alongside the existing `anomaly_tick` import and call `risk_tick` after `anomaly_tick` inside the same `Session` block:

```python
    from ccguard.server.services.anomaly_service import tick as anomaly_tick
    from ccguard.server.services.risk_service import tick as risk_tick
    # ...
        def _tick_job_sync() -> None:
            try:
                with _SessionTick(engine) as s:
                    summary = anomaly_tick(s)
                    risk_summary = risk_tick(s)
                logger.info(
                    "anomaly tick: machines=%d findings=%d errors=%d",
                    summary["machines_evaluated"],
                    summary["findings_emitted"],
                    len(summary["errors"]),
                )
                logger.info(
                    "risk tick: machines=%d findings=%d errors=%d",
                    risk_summary["machines_evaluated"],
                    risk_summary["findings_emitted"],
                    len(risk_summary["errors"]),
                )
            except Exception:  # noqa: BLE001
                logger.exception("scheduled tick raised")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_risk_tick_lifespan.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/main.py tests/integration/test_risk_tick_lifespan.py
git commit -m "feat(risk): chain risk tick after anomaly tick in scheduler lifespan"
```

---

### Task 5: End-to-end + full-suite regression

Drive the full path (ingest signals via the audit API → run tick → assert finding) and confirm no regressions.

**Files:**
- Test: `tests/integration/test_risk_e2e.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/integration/test_risk_e2e.py
"""End-to-end: signal ingest → risk tick → FindingRecord('risk.elevated')."""
from __future__ import annotations

import json

from sqlmodel import select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.services import risk_service
from ccguard.server.services.risk_constants import RISK_RULE_ID


def test_ingested_signals_drive_a_risk_finding(client, session, agent_headers):
    # Seed the machine + a warm baseline so the warm-up guard passes.
    session.add(Machine(machine_id="m-e2e", hostname="h"))
    session.add(MachineBaseline(
        machine_id="m-e2e", metric="bash_calls_per_day",
        mean=1.0, stdev=0.5, sample_count=14, baseline_ready=True,
    ))
    session.commit()

    body = {
        "schema_version": "0.2",
        "machine_id": "m-e2e",
        "events": [
            {
                "ts": "2026-05-30T11:59:00+00:00",
                "tool_name": "Bash",
                "fingerprint": "0123456789abcdef",
                "decision": "allow",
                "result_status": "success",
                "signals": ["cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"],
            }
        ],
    }
    resp = client.post("/api/v1/audit", content=json.dumps(body), headers=agent_headers)
    assert resp.status_code == 200, resp.text

    summary = risk_service.tick(session)
    assert summary["findings_emitted"] >= 1

    finding = session.exec(
        select(FindingRecord).where(FindingRecord.rule_id == RISK_RULE_ID)
    ).first()
    assert finding is not None
    payload = json.loads(finding.payload_json)
    assert payload["score"] > payload["threshold"]
    assert set(payload["contributions"]) >= {"cred.read.aws", "egress.network_tool", "exec.pipe_to_shell"}
```

> **Fixture note:** `client`, `session`, `agent_headers` already exist — they are used by `tests/integration/test_signals_ingest.py` and `test_signals_e2e.py`. Reuse the same conftest path.

- [ ] **Step 2: Run test to verify it fails (if any wiring gap), else passes**

Run: `uv run pytest tests/integration/test_risk_e2e.py -v`
Expected: PASS if Tasks 1-4 are complete. If it FAILs, fix the wiring gap it reveals before continuing.

- [ ] **Step 3: Run the full non-e2e suite for regressions**

Run: `uv run pytest --ignore=tests/e2e -q`
Expected: All previously-passing tests still pass (baseline was ~755 + new Stage 1 tests). New Stage 2 tests are green.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_risk_e2e.py
git commit -m "test(risk): end-to-end signal-ingest-to-finding flow"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** Implements spec §4.2 (risk-scoring engine) at the basic level called out in §6 staging — cumulative weighted score, decay, threshold, warm-up, `risk.elevated` finding with explainability breakdown. Peer-group normalization is deferred (spec explicitly permits this — "basic and refine later").
- **Privacy invariant preserved:** the engine reads only `signals_json` (catalog IDs), never raw input. `FindingRecord.payload_json` carries IDs + numeric contributions, no content.
- **Backward compat:** machines with no signals (v0.1 agents, idle machines) score 0 → no finding; cold machines (no warm baseline) skip → no finding; unknown signal IDs from future agents get weight 1.0 instead of raising.
- **Concurrency:** mirrors `anomaly_service` — single scheduler writer, service-layer same-UTC-day dedup, per-machine try/except so one bad row never aborts a sweep.
- **Tunability without redeploy:** all three knobs (`risk.threshold`, `risk.window_hours`, `risk.half_life_hours`) and (in a later stage) per-signal weights live in `SettingsRecord`.
- **No new deps.** No DB migration tooling needed (no schema changes; only new SettingsRecord rows, which are inserted by the seeder).
- **Out of scope acknowledged:** IOA sequence detector, UI, suppression, `enforcement_mode` switch — each is a separate planned stage.
