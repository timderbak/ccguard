"""Risk-scoring engine (Behavioral Detection, Stage 2).

The kernel is :func:`compute_risk_score` — a pure function over a list of
``RiskInputEvent`` records (timestamp + signal IDs). It applies a per-signal
weight (``risk_constants.DEFAULT_WEIGHTS``, overridable via SettingsRecord) and
an exponential decay by event age so old activity fades:

    score = Σ_event Σ_signal weight(signal) · 2^(-age_hours / half_life_hours)

Events older than the window are dropped. Unknown signal IDs (forward compat
for future catalog additions before this server is upgraded) get weight 1.0
rather than raising — fail-open is the agreed posture for the engine.

The orchestrator :func:`tick` (added in Task 3) loads events for one machine,
calls this kernel, and emits a ``FindingRecord("risk.elevated")`` when the
score crosses the configured threshold.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

log = logging.getLogger(__name__)


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


# --- Orchestrator (Task 3) -------------------------------------------------
# Imports kept here (not at top) to keep the pure kernel above strictly
# dependency-free for clarity; the orchestrator pulls in DB + settings.

from ccguard.server.db.models import (  # noqa: E402
    FindingRecord,
    Machine,
    MachineBaseline,
    ToolUseEvent,
)
from ccguard.server.services import settings_service  # noqa: E402
from ccguard.server.services._utc import aware_utc  # noqa: E402
from ccguard.server.services.risk_constants import (  # noqa: E402
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_THRESHOLD,
    DEFAULT_WEIGHTS,
    DEFAULT_WINDOW_HOURS,
    RISK_RULE_ID,
)


def _load_tunables(session: Session) -> tuple[float, float, float]:
    """Read (threshold, window_hours, half_life_hours) from SettingsRecord,
    falling back to defaults on missing or unparseable values."""

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


def _same_day_risk_finding_exists(
    session: Session, machine_id: str, today_utc: datetime
) -> bool:
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
    """Load ``ToolUseEvent`` rows with at least one signal for this machine.

    Filters empty-signal events at the SQL layer to keep the working set small.
    Tolerates malformed ``signals_json`` (treats it as no signals).
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
        # SQLite stores datetimes tz-naive; normalize to UTC so arithmetic
        # against the tz-aware ``now`` does not raise.
        out.append(RiskInputEvent(ts=aware_utc(row.ts), signals=tuple(str(s) for s in sigs)))
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

    Returns ``{"machines_evaluated", "findings_emitted", "errors"}``. Per-machine
    failures are caught so one machine's bad data does not abort the sweep.
    """
    machines = list(session.exec(select(Machine)))
    emitted = 0
    errors: list[str] = []
    for m in machines:
        try:
            if evaluate_one(session, m.machine_id) is not None:
                emitted += 1
        except Exception as exc:  # noqa: BLE001 — boundary swallow is intentional
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
