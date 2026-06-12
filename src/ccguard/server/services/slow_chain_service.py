"""Low-and-slow kill-chain accumulator (P7-depth).

Third tier of the correlation family, separated by TIME HORIZON:

* ``sequence_service``  — minutes  (tight deterministic IOA)
* ``chain_engine``      — hours    (scenario stage-sequence in a window)
* ``slow_chain_service``— days     (distinct advanced-stage accumulation) ← here

The kernel :func:`evaluate_progression` is a pure function over (ts, signals)
events: it resolves each signal to a kill-chain stage (``chain_constants``),
keeps only the *advanced* stages, and reports how many DISTINCT ones appeared
plus the span between the first and last advanced-stage event.

The orchestrator :func:`evaluate_one` emits ``ioa.slow_chain`` (``warn``) when
≥ ``min_distinct`` advanced stages appear AND they span ≥ ``min_span_hours``
(so a fast burst the tight-window engines already catch does not double-fire).
Mirrors the anomaly/risk tick contract: per-machine try/except, same-UTC-day
dedup, single-session sweep.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.services import settings_service
from ccguard.server.services._utc import aware_utc
from ccguard.server.services.chain_constants import stage_for_signal, stage_rank
from ccguard.server.services.slow_chain_constants import (
    ADVANCED_STAGES,
    DEFAULT_LOOKBACK_DAYS,
    DEFAULT_MIN_DISTINCT_STAGES,
    DEFAULT_MIN_SPAN_HOURS,
    SLOW_CHAIN_RULE_ID,
    SLOW_CHAIN_SEVERITY,
    SETTING_LOOKBACK_DAYS,
    SETTING_MIN_SPAN_HOURS,
    SETTING_MIN_STAGES,
)

log = logging.getLogger(__name__)


# --- Pure kernel -----------------------------------------------------------


@dataclass(frozen=True)
class SlowEvent:
    """One per-event input: tz-aware UTC timestamp + catalog signal IDs."""

    ts: datetime
    signals: tuple[str, ...]


@dataclass(frozen=True)
class StageHit:
    """An advanced kill-chain stage observed in the lookback, with provenance."""

    stage: str
    first_seen: datetime
    last_seen: datetime
    count: int
    example_signal: str


@dataclass(frozen=True)
class SlowChainResult:
    """Outcome of one machine's progression scan."""

    stages: list[StageHit] = field(default_factory=list)  # advanced stages, kill-chain order

    @property
    def distinct_count(self) -> int:
        return len(self.stages)

    @property
    def span_seconds(self) -> float:
        """Seconds between the earliest and latest advanced-stage event."""
        if not self.stages:
            return 0.0
        first = min(h.first_seen for h in self.stages)
        last = max(h.last_seen for h in self.stages)
        return max(0.0, (last - first).total_seconds())


def evaluate_progression(
    events: Iterable[SlowEvent],
    now: datetime,
    *,
    lookback_days: float,
    advanced_stages: frozenset[str] = ADVANCED_STAGES,
) -> SlowChainResult:
    """Accumulate distinct ADVANCED kill-chain stages across ``events``.

    Events older than ``lookback_days`` are dropped. For every advanced stage we
    record the first/last timestamp, an occurrence count, and one example
    signal. The result lists stages in kill-chain order for legible payloads.
    """
    cutoff = now - timedelta(days=lookback_days)
    acc: dict[str, dict] = {}
    for evt in events:
        if evt.ts < cutoff:
            continue
        # A single event may carry several signals → several stages; count each
        # advanced stage once per event (dedup within the event).
        seen_here: set[str] = set()
        for sid in evt.signals:
            stage = stage_for_signal(str(sid))
            if stage is None or stage not in advanced_stages or stage in seen_here:
                continue
            seen_here.add(stage)
            slot = acc.get(stage)
            if slot is None:
                acc[stage] = {
                    "first": evt.ts,
                    "last": evt.ts,
                    "count": 1,
                    "example": str(sid),
                }
            else:
                slot["count"] += 1
                if evt.ts < slot["first"]:
                    slot["first"] = evt.ts
                if evt.ts > slot["last"]:
                    slot["last"] = evt.ts
    hits = [
        StageHit(
            stage=stage,
            first_seen=slot["first"],
            last_seen=slot["last"],
            count=slot["count"],
            example_signal=slot["example"],
        )
        for stage, slot in acc.items()
    ]
    hits.sort(key=lambda h: stage_rank(h.stage))
    return SlowChainResult(stages=hits)


# --- Orchestrator ----------------------------------------------------------


def _load_tunables(session: Session) -> tuple[float, int, float]:
    """Read (lookback_days, min_distinct, min_span_hours) from settings."""

    def _f(key: str, default: float) -> float:
        raw = settings_service.get_setting(session, key)
        if raw is None:
            return default
        try:
            return float(raw)
        except (TypeError, ValueError):
            log.warning("slow_chain: bad %s=%r, using default %s", key, raw, default)
            return default

    lookback = _f(SETTING_LOOKBACK_DAYS, DEFAULT_LOOKBACK_DAYS)
    min_span = _f(SETTING_MIN_SPAN_HOURS, DEFAULT_MIN_SPAN_HOURS)
    min_distinct = int(_f(SETTING_MIN_STAGES, float(DEFAULT_MIN_DISTINCT_STAGES)))
    return lookback, min_distinct, min_span


def _load_events(session: Session, machine_id: str, since: datetime) -> list[SlowEvent]:
    """Load this machine's signal-bearing events since ``since`` (tz-aware)."""
    stmt = (
        select(ToolUseEvent)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .where(ToolUseEvent.signals_json != "[]")
    )
    out: list[SlowEvent] = []
    for row in session.exec(stmt):
        try:
            sigs = json.loads(row.signals_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(sigs, list) or not sigs:
            continue
        out.append(SlowEvent(ts=aware_utc(row.ts), signals=tuple(str(s) for s in sigs)))
    return out


def _same_day_finding_exists(session: Session, machine_id: str, today_utc: datetime) -> bool:
    """Service-layer same-UTC-day dedup, mirroring anomaly/risk."""
    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == SLOW_CHAIN_RULE_ID)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def evaluate_one(session: Session, machine_id: str) -> FindingRecord | None:
    """Emit ``ioa.slow_chain`` if a machine's distinct advanced-stage count and
    span cross the thresholds. Returns the finding, or None."""
    lookback_days, min_distinct, min_span_hours = _load_tunables(session)
    now = datetime.now(UTC)
    since = now - timedelta(days=lookback_days)

    events = _load_events(session, machine_id, since)
    result = evaluate_progression(events, now, lookback_days=lookback_days)

    if result.distinct_count < min_distinct:
        return None
    # Burst that the tight-window engines already own → stay quiet.
    if result.span_seconds < min_span_hours * 3600.0:
        return None
    if _same_day_finding_exists(session, machine_id, now):
        return None

    payload = {
        "distinct_count": result.distinct_count,
        "min_distinct": min_distinct,
        "span_hours": round(result.span_seconds / 3600.0, 2),
        "lookback_days": lookback_days,
        "stages": [
            {
                "stage": h.stage,
                "first_seen": h.first_seen.isoformat(),
                "last_seen": h.last_seen.isoformat(),
                "count": h.count,
                "example_signal": h.example_signal,
            }
            for h in result.stages
        ],
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=SLOW_CHAIN_RULE_ID,
        severity=SLOW_CHAIN_SEVERITY,
        discovered_at=now,
        payload_json=json.dumps(payload, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, object]:
    """Run the slow-chain sweep over every machine. Mirrors anomaly/risk tick."""
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
            log.warning("slow_chain tick error: %s", errors[-1])
    return {
        "machines_evaluated": len(machines),
        "findings_emitted": emitted,
        "errors": errors,
    }
