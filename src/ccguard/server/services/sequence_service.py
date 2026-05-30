"""IOA exfil-sequence detector (Behavioral Detection, Stage 3).

The kernel is :func:`detect_exfil_sequence` — a pure function over a list of
``SequenceInputEvent`` records. It returns the first ``ExfilMatch`` where a
``cred.read.*`` signal is followed by an ``egress.*`` signal within
``window_minutes`` on the same machine (the SQL loader enforces same-machine
upstream).

The orchestrator :func:`tick` loads events for one machine, calls the kernel,
and emits a ``FindingRecord("ioa.exfil_sequence", severity="high")`` with
explainability payload when a match is found.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SequenceInputEvent:
    """One per-event input to the sequence detector.

    ``ts`` must be tz-aware (UTC). ``signals`` is a tuple of catalog IDs.
    """

    ts: datetime
    signals: tuple[str, ...]


@dataclass(frozen=True)
class ExfilMatch:
    """A matched cred→egress pair. Persisted into ``FindingRecord.payload_json``."""

    cred_ts: datetime
    cred_signal: str
    egress_ts: datetime
    egress_signal: str
    elapsed_seconds: float


def detect_exfil_sequence(
    events: Iterable[SequenceInputEvent],
    window_minutes: float,
    cred_prefix: str,
    egress_prefix: str,
) -> ExfilMatch | None:
    """Return the first cred→egress pair within ``window_minutes``, or ``None``.

    "First" means: the earliest cred event that has any egress event with
    ``egress.ts >= cred.ts`` and ``egress.ts - cred.ts <= window``. Within
    that cred event, the earliest egress event in window wins. Events with
    both prefixes on the same row produce a zero-gap match.
    """
    sorted_events = sorted(events, key=lambda e: e.ts)
    if not sorted_events:
        return None

    window = timedelta(minutes=window_minutes)
    for i, cred_evt in enumerate(sorted_events):
        cred_hit = next((s for s in cred_evt.signals if s.startswith(cred_prefix)), None)
        if cred_hit is None:
            continue
        same_row_egress = next(
            (s for s in cred_evt.signals if s.startswith(egress_prefix)), None
        )
        if same_row_egress is not None:
            return ExfilMatch(
                cred_ts=cred_evt.ts,
                cred_signal=cred_hit,
                egress_ts=cred_evt.ts,
                egress_signal=same_row_egress,
                elapsed_seconds=0.0,
            )
        for later in sorted_events[i + 1 :]:
            gap = later.ts - cred_evt.ts
            if gap > window:
                break
            egress_hit = next(
                (s for s in later.signals if s.startswith(egress_prefix)), None
            )
            if egress_hit is not None:
                return ExfilMatch(
                    cred_ts=cred_evt.ts,
                    cred_signal=cred_hit,
                    egress_ts=later.ts,
                    egress_signal=egress_hit,
                    elapsed_seconds=gap.total_seconds(),
                )
    return None


# --- Orchestrator ---------------------------------------------------------
# Imports kept here (not at top) to keep the pure kernel above dependency-free.

from sqlalchemy import func  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from ccguard.server.db.models import (  # noqa: E402
    FindingRecord,
    Machine,
    MachineBaseline,
    ToolUseEvent,
)
from ccguard.server.services import settings_service  # noqa: E402
from ccguard.server.services.sequence_constants import (  # noqa: E402
    CRED_PREFIX,
    DEFAULT_LOOKBACK_HOURS,
    DEFAULT_WINDOW_MINUTES,
    EGRESS_PREFIX,
    SEQUENCE_RULE_ID,
)


def _load_tunables(session: Session) -> tuple[float, float]:
    """Read (window_minutes, lookback_hours) from SettingsRecord, falling back
    to defaults on missing or unparseable values."""

    def _f(key: str, default: float) -> float:
        raw = settings_service.get_setting(session, key)
        if raw is None:
            return default
        try:
            return float(raw)
        except (TypeError, ValueError):
            log.warning("sequence: bad %s=%r, using default %s", key, raw, default)
            return default

    return (
        _f("sequence.window_minutes", DEFAULT_WINDOW_MINUTES),
        _f("sequence.lookback_hours", DEFAULT_LOOKBACK_HOURS),
    )


def _machine_is_warm(session: Session, machine_id: str) -> bool:
    stmt = (
        select(MachineBaseline)
        .where(MachineBaseline.machine_id == machine_id)
        .where(MachineBaseline.baseline_ready == True)  # noqa: E712
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _same_day_finding_exists(
    session: Session, machine_id: str, today_utc: datetime
) -> bool:
    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == SEQUENCE_RULE_ID)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _load_events(
    session: Session, machine_id: str, since: datetime
) -> list[SequenceInputEvent]:
    """Load events with signals for this machine since ``since``.

    Same SQLite-tz-naive normalization as risk_service._load_events.
    """
    stmt = (
        select(ToolUseEvent)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .where(ToolUseEvent.signals_json != "[]")
    )
    out: list[SequenceInputEvent] = []
    for row in session.exec(stmt):
        try:
            sigs = json.loads(row.signals_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(sigs, list) or not sigs:
            continue
        ts = row.ts
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        out.append(SequenceInputEvent(ts=ts, signals=tuple(str(s) for s in sigs)))
    return out


def evaluate_one(session: Session, machine_id: str) -> FindingRecord | None:
    """Detect an exfil sequence for one machine and emit a finding if matched."""
    if not _machine_is_warm(session, machine_id):
        return None

    window_min, lookback_h = _load_tunables(session)
    now = datetime.now(UTC)
    since = now - timedelta(hours=lookback_h)
    events = _load_events(session, machine_id, since)
    if not events:
        return None

    match = detect_exfil_sequence(events, window_min, CRED_PREFIX, EGRESS_PREFIX)
    if match is None:
        return None

    if _same_day_finding_exists(session, machine_id, now):
        return None

    payload = {
        "cred_ts": match.cred_ts.isoformat(),
        "cred_signal": match.cred_signal,
        "egress_ts": match.egress_ts.isoformat(),
        "egress_signal": match.egress_signal,
        "elapsed_seconds": match.elapsed_seconds,
        "window_minutes": window_min,
        "lookback_hours": lookback_h,
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=SEQUENCE_RULE_ID,
        severity="high",
        discovered_at=now,
        payload_json=json.dumps(payload, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, object]:
    """Detect exfil sequences for every machine. Mirrors risk_service.tick."""
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
            log.warning("sequence tick error: %s", errors[-1])
    return {
        "machines_evaluated": len(machines),
        "findings_emitted": emitted,
        "errors": errors,
    }
