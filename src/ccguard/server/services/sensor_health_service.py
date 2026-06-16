"""Server-side sensor silence detection (ТЗ-07).

The inversion of every other detector: it fires on the ABSENCE of signal. A
dead/suppressed agent can't report its own death, so the server is the watchdog
— each scheduler tick it checks who has gone quiet past the grace window.

Lifecycle (computed from ``last_heartbeat_at`` vs the expected interval):
  active  — heartbeat within interval×grace.
  stale   — overdue but within grace (reboot / short pause) — NO alert.
  silent  — quiet beyond grace → suspicious → one ``sensor.silent`` finding per
            episode (``Machine.silent_since`` is the open-episode marker; the
            heartbeat endpoint clears it and emits ``sensor.recovered`` on return).

Machines that never sent a heartbeat (legacy agents, last_heartbeat_at NULL) are
never alerted on — only a sensor that was alive and then vanished is suspicious.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine
from ccguard.server.services import settings_service

log = logging.getLogger(__name__)

_DEFAULT_INTERVAL_SEC = 900.0  # 15 min — mirrors the daemon default cadence
_DEFAULT_GRACE_MULTIPLIER = 3.0  # silent only after 3 missed intervals (45 min)
_DEFAULT_MAX_INTERVAL_SEC = 3600.0  # C1: cap on the agent-DECLARED cadence — a
# compromised agent must not inflate expected_interval_sec (≤86400 per schema)
# to push silence detection past max×grace. Tunable via sensor.max_interval_sec.

_RULE_SILENT = "sensor.silent"


def _f(session: Session, key: str, default: float) -> float:
    raw = settings_service.get_setting(session, key)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        log.warning("sensor: bad %s=%r, using default %s", key, raw, default)
        return default


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _effective_interval(session: Session, machine: Machine) -> float:
    """Heartbeat interval used for liveness math. The agent's declared interval
    is honored but CLAMPED to ``sensor.max_interval_sec`` so a compromised agent
    can't inflate it to delay silence detection (C1)."""
    declared = float(
        machine.expected_interval_sec
        or _f(session, "sensor.expected_interval_sec", _DEFAULT_INTERVAL_SEC)
    )
    cap = _f(session, "sensor.max_interval_sec", _DEFAULT_MAX_INTERVAL_SEC)
    return min(declared, cap)


def _silence_threshold_sec(session: Session, machine: Machine) -> float:
    """interval×grace; the machine's declared interval wins over the default but
    is clamped to the cap (C1)."""
    grace = _f(session, "sensor.grace_multiplier", _DEFAULT_GRACE_MULTIPLIER)
    return _effective_interval(session, machine) * grace


def lifecycle_state(
    session: Session, machine: Machine, now: datetime | None = None
) -> str:
    """Return ``active`` | ``stale`` | ``silent`` | ``unknown`` for a machine."""
    if machine.last_heartbeat_at is None:
        return "unknown"  # legacy / never reported — not alertable
    now = now or datetime.now(UTC)
    interval = _effective_interval(session, machine)
    grace = _f(session, "sensor.grace_multiplier", _DEFAULT_GRACE_MULTIPLIER)
    quiet = (now - _aware(machine.last_heartbeat_at)).total_seconds()
    if quiet > interval * grace:
        return "silent"
    if quiet > interval:
        return "stale"
    return "active"


def tick(session: Session) -> dict[str, object]:
    """Detect newly-silent sensors. One finding per silence episode."""
    now = datetime.now(UTC)
    machines = list(session.exec(select(Machine)))
    emitted = 0
    errors: list[str] = []
    for m in machines:
        try:
            if m.last_heartbeat_at is None:
                continue  # never alert on a sensor that never reported
            state = lifecycle_state(session, m, now)
            if state == "silent" and m.silent_since is None:
                quiet_min = (now - _aware(m.last_heartbeat_at)).total_seconds() / 60.0
                # Weighted severity: a sensor that vanished right after reporting
                # its hook was stripped is suppression → block; otherwise warn.
                severity = "block" if m.hooks_intact is False else "warn"
                session.add(
                    FindingRecord(
                        machine_id=m.machine_id,
                        inventory_id=None,
                        rule_id=_RULE_SILENT,
                        severity=severity,
                        discovered_at=now,
                        payload_json=json.dumps(
                            {
                                "silent_minutes": round(quiet_min, 1),
                                "last_heartbeat_at": _aware(m.last_heartbeat_at).isoformat(),
                                "last_state": "active",
                                "hooks_intact": m.hooks_intact,
                                "threshold_sec": _silence_threshold_sec(session, m),
                            }
                        ),
                    )
                )
                m.silent_since = now  # open the episode → dedup future ticks
                session.add(m)
                emitted += 1
        except Exception as exc:  # noqa: BLE001 — tick must not crash the loop
            try:
                session.rollback()
            except Exception:  # noqa: BLE001
                pass
            errors.append(f"{m.machine_id}: {exc}")
            log.warning("sensor tick error: %s", errors[-1])
    if emitted:
        session.commit()
    return {
        "machines_evaluated": len(machines),
        "findings_emitted": emitted,
        "errors": errors,
    }
