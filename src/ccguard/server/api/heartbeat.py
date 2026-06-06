"""POST /api/v1/heartbeat — agent liveness + self-integrity ingest (ТЗ-07).

Updates ``Machine.last_heartbeat_at`` (the explicit liveness clock) and folds
in two integrity signals at ingest time:

* hooks_intact transitions to False → ``sensor.hooks_removed`` (agent is alive
  but its hook was stripped — a clear suppression signal, not a clean shutdown).
* the machine was in an open silence episode and just returned → close the
  episode and emit an info ``sensor.recovered`` (how long we were blind).

Silence DETECTION itself lives in ``sensor_health_service`` (a dead agent can't
report its own death) — this endpoint only records life.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlmodel import Session

from ccguard.schemas.heartbeat import HeartbeatIn
from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import FindingRecord, Machine

router = APIRouter(prefix="/api/v1")


@router.post("/heartbeat")
async def post_heartbeat(
    request: Request,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> Any:
    try:
        raw = await request.json()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}") from exc
    try:
        hb = HeartbeatIn.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    now = datetime.now(UTC)
    machine = session.get(Machine, hb.machine_id)
    if machine is None:
        machine = Machine(machine_id=hb.machine_id, first_seen=now, last_seen=now)
        session.add(machine)

    prev_hooks_intact = machine.hooks_intact
    was_silent_since = machine.silent_since

    machine.last_heartbeat_at = now
    if hb.agent_version is not None:
        machine.agent_version = hb.agent_version
    if hb.expected_interval_sec is not None:
        machine.expected_interval_sec = hb.expected_interval_sec
    machine.hooks_intact = hb.hooks_intact

    # Integrity: hook went from intact/unknown → removed while the agent is
    # still alive. Emit once per transition (repeat False heartbeats are quiet).
    if hb.hooks_intact is False and prev_hooks_intact is not False:
        session.add(
            FindingRecord(
                machine_id=hb.machine_id,
                inventory_id=None,
                rule_id="sensor.hooks_removed",
                severity="block",
                discovered_at=now,
                payload_json=json.dumps(
                    {
                        "reason": "agent reported its ccguard hook is no longer installed",
                        "agent_version": machine.agent_version,
                    }
                ),
            )
        )

    # Recovery: the machine was in an open silence episode and just came back.
    if was_silent_since is not None:
        silent_min = (now - _aware(was_silent_since)).total_seconds() / 60.0
        machine.silent_since = None
        session.add(
            FindingRecord(
                machine_id=hb.machine_id,
                inventory_id=None,
                rule_id="sensor.recovered",
                severity="info",
                discovered_at=now,
                payload_json=json.dumps(
                    {"silent_minutes": round(silent_min, 1),
                     "note": "sensor resumed heartbeats"}
                ),
            )
        )

    session.add(machine)
    session.commit()
    return {"accepted": True}


def _aware(dt: datetime) -> datetime:
    """SQLite returns tz-naive datetimes; treat them as UTC."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
