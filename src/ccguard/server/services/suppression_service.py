"""One-click signal suppression (Pilot prep #3).

The primary defense against alert fatigue. SOC clicks "Suppress 30d" on a
finding → that (machine, signal) pair is excluded from risk scoring for
the next 30 days, then automatically un-suppresses.

Storage piggybacks on ``SettingsRecord`` with key
``suppress.<machine_id>.<signal_id>`` and a JSON value carrying the
``until`` date (ISO), ``reason``, and ``by`` (reviewer id). This avoids a
new table for a feature that is fundamentally just "tunables".
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import SettingsRecord
from ccguard.server.services._utc import aware_utc

_KEY_PREFIX = "suppress."


def _key(machine_id: str, signal_id: str) -> str:
    return f"{_KEY_PREFIX}{machine_id}.{signal_id}"


def add(
    session: Session,
    *,
    machine_id: str,
    signal_id: str,
    days: int,
    reason: str,
    by: str,
) -> SettingsRecord:
    """Suppress this (machine, signal) for ``days``. Idempotent UPSERT."""
    until = (datetime.now(UTC) + timedelta(days=days)).isoformat()
    payload = json.dumps({"until": until, "reason": reason, "by": by}, ensure_ascii=False)
    key = _key(machine_id, signal_id)
    existing = session.get(SettingsRecord, key)
    if existing is None:
        existing = SettingsRecord(key=key, value=payload)
    else:
        existing.value = payload
        existing.updated_at = datetime.now(UTC)
    session.add(existing)
    session.commit()
    session.refresh(existing)
    return existing


def remove(session: Session, *, machine_id: str, signal_id: str) -> None:
    """Lift a suppression. No-op if absent."""
    row = session.get(SettingsRecord, _key(machine_id, signal_id))
    if row is not None:
        session.delete(row)
        session.commit()


def list_active(
    session: Session, *, machine_id: str, now: datetime
) -> set[str]:
    """Return signal IDs currently suppressed for ``machine_id`` (unexpired).

    Corrupt entries (bad JSON, missing fields) are silently skipped — the
    feature must never crash the risk path.
    """
    prefix = f"{_KEY_PREFIX}{machine_id}."
    stmt = select(SettingsRecord).where(
        SettingsRecord.key.like(f"{prefix}%")  # type: ignore[attr-defined]
    )
    out: set[str] = set()
    for row in session.exec(stmt):
        try:
            payload = json.loads(row.value)
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        until_raw = payload.get("until")
        if not isinstance(until_raw, str):
            continue
        try:
            until = aware_utc(datetime.fromisoformat(until_raw))
        except ValueError:
            continue
        if until <= now:
            continue
        signal_id = row.key[len(prefix):]
        out.add(signal_id)
    return out


def list_for_machine(
    session: Session, *, machine_id: str
) -> list[dict[str, Any]]:
    """All suppression entries for a machine — for admin display."""
    prefix = f"{_KEY_PREFIX}{machine_id}."
    stmt = select(SettingsRecord).where(
        SettingsRecord.key.like(f"{prefix}%")  # type: ignore[attr-defined]
    )
    out: list[dict[str, Any]] = []
    now = datetime.now(UTC)
    for row in session.exec(stmt):
        try:
            payload = json.loads(row.value)
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        until_raw = payload.get("until", "")
        try:
            until = aware_utc(datetime.fromisoformat(until_raw)) if until_raw else None
        except ValueError:
            until = None
        out.append({
            "signal_id": row.key[len(prefix):],
            "until": until_raw,
            "reason": payload.get("reason", ""),
            "by": payload.get("by", ""),
            "expired": until is not None and until <= now,
        })
    return out
