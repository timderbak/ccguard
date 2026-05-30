"""Risk history fetch helper for the machine_detail sparkline (Pilot prep #2).

Daily UPSERT of ``MachineRiskHistory`` happens in :mod:`risk_service.tick`.
This module reads it back as an aligned 14-day series with missing days
filled with score=0 so the sparkline renders without gaps.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import MachineRiskHistory

_WINDOW_DAYS = 14


def get_risk_history_14d(session: Session, machine_id: str) -> list[dict[str, Any]]:
    """Return 14 aligned per-day dicts (oldest → newest, today last).

    Each entry: ``{"date": "YYYY-MM-DD", "score": float, "top_signal": str|None}``.
    Days without a stored row default to score=0 / top_signal=None.
    """
    today = datetime.now(UTC).date()
    earliest = today - timedelta(days=_WINDOW_DAYS - 1)
    rows = list(
        session.exec(
            select(MachineRiskHistory)
            .where(MachineRiskHistory.machine_id == machine_id)
            .where(MachineRiskHistory.date_utc >= earliest.isoformat())
        )
    )
    by_date = {r.date_utc: r for r in rows}
    out: list[dict[str, Any]] = []
    for delta in range(_WINDOW_DAYS - 1, -1, -1):
        d = today - timedelta(days=delta)
        key = d.isoformat()
        row = by_date.get(key)
        out.append({
            "date": key,
            "score": row.score if row else 0.0,
            "top_signal": row.top_signal if row else None,
        })
    return out


def upsert_today(
    session: Session, *, machine_id: str, score: float, top_signal: str | None
) -> None:
    """Idempotent UPSERT of (machine_id, today_utc) into MachineRiskHistory."""
    today_iso = datetime.now(UTC).date().isoformat()
    existing = session.exec(
        select(MachineRiskHistory)
        .where(MachineRiskHistory.machine_id == machine_id)
        .where(MachineRiskHistory.date_utc == today_iso)
        .limit(1)
    ).first()
    if existing is None:
        session.add(
            MachineRiskHistory(
                machine_id=machine_id,
                date_utc=today_iso,
                score=score,
                top_signal=top_signal,
            )
        )
    else:
        existing.score = score
        existing.top_signal = top_signal
        existing.updated_at = datetime.now(UTC)
        session.add(existing)
    session.commit()
