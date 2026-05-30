"""Fleet-wide current risk view (Behavioral Detection, Stage 4b).

Aggregates the current decay-weighted risk score across all warm machines so
the overview page can show "who is hot right now" without waiting for the
tick to fire a finding. Read-only: never writes findings, never mutates state.

Cold machines (no warm baseline) are skipped — consistent with the risk
tick's warm-up posture.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import Machine, MachineBaseline
from ccguard.server.services.risk_constants import DEFAULT_WEIGHTS
from ccguard.server.services.risk_service import (
    _load_events,
    _load_tunables,
    compute_risk_score,
)


def _warm_machine_ids(session: Session) -> set[str]:
    stmt = (
        select(MachineBaseline.machine_id)
        .where(MachineBaseline.baseline_ready == True)  # noqa: E712
        .distinct()
    )
    return {mid for mid in session.exec(stmt)}


def compute_fleet_risk(session: Session, limit: int = 10) -> list[dict[str, Any]]:
    """Return warm machines sorted by current decay-weighted risk score, desc.

    Each row: ``{machine_id, machine_label, score, top_signal, event_count}``.
    Empty list if no machines are warm. Cold machines are skipped.
    """
    warm = _warm_machine_ids(session)
    if not warm:
        return []

    _threshold, window_h, half_life_h = _load_tunables(session)
    now = datetime.now(UTC)
    since = now - timedelta(hours=window_h)

    rows: list[dict[str, Any]] = []
    for m in session.exec(select(Machine)):
        if m.machine_id not in warm:
            continue
        events = _load_events(session, m.machine_id, since)
        breakdown = compute_risk_score(events, now, DEFAULT_WEIGHTS, window_h, half_life_h)
        top_signal: str | None = None
        if breakdown.contributions:
            top_signal = max(breakdown.contributions.items(), key=lambda kv: kv[1])[0]
        rows.append(
            {
                "machine_id": m.machine_id,
                "machine_label": m.machine_label,
                "score": breakdown.score,
                "top_signal": top_signal,
                "event_count": breakdown.event_count,
            }
        )

    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:limit]
