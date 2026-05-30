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

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta


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
