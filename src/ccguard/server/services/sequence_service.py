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

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable


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
