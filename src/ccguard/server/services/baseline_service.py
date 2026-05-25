"""Baseline statistics service (Plan 02-02).

Turns a list of recent daily observations (typically 14 points produced by the
aggregators in :mod:`metric_aggregators`) into a persisted
:class:`MachineBaseline` row containing ``mean``, ``stdev``, ``sample_count``,
``baseline_ready`` and the JSON-encoded recent points used for sparkline reuse.

Public surface:

* :func:`compute_baseline` — pure function over ``list[float]``; uses
  :mod:`statistics` from the stdlib (sample stdev, ``n-1`` denominator).
* :func:`upsert_baseline` — INSERT ... ON CONFLICT(machine_id, metric) DO
  UPDATE against the SQLite composite UNIQUE index installed by plan 02-01
  (``ux_machinebaseline_machine_metric``). Idempotent; safe under repeat
  calls — never raises ``IntegrityError`` on duplicates.

Warm-up flag: ``baseline_ready`` flips to ``True`` only when
``len(points) >= WARMUP_THRESHOLD`` (=7). The scheduler (plan 02-03) reads this
flag before emitting anomaly findings so we don't false-positive on a machine
with only a few days of history.
"""

from __future__ import annotations

import json
import statistics
from datetime import UTC, datetime

from sqlalchemy import text as _sql
from sqlmodel import Session, select

from ..db.models import MachineBaseline

WARMUP_THRESHOLD: int = 7


def compute_baseline(points: list[float]) -> dict:
    """Compute ``mean``, ``stdev``, ``sample_count``, and ``baseline_ready``.

    Uses :func:`statistics.fmean` and :func:`statistics.stdev` (sample stdev,
    ``n-1`` denominator). Returns ``stdev=0.0`` when ``len(points) < 2`` (where
    :func:`statistics.stdev` would otherwise raise ``StatisticsError``).

    Warm-up gate (CR-02): ``points`` arrives from the aggregators as a
    14-length zero-padded series, so ``len(points)`` is always 14 and cannot
    distinguish a brand-new machine from one with two weeks of history. We
    therefore derive the persisted ``sample_count`` from the **non-zero**
    points (real activity signal) and gate ``baseline_ready`` on it. A
    legitimately-quiet day reads as zero too, but for the four anomaly
    metrics used in Phase 2 a machine that has truly been quiet for >7 days
    has no useful baseline to compare against anyway — so requiring at least
    ``WARMUP_THRESHOLD`` days of observed activity is the correct gate.
    """
    n = len(points)
    mean = float(statistics.fmean(points)) if n >= 1 else 0.0
    stdev = float(statistics.stdev(points)) if n >= 2 else 0.0
    real_n = sum(1 for v in points if v > 0)
    return {
        "mean": mean,
        "stdev": stdev,
        "sample_count": real_n,
        "baseline_ready": real_n >= WARMUP_THRESHOLD,
    }


_UPSERT_SQL = _sql(
    "INSERT INTO machinebaseline "
    "  (machine_id, metric, mean, stdev, sample_count, baseline_ready, "
    "   recent_points_json, updated_at) "
    "VALUES (:machine_id, :metric, :mean, :stdev, :sample_count, "
    "        :baseline_ready, :recent_points_json, :updated_at) "
    "ON CONFLICT(machine_id, metric) DO UPDATE SET "
    "  mean = excluded.mean, "
    "  stdev = excluded.stdev, "
    "  sample_count = excluded.sample_count, "
    "  baseline_ready = excluded.baseline_ready, "
    "  recent_points_json = excluded.recent_points_json, "
    "  updated_at = excluded.updated_at"
)


def upsert_baseline(
    session: Session,
    machine_id: str,
    metric: str,
    points: list[float],
) -> MachineBaseline:
    """Persist (or refresh) the baseline row for ``(machine_id, metric)``.

    Race-free upsert via SQLite ``ON CONFLICT(machine_id, metric) DO UPDATE``,
    relying on the composite UNIQUE index ``ux_machinebaseline_machine_metric``
    installed by :func:`ccguard.server.db.session.init_db` in plan 02-01.

    Returns the persisted :class:`MachineBaseline` row (post-upsert SELECT) so
    callers (scheduler, finding-emitter) can read back the canonical record
    without re-querying.
    """
    stats = compute_baseline(points)
    now = datetime.now(UTC)
    session.exec(  # type: ignore[call-overload]
        _UPSERT_SQL.bindparams(
            machine_id=machine_id,
            metric=metric,
            mean=stats["mean"],
            stdev=stats["stdev"],
            sample_count=stats["sample_count"],
            baseline_ready=stats["baseline_ready"],
            recent_points_json=json.dumps(points),
            updated_at=now,
        )
    )
    session.commit()
    row = session.exec(
        select(MachineBaseline)
        .where(MachineBaseline.machine_id == machine_id)
        .where(MachineBaseline.metric == metric)
    ).one()
    return row
