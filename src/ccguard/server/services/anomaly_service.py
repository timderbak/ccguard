"""Anomaly detection orchestrator (Plan 02-03).

Single autonomous entry point: :func:`tick` iterates every :class:`Machine`,
computes the 14-day series for every locked metric in
:data:`anomaly_constants.ALL_METRICS`, persists the rolling baseline via
:func:`baseline_service.upsert_baseline`, and — when the latest point exceeds
``mean + 3 * stdev`` AND the baseline is past warm-up — emits a single
:class:`FindingRecord` (severity ``warn``, ``rule_id = "anomaly.<metric>"``,
``inventory_id`` NULL).

Idempotency contract (per plan 02-CONTEXT.md / RESEARCH.md):

* **Same UTC day dedup is enforced at the service layer**, NOT via a DB UNIQUE
  constraint. The pre-check uses ``func.date(discovered_at) == today_utc_date``
  scoped to ``(machine_id, rule_id)``. Repeated ticks in the same day on the
  same data emit at most one finding per (machine, rule).
* Different-day re-emission is allowed (yesterday's finding does not block
  today's).

Error tolerance: each per-machine-per-metric evaluation is wrapped in
``try/except`` so one machine's broken aggregator does not abort the tick.
Failures are recorded in the returned summary's ``errors`` list as
``"<machine>/<metric>: <exc>"`` strings.

Session strategy: tick() uses a **single Session** for the whole sweep,
committing per finding insert (the upserts in :func:`baseline_service`
already commit). This matches the existing service-layer idiom and keeps the
SQLite WAL writer count predictable.

Degenerate-stdev rule (locked): when ``stdev == 0`` and ``latest != mean``,
we treat the deviation as anomalous only on the **high side** (``latest > mean``).
A flat baseline that drops to zero is not an attacker signal; a flat baseline
that suddenly spikes is.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from ..db.models import FindingRecord, Machine
from . import baseline_service
from . import metric_aggregators as agg
from .anomaly_constants import ALL_METRICS, rule_id_for

log = logging.getLogger(__name__)

SIGMA_THRESHOLD: float = 3.0

# Aggregator dispatch — keyed by the metric name (which is also the suffix in
# ``anomaly.<metric>``). Mutable module-level dict so tests can monkey-patch
# individual aggregators via ``unittest.mock.patch.dict``.
_DISPATCH: dict[str, Callable[..., list[tuple[Any, int]]]] = {
    "bash_calls_per_day": agg.bash_calls_per_day_series,
    "new_mcp_per_week": agg.new_mcp_per_week_series,
    "new_agents_per_week": agg.new_agents_per_week_series,
    "skill_dir_hash_changes_per_week": agg.skill_dir_hash_changes_per_week_series,
}


def _is_outlier(latest: float, mean: float, stdev: float) -> bool:
    """True iff the latest observation is anomalously high.

    * ``stdev > 0``: standard 3σ test on the upper tail.
    * ``stdev == 0``: degenerate guard — only positive deviations count.
    """
    if stdev > 0:
        return (latest - mean) > SIGMA_THRESHOLD * stdev
    return latest > mean


def _sigma_distance(latest: float, mean: float, stdev: float) -> float:
    """Z-score; ``inf`` when stdev is zero (degenerate baseline)."""
    if stdev > 0:
        return (latest - mean) / stdev
    return float("inf")


def _same_day_finding_exists(
    session: Session,
    machine_id: str,
    rule_id: str,
    today_utc: datetime,
) -> bool:
    """Service-layer dedup pre-check (no DB UNIQUE — per RESEARCH).

    Uses SQLite-compatible ``func.date()`` on ``discovered_at`` to bucket on
    the UTC date (FindingRecord.discovered_at is always tz-aware UTC).
    """
    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == rule_id)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def evaluate_one(
    session: Session,
    machine_id: str,
    metric: str,
) -> FindingRecord | None:
    """Compute baseline + emit anomaly finding for one (machine, metric)."""
    aggregator = _DISPATCH[metric]
    series = aggregator(session, machine_id)
    point_values = [float(v) for _d, v in series]

    baseline = baseline_service.upsert_baseline(session, machine_id, metric, point_values)

    if not baseline.baseline_ready:
        return None
    if not point_values:
        return None

    latest = point_values[-1]
    mean = float(baseline.mean)
    stdev = float(baseline.stdev)

    if not _is_outlier(latest, mean, stdev):
        return None

    rule_id = rule_id_for(metric)
    now = datetime.now(UTC)

    if _same_day_finding_exists(session, machine_id, rule_id, now):
        return None

    payload = {
        "observed_value": latest,
        "mean": mean,
        "stdev": stdev,
        "sigma_distance": _sigma_distance(latest, mean, stdev),
        "metric": metric,
        "sample_count": int(baseline.sample_count),
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=rule_id,
        severity="warn",
        discovered_at=now,
        payload_json=json.dumps(payload),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, Any]:
    """Run the full anomaly sweep over every machine × every metric.

    Returns a summary dict::

        {
            "machines_evaluated": int,
            "findings_emitted":   int,
            "errors": ["<machine>/<metric>: <exc>", ...],
        }

    Per-machine-per-metric failures are caught and recorded — they never abort
    the rest of the sweep.
    """
    machines = list(session.exec(select(Machine)))
    findings_emitted = 0
    errors: list[str] = []

    for m in machines:
        for metric in ALL_METRICS:
            try:
                f = evaluate_one(session, m.machine_id, metric)
                if f is not None:
                    findings_emitted += 1
            except Exception as exc:  # noqa: BLE001 — boundary swallow is intentional
                # Roll back any partial state from this evaluation so the
                # session stays usable for the next iteration.
                try:
                    session.rollback()
                except Exception:  # noqa: BLE001
                    pass
                msg = f"{m.machine_id}/{metric}: {exc}"
                log.warning("anomaly tick error: %s", msg)
                errors.append(msg)

    return {
        "machines_evaluated": len(machines),
        "findings_emitted": findings_emitted,
        "errors": errors,
    }
